/*
 * Copyright (c) 2025 TESOBE
 *
 * This file is part of OBP-OIDC.
 *
 * OBP-OIDC is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * OBP-OIDC is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with OBP-OIDC. If not, see <http://www.gnu.org/licenses/>.
 */

package com.tesobe.oidc.endpoints

import cats.effect.{IO, Ref}
import com.tesobe.oidc.auth.{AuthService, CodeService, ParService}
import com.tesobe.oidc.endpoints.HtmlUtils.htmlEncode
import com.tesobe.oidc.models.{ConsentChallenge, OidcError, User}
import com.tesobe.oidc.ratelimit.RateLimitService
import com.tesobe.oidc.config.OidcConfig
import com.tesobe.oidc.tokens.JwtService
import io.circe.syntax._
import org.http4s._
import org.http4s.circe._
import org.http4s.dsl.io._
import org.http4s.headers.Location
import org.slf4j.LoggerFactory
import com.tesobe.oidc.stats.StatsService

import java.time.Instant
import java.util.UUID

class AuthEndpoint(
    authService: AuthService[IO],
    codeService: CodeService[IO],
    statsService: StatsService[IO],
    rateLimitService: RateLimitService[IO],
    config: OidcConfig,
    jwtService: JwtService[IO],
    consentChallengesRef: Ref[IO, Map[String, ConsentChallenge]],
    parService: ParService[IO]
) {

  private val logger = LoggerFactory.getLogger(getClass)

  // Test logging immediately when class is created
  logger.info("AuthEndpoint created - logging is working!")
  println("AuthEndpoint created - logging is working!")

  val routes: HttpRoutes[IO] = HttpRoutes.of[IO] {
    // Standalone testing page that does not require query parameters
    // Allows manual login verification without any external client/Portal
    // Only available in local development mode
    case GET -> Root / "obp-oidc" / "test-login"
        if config.localDevelopmentMode =>
      showStandaloneLoginForm()

    // PAR (RFC 9126): request_uri resolves to a previously pushed set of
    // authorization parameters. Matched before the direct-parameter case so
    // request_uri-bearing requests (which omit response_type/redirect_uri/
    // scope from the query string) are intercepted here.
    case GET -> Root / "obp-oidc" / "auth" :?
        RequestUriQueryParamMatcher(requestUri) +&
        ClientIdQueryParamMatcher(clientId) =>
      handlePushedAuthorizationRequest(requestUri, clientId)

    case GET -> Root / "obp-oidc" / "auth" :?
        ResponseTypeQueryParamMatcher(responseType) +&
        ClientIdQueryParamMatcher(clientId) +&
        RedirectUriQueryParamMatcher(redirectUri) +&
        ScopeQueryParamMatcher(scope) +&
        StateQueryParamMatcher(state) +&
        NonceQueryParamMatcher(nonce) +&
        ConsentRequestIdQueryParamMatcher(consentRequestId) +&
        BankIdQueryParamMatcher(bankId) +&
        ConsentIdQueryParamMatcher(consentId) +&
        CodeChallengeQueryParamMatcher(codeChallenge) +&
        CodeChallengeMethodQueryParamMatcher(codeChallengeMethod) =>
      handleAuthorizationRequest(
        responseType,
        clientId,
        redirectUri,
        scope,
        state,
        nonce,
        consentRequestId,
        bankId,
        consentId,
        codeChallenge,
        codeChallengeMethod
      )

    case req @ POST -> Root / "obp-oidc" / "auth" =>
      req
        .as[UrlForm]
        .flatMap(form => handleLoginSubmissionWithRequest(form, Some(req)))

    // Consent callback: Portal redirects here after user approves/denies consent
    case GET -> Root / "obp-oidc" / "consent-callback" :?
        ChallengeQueryParamMatcher(challengeId) +&
        ConsentIdCallbackQueryParamMatcher(consentId) +&
        ConsentStatusQueryParamMatcher(consentStatus) +&
        UsernameCallbackQueryParamMatcher(username) +&
        ProviderCallbackQueryParamMatcher(provider) =>
      handleConsentCallback(challengeId, consentId, consentStatus, username, provider)
  }

  // Query parameter matchers
  object ResponseTypeQueryParamMatcher
      extends QueryParamDecoderMatcher[String]("response_type")
  object ClientIdQueryParamMatcher
      extends QueryParamDecoderMatcher[String]("client_id")
  object RedirectUriQueryParamMatcher
      extends QueryParamDecoderMatcher[String]("redirect_uri")
  object ScopeQueryParamMatcher
      extends QueryParamDecoderMatcher[String]("scope")
  object StateQueryParamMatcher
      extends OptionalQueryParamDecoderMatcher[String]("state")
  object NonceQueryParamMatcher
      extends OptionalQueryParamDecoderMatcher[String]("nonce")
  object ConsentRequestIdQueryParamMatcher
      extends OptionalQueryParamDecoderMatcher[String]("consent_request_id")
  object BankIdQueryParamMatcher
      extends OptionalQueryParamDecoderMatcher[String]("bank_id")
  object ConsentIdQueryParamMatcher
      extends OptionalQueryParamDecoderMatcher[String]("consent_id")
  // PKCE (RFC 7636)
  object CodeChallengeQueryParamMatcher
      extends OptionalQueryParamDecoderMatcher[String]("code_challenge")
  object CodeChallengeMethodQueryParamMatcher
      extends OptionalQueryParamDecoderMatcher[String]("code_challenge_method")
  // PAR (RFC 9126)
  object RequestUriQueryParamMatcher
      extends QueryParamDecoderMatcher[String]("request_uri")

  // Consent callback query parameter matchers
  object ChallengeQueryParamMatcher
      extends QueryParamDecoderMatcher[String]("challenge")
  object ConsentIdCallbackQueryParamMatcher
      extends OptionalQueryParamDecoderMatcher[String]("consent_id")
  object ConsentStatusQueryParamMatcher
      extends QueryParamDecoderMatcher[String]("consent_status")
  object UsernameCallbackQueryParamMatcher
      extends OptionalQueryParamDecoderMatcher[String]("username")
  object ProviderCallbackQueryParamMatcher
      extends OptionalQueryParamDecoderMatcher[String]("provider")

  // PAR (RFC 9126): resolve a previously pushed request_uri into a full set
  // of authorization parameters, then continue through the normal flow.
  // request_uri is one-time-use and validated (existence, expiry, client_id
  // match) inside parService.consumeRequest before anything else runs.
  // Resolution failures return a direct JSON error rather than a redirect —
  // the redirect_uri isn't trustworthy until the request_uri itself is valid.
  private def handlePushedAuthorizationRequest(
      requestUri: String,
      clientId: String
  ): IO[Response[IO]] = {
    parService.consumeRequest(requestUri, clientId).flatMap {
      case Left(error) =>
        IO(logger.warn(s"PAR resolution failed for clientId: $clientId: ${error.error_description.getOrElse(error.error)}")) *>
          BadRequest(error.asJson)
      case Right(par) =>
        handleAuthorizationRequest(
          par.response_type,
          par.client_id,
          par.redirect_uri,
          par.scope,
          par.state,
          par.nonce,
          par.consent_request_id,
          par.bank_id,
          par.consent_id,
          par.code_challenge,
          par.code_challenge_method
        )
    }
  }

  private def handleAuthorizationRequest(
      responseType: String,
      clientId: String,
      redirectUri: String,
      scope: String,
      state: Option[String],
      nonce: Option[String],
      consentRequestId: Option[String] = None,
      bankId: Option[String] = None,
      consentId: Option[String] = None,
      codeChallenge: Option[String] = None,
      codeChallengeMethod: Option[String] = None
  ): IO[Response[IO]] = {

    IO(
      logger.info(
        s"handleAuthorizationRequest called - responseType: $responseType, clientId: $clientId, redirectUri: $redirectUri, scope: $scope, consentRequestId: $consentRequestId, bankId: $bankId"
      )
    ) *>
      IO(
        println(
          s"handleAuthorizationRequest called - responseType: $responseType, clientId: $clientId, redirectUri: $redirectUri, scope: $scope"
        )
      ) *>
      // Validate request parameters
      (if (responseType != "code" && responseType != "code id_token") {
         IO(logger.warn(s"Unsupported response_type: $responseType")) *>
           IO(println(s"Unsupported response_type: $responseType")) *> {
             val error = OidcError(
               "unsupported_response_type",
               Some("Supported response types: 'code', 'code id_token'"),
               state = state
             )
             redirectWithError(redirectUri, error)
           }
       } else if (!scope.contains("openid")) {
         IO(logger.warn(s"Missing 'openid' scope: $scope")) *>
           IO(println(s"Missing 'openid' scope: $scope")) *> {
             val error = OidcError(
               "invalid_scope",
               Some("'openid' scope is required"),
               state = state
             )
             redirectWithError(redirectUri, error)
           }
       } else if (codeChallengeMethod.exists(_ != "S256")) {
         // PKCE (RFC 7636) + FAPI: only S256 is accepted; 'plain' is rejected.
         IO(logger.warn(s"Unsupported code_challenge_method: ${codeChallengeMethod.getOrElse("")}")) *> {
           val error = OidcError(
             "invalid_request",
             Some("code_challenge_method must be S256"),
             state = state
           )
           redirectWithError(redirectUri, error)
         }
       } else {
         // Validate client and redirect URI
         IO(
           logger.info(s"Response type and scope valid, validating client...")
         ) *>
           IO(
             println(s"Response type and scope valid, validating client...")
           ) *>
           authService.validateClient(clientId, redirectUri).flatMap {
             isValid =>
               if (!isValid) {
                 IO(
                   logger.warn(
                     s"Client validation failed for clientId: $clientId, redirectUri: $redirectUri"
                   )
                 ) *>
                   IO(
                     println(
                       s"Client validation failed for clientId: $clientId, redirectUri: $redirectUri"
                     )
                   ) *> {
                     val error = OidcError(
                       "invalid_client",
                       Some("Invalid client_id or redirect_uri"),
                       state = state
                     )
                     redirectWithError(redirectUri, error)
                   }
               } else {
                 (consentRequestId, consentId) match {
                   case (Some(crId), _) =>
                     // OBP consent-request flow: skip login form, redirect straight to Portal.
                     // The user will authenticate on Portal (which does its own OAuth with OBP-OIDC).
                     IO(logger.info(s"Client validated, consent_request_id present — skipping login, redirecting to Portal...")) *>
                       redirectToPortalForConsent(clientId, redirectUri, scope, state, nonce, responseType, crId, bankId.getOrElse(""))
                   case (_, Some(cid)) =>
                     // UK Open Banking flow: the TPP has already lodged an account-access consent
                     // (status AWAITINGAUTHORISATION). Route the PSU to Portal to authenticate and
                     // approve it; Portal calls OBP-API to authorise the consent, then redirects back
                     // to /consent-callback so we mint a code bound to this consent_id.
                     IO(logger.info(s"Client validated, UK consent_id present ($cid) — redirecting to Portal for UK consent approval...")) *>
                       redirectToPortalForUKConsent(clientId, redirectUri, scope, state, nonce, responseType, cid, bankId.getOrElse(""))
                   case _ =>
                     // Normal flow: show login form
                     IO(logger.info(s"Client validated, showing login form...")) *>
                       IO(println(s"Client validated, showing login form...")) *>
                       showLoginForm(clientId, redirectUri, scope, state, nonce, responseType = responseType, consentId = consentId, codeChallenge = codeChallenge, codeChallengeMethod = codeChallengeMethod)
                 }
               }
           }
       })
  }

  private def validateAuthInput(
      username: String,
      password: String,
      provider: String
  ): Either[String, (String, String, String)] = {
    if (username.isEmpty || username.trim.isEmpty)
      Left("Username cannot be empty")
    else if (username.length < 8)
      Left("Username must be at least 8 characters")
    else if (username.length > 100)
      Left("Username must not exceed 100 characters")
    else if (password.isEmpty)
      Left("Password cannot be empty")
    else if (password.length < 10)
      Left("Password must be at least 10 characters")
    else if (password.length > 512)
      Left("Password must not exceed 512 characters")
    else if (provider.isEmpty || provider.trim.isEmpty)
      Left("Provider cannot be empty")
    else if (provider.length < 5)
      Left("Provider must be at least 5 characters")
    else if (provider.length > 512)
      Left("Provider must not exceed 512 characters")
    else
      Right((username.trim, password, provider.trim))
  }

  private def handleLoginSubmission(form: UrlForm): IO[Response[IO]] = {
    handleLoginSubmissionWithRequest(form, None)
  }

  private def handleLoginSubmissionWithRequest(
      form: UrlForm,
      requestOpt: Option[Request[IO]]
  ): IO[Response[IO]] = {
    val formData = form.values.view.mapValues(_.headOption.getOrElse("")).toMap

    for {
      _ <- IO(logger.info("LOGIN FORM SUBMISSION STARTED"))
      _ <- IO(println("LOGIN FORM SUBMISSION STARTED"))

      // Extract IP address for rate limiting
      ip = requestOpt
        .flatMap(_.remoteAddr)
        .map(_.toString)
        .getOrElse("unknown")

      username <- IO.fromOption(formData.get("username"))(
        new RuntimeException("Missing username")
      )
      _ <- IO(
        logger.info(
          s"Auth form submitted for username: '$username' from IP: $ip"
        )
      )
      _ <- IO(
        println(
          s"Auth form submitted for username: '$username' from IP: $ip"
        )
      )

      password <- IO.fromOption(formData.get("password"))(
        new RuntimeException("Missing password")
      )
      _ <- IO(
        logger.debug(s"Password received (length: ${password.length})")
      )
      provider <- IO.fromOption(formData.get("provider"))(
        new RuntimeException("Missing provider")
      )
      _ <- IO(logger.info(s"Provider selected: '$provider'"))

      // Validate input lengths
      validatedInput <- IO
        .fromEither(
          validateAuthInput(username, password, provider).left.map(errorMsg =>
            new RuntimeException(errorMsg)
          )
        )
        .handleErrorWith { error =>
          IO(logger.warn(s"Input validation failed: ${error.getMessage}")) *>
            IO(println(s"Input validation failed: ${error.getMessage}")) *>
            IO.raiseError(error)
        }
      validUsername = validatedInput._1
      validPassword = validatedInput._2
      validProvider = validatedInput._3

      clientId <- IO.fromOption(formData.get("client_id"))(
        new RuntimeException("Missing client_id")
      )
      redirectUri <- IO.fromOption(formData.get("redirect_uri"))(
        new RuntimeException("Missing redirect_uri")
      )
      scope <- IO.fromOption(formData.get("scope"))(
        new RuntimeException("Missing scope")
      )
      state = formData.get("state")
      nonce = formData.get("nonce")
      responseType = formData.get("response_type").getOrElse("code")
      consentId = formData.get("consent_id")
      codeChallenge = formData.get("code_challenge")
      codeChallengeMethod = formData.get("code_challenge_method")

      _ <- IO(
        logger.info(
          s"Calling authentication service for username: '$validUsername' with provider: '$validProvider'"
        )
      )

      // Perform authentication
      authResult <- authService.authenticate(
        validUsername,
        validPassword,
        validProvider
      )

      response <- authResult match {
        case Right(user) =>
          // Authentication successful - clear rate limit tracking
          rateLimitService.recordSuccessfulLogin(ip, validUsername) *>
            IO(
              logger.info(s"Authentication successful for user: ${user.sub}")
            ) *>
            generateCodeForUser(
              user, clientId, redirectUri, scope, state, nonce,
              responseType, consentId = consentId,
              codeChallenge = codeChallenge, codeChallengeMethod = codeChallengeMethod
            )
        case Left(error) =>
          // Authentication failed - record failed attempt for rate limiting
          rateLimitService.checkAndRecordFailedAttempt(ip, validUsername) *>
            IO(
              logger.warn(
                s"Authentication failed for username: '$validUsername', provider: '$validProvider', error: ${error.error}, description: ${error.error_description.getOrElse("none")}"
              )
            ) *>
            IO(
              println(
                s"Authentication failed for username: '$validUsername', provider: '$validProvider', error: ${error.error}, description: ${error.error_description.getOrElse("none")}"
              )
            ) *>
            showLoginForm(
              clientId,
              redirectUri,
              scope,
              state,
              nonce,
              Some("Incorrect username/password"),
              responseType,
              consentId,
              codeChallenge,
              codeChallengeMethod
            )
      }
    } yield response
  }.handleErrorWith { error =>
    logger.error(
      s"Error handling login submission: ${error.getMessage}",
      error
    )
    BadRequest("Invalid form data. Please try again.")
  }

  /** Store authorization state and redirect to Portal for consent approval.
    * No user authentication happens here — the user will authenticate on Portal.
    */
  private def redirectToPortalForConsent(
      clientId: String,
      redirectUri: String,
      scope: String,
      state: Option[String],
      nonce: Option[String],
      responseType: String,
      consentRequestId: String,
      bankId: String
  ): IO[Response[IO]] = {
    for {
      challengeId <- IO(UUID.randomUUID().toString)
      exp = Instant.now().plusSeconds(config.codeExpirationSeconds).getEpochSecond

      challenge = ConsentChallenge(
        challenge = challengeId,
        clientId = clientId,
        redirectUri = redirectUri,
        scope = scope,
        state = state,
        nonce = nonce,
        responseType = responseType,
        consentRequestId = consentRequestId,
        bankId = bankId,
        exp = exp
      )

      _ <- consentChallengesRef.update(_ + (challengeId -> challenge))
      _ <- IO(logger.info(s"Created consent challenge: $challengeId for consent_request_id: $consentRequestId, redirecting to Portal"))

      // Build the OBP-OIDC consent callback URL that Portal will redirect back to
      oidcReturnUrl = s"${config.issuer}/consent-callback?challenge=${java.net.URLEncoder.encode(challengeId, "UTF-8")}"

      // Redirect to Portal's login page with consent params
      // Portal will authenticate the user (OBP-OIDC session may make this seamless),
      // then show the consent approval page
      portalUrl = s"${config.obpPortalBaseUrl}/login/obp-oidc" +
        s"?consent_request_id=${java.net.URLEncoder.encode(consentRequestId, "UTF-8")}" +
        s"&bank_id=${java.net.URLEncoder.encode(bankId, "UTF-8")}" +
        s"&oidc_return_url=${java.net.URLEncoder.encode(oidcReturnUrl, "UTF-8")}"

      _ <- IO(logger.info(s"Redirecting to Portal for consent: $portalUrl"))
      response <- SeeOther(Location(Uri.unsafeFromString(portalUrl)))
    } yield response
  }

  /** Store authorization state and redirect to Portal for UK Open Banking consent approval.
    *
    * Unlike the OBP consent-request flow, the UK consent already exists (the TPP lodged it
    * via POST /account-access-consents and passed its consent_id here). Portal authenticates
    * the PSU, calls OBP-API to authorise that consent (status → AUTHORISED, bound to the PSU),
    * then redirects back to /consent-callback where we mint the authorization code — so the
    * TPP's token carries the consent_id claim that OBP-API validates on data calls.
    */
  private def redirectToPortalForUKConsent(
      clientId: String,
      redirectUri: String,
      scope: String,
      state: Option[String],
      nonce: Option[String],
      responseType: String,
      consentId: String,
      bankId: String
  ): IO[Response[IO]] = {
    for {
      challengeId <- IO(UUID.randomUUID().toString)
      exp = Instant.now().plusSeconds(config.codeExpirationSeconds).getEpochSecond

      challenge = ConsentChallenge(
        challenge = challengeId,
        clientId = clientId,
        redirectUri = redirectUri,
        scope = scope,
        state = state,
        nonce = nonce,
        responseType = responseType,
        consentRequestId = consentId, // reused to carry the UK consent_id (not read back on callback)
        bankId = bankId,
        exp = exp
      )

      _ <- consentChallengesRef.update(_ + (challengeId -> challenge))
      _ <- IO(logger.info(s"Created consent challenge: $challengeId for UK consent_id: $consentId, redirecting to Portal"))

      oidcReturnUrl = s"${config.issuer}/consent-callback?challenge=${java.net.URLEncoder.encode(challengeId, "UTF-8")}"

      // Portal reads api_standard=UKOpenBanking to drive the UK approval page (which calls
      // OBP-API's consent authorise endpoint) instead of the OBP consent-request page.
      portalUrl = s"${config.obpPortalBaseUrl}/login/obp-oidc" +
        s"?consent_id=${java.net.URLEncoder.encode(consentId, "UTF-8")}" +
        s"&api_standard=UKOpenBanking" +
        s"&bank_id=${java.net.URLEncoder.encode(bankId, "UTF-8")}" +
        s"&oidc_return_url=${java.net.URLEncoder.encode(oidcReturnUrl, "UTF-8")}"

      _ <- IO(logger.info(s"Redirecting to Portal for UK consent: $portalUrl"))
      response <- SeeOther(Location(Uri.unsafeFromString(portalUrl)))
    } yield response
  }

  /** Handle the consent callback from Portal after user approves/denies consent.
    *
    * Two completion modes, chosen by whether Portal identifies the user:
    *  - `username` + `provider` present and resolvable: standard OIDC completion —
    *    mint an authorization code for the original client (bound to the consent_id),
    *    so the client's token exchange yields JWTs carrying the `consent_id` claim
    *    that resource servers (OBP-API) validate against. Resolution goes through
    *    the OBP-API REST endpoint (users/provider/PROVIDER/username/USERNAME).
    *  - no `username` (legacy, e.g. Hola): redirect back to the client with
    *    `consent_status=ACCEPTED&consent_id=...` only — the client then uses
    *    Consent-Id + Consumer-Key headers against OBP-API, no OAuth code minted.
    */
  private def handleConsentCallback(
      challengeId: String,
      consentId: Option[String],
      consentStatus: String,
      username: Option[String],
      provider: Option[String]
  ): IO[Response[IO]] = {
    for {
      challenges <- consentChallengesRef.get
      response <- challenges.get(challengeId) match {
        case Some(challenge) =>
          // Consume the challenge (one-time use)
          consentChallengesRef.update(_ - challengeId) *> {
            // Check expiration
            val now = Instant.now().getEpochSecond
            if (challenge.exp < now) {
              IO(logger.warn(s"Consent challenge expired: $challengeId")) *> {
                val error = OidcError("access_denied", Some("Consent challenge expired"), state = challenge.state)
                redirectWithError(challenge.redirectUri, error)
              }
            } else if (consentStatus == "ACCEPTED" || consentStatus == "VALID") {
              IO(logger.info(s"Consent approved for challenge: $challengeId, consent_id: $consentId, username: ${username.getOrElse("none")}, provider: ${provider.getOrElse("none")}")) *>
                resolveCallbackUser(username, provider).flatMap {
                  case Some(user) =>
                    // Standard OIDC completion: issue an authorization code for the
                    // original client; the consent binding travels inside the code and
                    // ends up as a consent_id claim in the access/ID/refresh tokens.
                    IO(logger.info(s"Resolved consent user '${user.sub}' — issuing authorization code for client ${challenge.clientId}")) *>
                      generateCodeForUser(
                        user,
                        challenge.clientId,
                        challenge.redirectUri,
                        challenge.scope,
                        challenge.state,
                        challenge.nonce,
                        challenge.responseType,
                        consentId
                      )
                  case None =>
                    // Legacy completion (no resolvable user): hand the consent_id back
                    // directly — client accesses OBP-API with Consent-Id + Consumer-Key headers.
                    val consentIdParam = consentId.map(c => s"&consent_id=${java.net.URLEncoder.encode(c, "UTF-8")}").getOrElse("")
                    val stateParam = challenge.state.map(s => s"&state=${java.net.URLEncoder.encode(s, "UTF-8")}").getOrElse("")
                    val location = s"${challenge.redirectUri}?consent_status=ACCEPTED${consentIdParam}${stateParam}"
                    IO(logger.info(s"No resolvable user in consent callback — legacy redirect with consent_id: $location")) *>
                      SeeOther(Location(Uri.unsafeFromString(location)))
                }
            } else {
              IO(logger.info(s"Consent denied for challenge: $challengeId, status: $consentStatus")) *> {
                val error = OidcError("access_denied", Some(s"User denied consent (status: $consentStatus)"), state = challenge.state)
                redirectWithError(challenge.redirectUri, error)
              }
            }
          }
        case None =>
          IO(logger.warn(s"Consent challenge not found: $challengeId")) *>
            BadRequest("Invalid or expired consent challenge.")
      }
    } yield response
  }

  /** Resolve the user identified by the Portal consent callback.
    * Preferred path: `username` + `provider` — resolved via the OBP-API REST endpoint
    * (GET /obp/v6.0.0/users/provider/PROVIDER/username/USERNAME), which needs no
    * database access. Without `provider` it falls back to the local lookup
    * (database view, or the login cache in API-only mode).
    */
  private def resolveCallbackUser(
      username: Option[String],
      provider: Option[String]
  ): IO[Option[User]] =
    username match {
      case None => IO.pure(None)
      case Some(uname) =>
        val viaProvider = provider match {
          case Some(p) => authService.getUserBySubAndProvider(uname, p)
          case None    => IO.pure(Option.empty[User])
        }
        viaProvider.flatMap {
          case found @ Some(_) => IO.pure(found)
          case None =>
            authService.getUserById(uname).flatTap {
              case Some(u) => IO(logger.info(s"Consent callback user resolved locally: ${u.sub}"))
              case None    => IO(logger.warn(s"Consent callback username '$uname' could not be resolved — falling back to legacy consent redirect"))
            }
        }
    }

  private def generateCodeForUser(
      user: User,
      clientId: String,
      redirectUri: String,
      scope: String,
      state: Option[String],
      nonce: Option[String],
      responseType: String = "code",
      consentId: Option[String] = None,
      codeChallenge: Option[String] = None,
      codeChallengeMethod: Option[String] = None
  ): IO[Response[IO]] = {
    for {
      _ <- statsService.incrementLoginSuccess(user.username)
      code <- codeService
        .generateCode(clientId, redirectUri, user.sub, scope, state, nonce, user.provider, consentId, codeChallenge, codeChallengeMethod)
      response <- responseType match {
        case "code id_token" =>
          for {
            idToken <- jwtService.generateHybridIdToken(user, clientId, code, state, nonce, consentId)
            resp <- redirectWithCodeAndIdToken(redirectUri, code, idToken, state)
          } yield resp
        case _ =>
          redirectWithCode(redirectUri, code, state)
      }
    } yield response
  }

  private def showLoginForm(
      clientId: String,
      redirectUri: String,
      scope: String,
      state: Option[String],
      nonce: Option[String],
      errorMessage: Option[String] = None,
      responseType: String = "code",
      consentId: Option[String] = None,
      codeChallenge: Option[String] = None,
      codeChallengeMethod: Option[String] = None
  ): IO[Response[IO]] = {

    IO(logger.info(s"showLoginForm called for clientId: $clientId")) *>
      IO(println(s"showLoginForm called for clientId: $clientId")) *>
      (for {
        providers <- authService.getAvailableProviders()
        clientOpt <- authService.findClientByClientIdThatIsKey(clientId)

        stateParam = state
          .map(s => s"""<input type="hidden" name="state" value="${htmlEncode(s)}">""")
          .getOrElse("")
        nonceParam = nonce
          .map(n => s"""<input type="hidden" name="nonce" value="${htmlEncode(n)}">""")
          .getOrElse("")
        consentIdParam = consentId
          .map(c => s"""<input type="hidden" name="consent_id" value="${htmlEncode(c)}">""")
          .getOrElse("")
        codeChallengeParam = codeChallenge
          .map(c => s"""<input type="hidden" name="code_challenge" value="${htmlEncode(c)}">""")
          .getOrElse("")
        codeChallengeMethodParam = codeChallengeMethod
          .map(m => s"""<input type="hidden" name="code_challenge_method" value="${htmlEncode(m)}">""")
          .getOrElse("")

        providerOptions = providers
          .map { provider =>
            s"""<option value="${htmlEncode(provider)}">${htmlEncode(provider)}</option>"""
          }
          .mkString("\n            ")

        clientName = clientOpt.map(_.client_name).getOrElse("Unknown Client")
        consumerId = clientOpt.map(_.consumer_id).getOrElse("Unknown Consumer")

        // Format client name for production display: replace dashes with spaces and convert to proper case
        formattedClientName = htmlEncode(clientName
          .replace("-", " ")
          .split(" ")
          .map(word =>
            if (word.isEmpty) ""
            else word.charAt(0).toUpper + word.substring(1).toLowerCase
          )
          .mkString(" ")
          .replace("Obp ", "OBP "))

        errorHtml = errorMessage
          .map(msg => s"""<div class="error">$msg</div>""")
          .getOrElse("")

        // Extract domain origin from redirect_uri for logo link
        logoLinkUrl =
          try {
            val uri = new java.net.URI(redirectUri)
            val port =
              if (uri.getPort > 0 && uri.getPort != 80 && uri.getPort != 443) {
                s":${uri.getPort}"
              } else {
                ""
              }
            s"${uri.getScheme}://${uri.getHost}${port}"
          } catch {
            case _: Exception =>
              redirectUri // Fallback to full redirect_uri if parsing fails
          }

        forgotPasswordLink = s"${config.obpPortalBaseUrl}/forgot-password"

        logoHtml = config.logoUrl match {
          case Some(url) =>
            s"""<div class="login-logo">
              <a href="$logoLinkUrl" title="Return to ${formattedClientName}">
                <img src="$url" alt="${config.logoAltText}">
              </a>
            </div>"""
          case None => ""
        }

        html = s"""
      <!DOCTYPE html>
      <html>
      <head>
        <title>Sign In - OBP OIDC Provider</title>
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <link rel="stylesheet" href="/static/css/main.css">
        <link rel="stylesheet" href="/static/css/forms.css">
      </head>
      <body class="form-page">
        <div class="login-container">
          $logoHtml
          <h2>Sign In</h2>
          <p class="subtitle">$formattedClientName is asking you to login</p>
          $errorHtml
          ${if (config.localDevelopmentMode) {
            s"""<div class="info">
            <strong>Consumer ID:</strong> ${htmlEncode(consumerId)}<br>
            <strong>Client Name:</strong> ${htmlEncode(clientName)}<br>
            <strong>Client ID:</strong> ${htmlEncode(clientId)}<br>
            <strong>Requested Scopes:</strong> ${htmlEncode(scope)}
          </div>"""
          } else {
            ""
          }}

          <form method="post" action="/obp-oidc/auth">
            <div class="form-group">
              <label for="username">Username</label>
              <input type="text" id="username" name="username" required autocomplete="username">
            </div>

            <div class="form-group">
              <label for="password">Password</label>
              <input type="password" id="password" name="password" required autocomplete="current-password">
              <div style="text-align: right; margin-top: 0.5rem;">
                <a href="$forgotPasswordLink" style="font-size: 0.9rem; color: #0066cc; text-decoration: none;">Forgot password?</a>
              </div>
            </div>

            ${
          // Show dropdown if: multiple providers OR single provider in dev mode
          // Hide dropdown if: single provider in production mode
          if (providers.length > 1 || config.localDevelopmentMode) {
            s"""<div class="form-group">
              <label for="provider">Authentication Provider</label>
              <select id="provider" name="provider" required>
              $providerOptions
              </select>
            </div>"""
          } else if (providers.length == 1) {
            // Single provider in production: use hidden field
            s"""<input type="hidden" name="provider" value="${htmlEncode(providers.head)}">"""
          } else {
            // No providers - shouldn't happen but handle gracefully
            s"""<div class="form-group">
              <label for="provider">Authentication Provider</label>
              <select id="provider" name="provider" required>
              $providerOptions
              </select>
            </div>"""
          }}

            <input type="hidden" name="client_id" value="${htmlEncode(clientId)}">
            <input type="hidden" name="redirect_uri" value="${htmlEncode(redirectUri)}">
            <input type="hidden" name="scope" value="${htmlEncode(scope)}">
            <input type="hidden" name="response_type" value="${htmlEncode(responseType)}">
            $stateParam
            $nonceParam
            $consentIdParam
            $codeChallengeParam
            $codeChallengeMethodParam

            <button type="submit">Sign In</button>
          </form>
        </div>
        <script>
          (function() {
            var sel = document.getElementById('provider');
            if (!sel) return;
            var saved = document.cookie.replace(/(?:(?:^|.*;\\s*)lastProvider\\s*=\\s*([^;]*).*$$)|^.*$$/, '$$1');
            if (saved) {
              for (var i = 0; i < sel.options.length; i++) {
                if (sel.options[i].value === decodeURIComponent(saved)) {
                  sel.selectedIndex = i;
                  break;
                }
              }
            }
            sel.addEventListener('change', function() {
              document.cookie = 'lastProvider=' + encodeURIComponent(sel.value) + ';path=/;max-age=31536000;SameSite=Lax';
            });
            sel.form.addEventListener('submit', function() {
              document.cookie = 'lastProvider=' + encodeURIComponent(sel.value) + ';path=/;max-age=31536000;SameSite=Lax';
            });
          })();
        </script>
      </body>
      </html>
    """

        response <- Ok(html).map(
          _.withContentType(
            org.http4s.headers.`Content-Type`(MediaType.text.html)
          )
        )
        _ <- IO(logger.info(s"Login form HTML generated successfully"))
        _ <- IO(println(s"Login form HTML generated successfully"))
      } yield response).flatTap { resp =>
        IO(logger.info(s"Login form response status: ${resp.status}")) *>
          IO(println(s"Login form response status: ${resp.status}"))
      }
  }

  /** Renders a standalone testing page that allows users to input all
    * parameters and submit directly to /obp-oidc/auth. This is useful to verify
    * the login flow without any external Portal.
    */
  private def showStandaloneLoginForm(): IO[Response[IO]] = {
    for {
      providers <- authService.getAvailableProviders()

      providerOptions = providers
        .map { provider =>
          s"""<option value=\"$provider\">$provider</option>"""
        }
        .mkString("\n            ")

      forgotPasswordLink = s"${config.obpPortalBaseUrl}/forgot-password"

      html = s"""
      <!DOCTYPE html>
      <html>
      <head>
        <title>Test Login - OBP OIDC Provider</title>
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <link rel="stylesheet" href="/static/css/main.css">
        <link rel="stylesheet" href="/static/css/forms.css">
      </head>
      <body class="form-page">
        <div class="login-container-large">
          <h2>OBP-OIDC Test Login</h2>
          <p class=\"subtitle\">Development Testing Interface</p>
          <div class=\"box\">
            <div class=\"hint\">This form submits to <code>/obp-oidc/auth</code> and simulates an OAuth2 Authorization Code request.</div>
          </div>

          <form method=\"post\" action=\"/obp-oidc/auth\">
          <div class=\"form-group\">
            <label for=\"client_id\">Client ID</label>
            <input type=\"text\" id=\"client_id\" name=\"client_id\" placeholder=\"Required\" required>
          </div>

          <div class=\"form-group\">
            <label for=\"redirect_uri\">Redirect URI</label>
            <input type=\"text\" id=\"redirect_uri\" name=\"redirect_uri\" placeholder=\"https://oauth.pstmn.io/v1/callback\" required>
            <div class=\"hint\">Must be registered for the client. Postman callback is supported.</div>
          </div>

          <div class=\"form-group\">
            <label for=\"scope\">Scope</label>
            <input type=\"text\" id=\"scope\" name=\"scope\" value=\"openid email profile\" required>
          </div>

          <div class=\"row\">
            <div class=\"form-group\">
              <label for=\"state\">State (optional)</label>
              <input type=\"text\" id=\"state\" name=\"state\" placeholder=\"optional\">
            </div>
            <div class=\"form-group\">
              <label for=\"nonce\">Nonce (optional)</label>
              <input type=\"text\" id=\"nonce\" name=\"nonce\" placeholder=\"optional\">
            </div>
          </div>

          <div class=\"form-group\">
            <label for=\"username\">Username</label>
            <input type=\"text\" id=\"username\" name=\"username\" required>
          </div>

          <div class=\"form-group\">
            <label for=\"password\">Password</label>
            <input type=\"password\" id=\"password\" name=\"password\" required>
            <div style=\"text-align: right; margin-top: 0.5rem;\">
              <a href=\"$forgotPasswordLink\" style=\"font-size: 0.9rem; color: #0066cc; text-decoration: none;\">Forgot password?</a>
            </div>
          </div>

          <div class=\"form-group\">
            <label for=\"provider\">Authentication Provider</label>
            <select id=\"provider\" name=\"provider\" required>
              $providerOptions
            </select>
          </div>

            <button type=\"submit\">Sign In</button>
          </form>
        </div>
        <script>
          (function() {
            var sel = document.getElementById('provider');
            if (!sel) return;
            var saved = document.cookie.replace(/(?:(?:^|.*;\\s*)lastProvider\\s*=\\s*([^;]*).*$$)|^.*$$/, '$$1');
            if (saved) {
              for (var i = 0; i < sel.options.length; i++) {
                if (sel.options[i].value === decodeURIComponent(saved)) {
                  sel.selectedIndex = i;
                  break;
                }
              }
            }
            sel.addEventListener('change', function() {
              document.cookie = 'lastProvider=' + encodeURIComponent(sel.value) + ';path=/;max-age=31536000;SameSite=Lax';
            });
            sel.form.addEventListener('submit', function() {
              document.cookie = 'lastProvider=' + encodeURIComponent(sel.value) + ';path=/;max-age=31536000;SameSite=Lax';
            });
          })();
        </script>
      </body>
      </html>
      """

      response <- Ok(html).map(
        _.withContentType(
          org.http4s.headers.`Content-Type`(MediaType.text.html)
        )
      )
    } yield response
  }

  private def redirectWithCode(
      redirectUri: String,
      code: String,
      state: Option[String]
  ): IO[Response[IO]] = {
    val stateParam = state.map(s => s"&state=${java.net.URLEncoder.encode(s, "UTF-8")}").getOrElse("") // Code URL-encoding
    val location = s"$redirectUri?code=$code$stateParam"
    IO(println(s"Redirecting with code to: $location")) *>
    SeeOther(Location(Uri.unsafeFromString(location)))
  }

  /** Redirect with both code and id_token in the fragment (hybrid flow).
    * Per OIDC Core 3.3.2.5, when response_type includes a token or id_token,
    * parameters MUST be returned in the URI fragment.
    */
  private def redirectWithCodeAndIdToken(
      redirectUri: String,
      code: String,
      idToken: String,
      state: Option[String]
  ): IO[Response[IO]] = {
    val stateParam = state.map(s => s"&state=${java.net.URLEncoder.encode(s, "UTF-8")}").getOrElse("")
    val location = s"$redirectUri#code=$code&id_token=$idToken$stateParam"
    IO(logger.info(s"Redirecting with code and id_token (hybrid flow) to: ${redirectUri}#code=...&id_token=...")) *>
    IO(println(s"Redirecting with code and id_token (hybrid flow)")) *>
    SeeOther(Location(Uri.unsafeFromString(location)))
  }

  private def redirectWithError(
      redirectUri: String,
      error: OidcError
  ): IO[Response[IO]] = {
    val stateParam = error.state.map(s => s"&state=${java.net.URLEncoder.encode(s, "UTF-8")}").getOrElse("")
    val descriptionParam = error.error_description
      .map(d => s"&error_description=${java.net.URLEncoder.encode(d, "UTF-8")}")
      .getOrElse("")
    val location =
      s"$redirectUri?error=${error.error}$descriptionParam$stateParam"
    SeeOther(Location(Uri.unsafeFromString(location)))
  }
}

object AuthEndpoint {
  def apply(
      authService: AuthService[IO],
      codeService: CodeService[IO],
      statsService: StatsService[IO],
      rateLimitService: RateLimitService[IO],
      config: OidcConfig,
      jwtService: JwtService[IO],
      consentChallengesRef: Ref[IO, Map[String, ConsentChallenge]],
      parService: ParService[IO]
  ): AuthEndpoint =
    new AuthEndpoint(
      authService,
      codeService,
      statsService,
      rateLimitService,
      config,
      jwtService,
      consentChallengesRef,
      parService
    )
}
