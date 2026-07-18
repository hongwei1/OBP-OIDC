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

import cats.effect.IO
import cats.syntax.all._
import com.tesobe.oidc.auth.{AuthService, CodeService, ClientAssertionService}
import com.tesobe.oidc.models.{OidcError, TokenRequest, TokenResponse}
import com.tesobe.oidc.tokens.JwtService
import com.tesobe.oidc.config.OidcConfig
import com.tesobe.oidc.stats.StatsService
import io.circe.syntax._
import org.http4s._
import org.http4s.circe._
import org.typelevel.ci.CIString
import org.http4s.dsl.io._
import org.slf4j.LoggerFactory
import java.security.MessageDigest

class TokenEndpoint(
    authService: AuthService[IO],
    codeService: CodeService[IO],
    jwtService: JwtService[IO],
    config: OidcConfig,
    statsService: StatsService[IO],
    clientAssertionService: ClientAssertionService[IO]
) {

  private val logger = LoggerFactory.getLogger(getClass)
  private val tokenEndpointUrl = s"${config.issuer}/token"

  val routes: HttpRoutes[IO] = HttpRoutes.of[IO] {
    case req @ POST -> Root / "obp-oidc" / "token" =>
      println(
        s"DEBUG: TokenEndpoint route matched! ${req.method} ${req.uri}"
      )
      println(s"DEBUG: About to log with logger...")
      logger.info(s"Token endpoint called")
      logger.info(
        s"Content-Type: ${req.headers.get[headers.`Content-Type`].map(_.mediaType).getOrElse("MISSING")}"
      )
      logger.info(
        s"Headers: ${req.headers.headers.map(h => s"${h.name}: ${h.value}").mkString(", ")}"
      )
      println(s"DEBUG: Logger calls completed, about to parse form...")

      req.as[UrlForm].attempt.flatMap {
        case Right(form) =>
          println(s"DEBUG: Form parsing successful")
          println(s"DEBUG: Form data: ${form.values}")
          handleTokenRequest(req, form)
        case Left(error) =>
          println(s"DEBUG: Form parsing failed: ${error.getMessage}")
          logger
            .error(s"Failed to parse form data: ${error.getMessage}", error)
          BadRequest(
            OidcError(
              "invalid_request",
              Some("Failed to parse form data")
            ).asJson
          )
      }

  }

  private def extractBasicAuthCredentials(
      req: Request[IO]
  ): Option[(String, String)] = {
    req.headers
      .get(CIString("Authorization"))
      .flatMap { authHeader =>
        val authValue = authHeader.head.value
        if (authValue.startsWith("Basic ")) {
          val encoded = authValue.substring(6)
          try {
            val decoded = new String(
              java.util.Base64.getDecoder.decode(encoded),
              "UTF-8"
            )
            decoded.split(":", 2) match {
              case Array(clientId, clientSecret) =>
                Some((clientId, clientSecret))
              case _ => None
            }
          } catch {
            case _: Exception => None
          }
        } else None
      }
  }

  private def handleTokenRequest(
      req: Request[IO],
      form: UrlForm
  ): IO[Response[IO]] = {
    println(s"DEBUG: handleTokenRequest called")
    val formData = form.values.view.mapValues(_.headOption.getOrElse("")).toMap
    println(s"DEBUG: formData created: ${formData}")

    logger.info(s"Token request received")
    logger.info(s"Form data keys: ${formData.keys.mkString(", ")}")

    val grantType = formData.get("grant_type")
    val code = formData.get("code")
    val redirectUri = formData.get("redirect_uri")
    // Support both Basic Auth header and form parameters for client authentication
    val basicCredentialsOpt = extractBasicAuthCredentials(req)
    val clientIdFromBasic = basicCredentialsOpt.map(_._1)
    val clientSecretFromBasic = basicCredentialsOpt.map(_._2)
    val clientIdFromForm = formData.get("client_id")
    val clientSecretFromForm = formData.get("client_secret")
    // Prefer Basic credentials if present; fall back to form client_id
    val resolvedClientId = clientIdFromBasic.orElse(clientIdFromForm)
    val credentialSource = if (clientIdFromBasic.isDefined) "Basic auth header" else if (clientIdFromForm.isDefined) "form data" else "NONE"
    val refreshToken = formData.get("refresh_token")
    val codeVerifier = formData.get("code_verifier") // PKCE (RFC 7636)
    // private_key_jwt client authentication (RFC 7523 / FAPI 1.0 Advanced)
    val clientAssertionType = formData.get("client_assertion_type")
    val clientAssertion = formData.get("client_assertion")
    val usesClientAssertion = clientAssertion.isDefined &&
      clientAssertionType.contains(ClientAssertionService.JwtBearerAssertionType)

    println(s"DEBUG: Grant type extracted: ${grantType}")
    logger.info(s"Grant type: ${grantType.getOrElse("MISSING")}")
    logger.info(s"Code: ${code.map(_ => "PROVIDED").getOrElse("MISSING")}")
    logger.info(s"Redirect URI: ${redirectUri.getOrElse("MISSING")}")
    logger.info(s"Client ID: ${resolvedClientId.getOrElse("MISSING")} (source: $credentialSource)")
    clientSecretFromBasic.foreach { secret =>
      val masked = if (secret.length <= 4) "****"
        else secret.take(2) + "*" * (secret.length - 4) + secret.takeRight(2)
      logger.info(s"Client secret from Basic auth: length=${secret.length}, masked=$masked")
    }

    println(s"DEBUG: About to match on parameters")
    grantType match {
      case Some("authorization_code") =>
        // Build optional credentials tuple for validation when provided
        val credentialsOpt: Option[(String, String)] =
          basicCredentialsOpt.orElse {
            (clientIdFromForm, clientSecretFromForm) match {
              case (Some(id), Some(secret)) => Some((id, secret))
              case _                        => None
            }
          }

        (code, redirectUri, resolvedClientId) match {
          case (Some(authCode), Some(redirectUriValue), Some(clientIdValue)) =>
            println(s"DEBUG: Matched authorization_code case")
            logger.info(
              s"Processing authorization_code grant for client: $clientIdValue"
            )
            // private_key_jwt (FAPI 1.0 Advanced) takes priority over Basic/secret auth when present.
            if (usesClientAssertion) {
              clientAssertionService.verify(clientAssertion.get, tokenEndpointUrl).flatMap {
                case Right(assertedClientId) if assertedClientId == clientIdValue =>
                  processAuthorizationCodeGrant(authCode, redirectUriValue, clientIdValue, codeVerifier)
                case Right(_) =>
                  logger.warn("client_assertion's client_id does not match resolved client_id")
                  BadRequest(OidcError("invalid_client", Some("client_id does not match client_assertion")).asJson)
                case Left(error) =>
                  logger.warn(s"Client assertion verification failed for authorization_code: ${error.error}")
                  BadRequest(error.asJson)
              }
            } else {
              // If credentials are provided (Basic or form), validate client secret
              credentialsOpt match {
                case Some((id, secret)) =>
                  if (id != clientIdValue) {
                    logger.warn(
                      "Client ID in credentials does not match resolved client_id"
                    )
                    BadRequest(
                      OidcError(
                        "invalid_client",
                        Some("Client ID mismatch")
                      ).asJson
                    )
                  } else {
                    authService.authenticateClient(id, secret).flatMap {
                      case Right(_) =>
                        logger.trace(
                          s"About to call processAuthorizationCodeGrant (basic auth validated)"
                        )
                        processAuthorizationCodeGrant(
                          authCode,
                          redirectUriValue,
                          clientIdValue,
                          codeVerifier
                        )
                      case Left(error) =>
                        logger.warn(
                          s"Client authentication failed for authorization_code: ${error.error}"
                        )
                        BadRequest(error.asJson)
                    }
                  }
                case None =>
                  // Public client (no secret) or legacy behavior
                  logger.trace(
                    s"About to call processAuthorizationCodeGrant (no client secret provided)"
                  )
                  processAuthorizationCodeGrant(
                    authCode,
                    redirectUriValue,
                    clientIdValue,
                    codeVerifier
                  )
              }
            }
          case _ =>
            println(
              s"DEBUG: Missing required parameters for authorization_code"
            )
            logger.warn(
              s"Missing required parameters for authorization_code - code: ${code.isDefined}, redirect_uri: ${redirectUri.isDefined}, client_id: ${resolvedClientId.isDefined}"
            )
            BadRequest(
              OidcError(
                "invalid_request",
                Some("Missing required parameters for authorization_code grant")
              ).asJson
            )
        }
      case Some("refresh_token") =>
        (refreshToken, resolvedClientId) match {
          case (Some(refreshTokenValue), Some(clientIdValue)) =>
            println(s"DEBUG: Matched refresh_token case")
            logger.info(
              s"Processing refresh_token grant for client: $clientIdValue"
            )
            processRefreshTokenGrant(refreshTokenValue, clientIdValue)
          case _ =>
            println(s"DEBUG: Missing required parameters for refresh_token")
            logger.warn(
              s"Missing required parameters for refresh_token - refresh_token: ${refreshToken.isDefined}, client_id: ${resolvedClientId.isDefined}"
            )
            BadRequest(
              OidcError(
                "invalid_request",
                Some("Missing required parameters for refresh_token grant")
              ).asJson
            )
        }
      case Some("client_credentials") =>
        println(s"DEBUG: Matched client_credentials case")
        logger.info(s"Processing client_credentials grant")

        val scope = formData.getOrElse("scope", "")

        if (usesClientAssertion) {
          clientAssertionService.verify(clientAssertion.get, tokenEndpointUrl).flatMap {
            case Right(assertedClientId) =>
              logger.trace("client_credentials authenticated via client_assertion")
              issueClientCredentialsToken(assertedClientId, scope)
            case Left(error) =>
              logger.warn(s"Client assertion verification failed for client_credentials: ${error.error}")
              BadRequest(error.asJson)
          }
        } else {
          // Extract client credentials from Basic Auth header or form data
          val credentials = extractBasicAuthCredentials(req).orElse {
            (formData.get("client_id"), formData.get("client_secret")) match {
              case (Some(id), Some(secret)) => Some((id, secret))
              case _                        => None
            }
          }

          credentials match {
            case Some((clientIdValue, clientSecretValue)) =>
              processClientCredentialsGrant(
                clientIdValue,
                clientSecretValue,
                scope
              )
            case None =>
              println(
                s"DEBUG: Missing client credentials for client_credentials"
              )
              logger.warn(
                s"Missing client credentials for client_credentials grant"
              )
              BadRequest(
                OidcError(
                  "invalid_request",
                  Some(
                    "Missing client_id and client_secret for client_credentials grant"
                  )
                ).asJson
              )
          }
        }
      case Some(unsupportedGrant) =>
        println(
          s"DEBUG: Matched unsupported grant type case: '$unsupportedGrant'"
        )
        logger.warn(s"Unsupported grant type: '$unsupportedGrant'")
        BadRequest(
          OidcError(
            "unsupported_grant_type",
            Some(s"Grant type '$unsupportedGrant' is not supported")
          ).asJson
        )
      case None =>
        println(s"DEBUG: Missing grant_type parameter")
        logger.warn(s"Missing grant_type parameter")
        BadRequest(
          OidcError(
            "invalid_request",
            Some("Missing grant_type parameter")
          ).asJson
        )
    }
  }

  // PKCE (RFC 7636 §4.6): BASE64URL-ENCODE(SHA256(ASCII(code_verifier))), no padding.
  private def computeS256Challenge(codeVerifier: String): String = {
    val digest = MessageDigest
      .getInstance("SHA-256")
      .digest(codeVerifier.getBytes(java.nio.charset.StandardCharsets.US_ASCII))
    java.util.Base64.getUrlEncoder.withoutPadding.encodeToString(digest)
  }

  private def processAuthorizationCodeGrant(
      code: String,
      redirectUri: String,
      clientId: String,
      codeVerifier: Option[String] = None
  ): IO[Response[IO]] = {

    logger.info(s"Validating authorization code for client: $clientId")
    logger.info(
      s"DEBUG: Code: ${code.take(8)}..., RedirectUri: $redirectUri"
    )
    logger.trace(
      s"About to call validateAndConsumeCode with code: ${code.take(8)}..."
    )
    codeService.validateAndConsumeCode(code, clientId, redirectUri).flatMap {
      case Right(authCode) =>
        logger.trace(
          s"Authorization code validation SUCCESS for user: ${authCode.sub}"
        )
        logger.info(s"Authorization code validated for user: ${authCode.sub}")
        logger.info(
          s"DEBUG: AuthCode details - scope: ${authCode.scope}, nonce: ${authCode.nonce}"
        )
        // PKCE (RFC 7636 §4.6): if the authorization request carried a code_challenge, the
        // matching code_verifier is mandatory here and must hash (S256) to that challenge.
        // If no challenge was captured, no verifier is required (non-PKCE clients unaffected).
        val pkceResult: Either[OidcError, Unit] = authCode.code_challenge match {
          case None => Right(())
          case Some(challenge) =>
            codeVerifier match {
              case None =>
                Left(OidcError("invalid_grant", Some("code_verifier is required for this authorization code")))
              case Some(verifier) if computeS256Challenge(verifier) == challenge =>
                Right(())
              case Some(_) =>
                Left(OidcError("invalid_grant", Some("code_verifier does not match code_challenge")))
            }
        }
        pkceResult match {
          case Left(err) =>
            logger.warn(s"PKCE verification failed for client $clientId: ${err.error_description.getOrElse("")}")
            BadRequest(err.asJson)
          case Right(()) =>
        // Get user information - use provider from auth code when available (API mode)
        logger.info(
          s"Looking up user: sub=${authCode.sub}, provider=${authCode.provider.getOrElse("none")}"
        )
        (authCode.provider match {
          case Some(provider) =>
            authService.getUserBySubAndProvider(authCode.sub, provider)
          case None =>
            authService.getUserById(authCode.sub)
        }).flatMap {
          case Some(user) =>
            logger.trace(s"User FOUND: ${user.username}")
            logger.info(s"User found: ${user.username}, generating tokens...")
            logger.info(
              s"DEBUG: About to generate tokens with azp claim set to clientId: $clientId"
            )
            logger.trace(
              s"Entering for comprehension for token generation"
            )
            for {
              // Generate tokens
              _ <- IO.pure(
                logger.trace(s"About to generate ID token")
              )
              _ <- IO.pure(
                logger.info(
                  s"DEBUG: Calling generateIdToken with clientId (azp): $clientId"
                )
              )
              idToken <- jwtService
                .generateIdToken(user, clientId, authCode.nonce, authCode.consent_id)
              _ <- IO.pure(
                logger.trace(s"ID token generated successfully")
              )
              _ <- IO.pure(
                logger.info(
                  s"DEBUG: Calling generateAccessToken with clientId (azp): $clientId"
                )
              )
              accessToken <- jwtService
                .generateAccessToken(user, clientId, authCode.scope, authCode.consent_id)
              _ <- IO.pure(
                logger.trace(
                  s"Access token generated successfully"
                )
              )
              _ <- IO.pure(
                logger.info(s"DEBUG: Both tokens generated successfully")
              )

              // Track successful authorization code grant
              _ <- statsService
                .incrementAuthorizationCodeSuccess(clientId, user.username)

              // Generate refresh token (stateless JWT)
              refreshTokenJwt <- jwtService
                .generateRefreshToken(user, clientId, authCode.scope, authCode.consent_id)

              // Get client details for tracking
              clientOpt <- authService.findClientByClientIdThatIsKey(clientId)
              clientName = clientOpt.map(_.client_name).getOrElse(clientId)

              // Record issued tokens in stats
              accessTokenExpiry = java.time.Instant
                .now()
                .plusSeconds(config.tokenExpirationSeconds)
              refreshTokenExpiry = java.time.Instant
                .now()
                .plusSeconds(config.tokenExpirationSeconds * 720)

              // Generate unique token IDs using SHA-256 hash
              accessTokenId = MessageDigest
                .getInstance("SHA-256")
                .digest(accessToken.getBytes("UTF-8"))
                .map("%02x".format(_))
                .mkString
                .take(8)
              refreshTokenId = MessageDigest
                .getInstance("SHA-256")
                .digest(refreshTokenJwt.getBytes("UTF-8"))
                .map("%02x".format(_))
                .mkString
                .take(8)

              _ <- statsService.recordTokenIssued(
                tokenId = accessTokenId,
                clientId = clientId,
                clientName = clientName,
                username = user.username,
                expiresAt = accessTokenExpiry,
                tokenType = "access",
                scope = authCode.scope
              )

              _ <- statsService.recordTokenIssued(
                tokenId = refreshTokenId,
                clientId = clientId,
                clientName = clientName,
                username = user.username,
                expiresAt = refreshTokenExpiry,
                tokenType = "refresh",
                scope = authCode.scope
              )

              // Create token response
              tokenResponse = TokenResponse(
                access_token = accessToken,
                token_type = "Bearer",
                expires_in = config.tokenExpirationSeconds,
                id_token = idToken,
                scope = authCode.scope,
                refresh_token = Some(refreshTokenJwt)
              )

              _ <- IO.pure(
                logger.trace(
                  s"Token response created, about to send OK response"
                )
              )
              _ <- IO.pure(
                logger
                  .info(s"DEBUG: Token response created, sending response")
              )
              response <- Ok(tokenResponse.asJson)
                .map(
                  _.putHeaders(
                    Header.Raw(CIString("Cache-Control"), "no-store"),
                    Header.Raw(CIString("Pragma"), "no-cache")
                  )
                )
              _ <- IO.pure(
                logger.trace(s"OK response created successfully")
              )

            } yield response

          case None =>
            logger.trace(
              s"User NOT FOUND for sub: ${authCode.sub}"
            )
            logger.warn(s"User not found for sub: ${authCode.sub}")
            BadRequest(
              OidcError("invalid_grant", Some("User not found")).asJson
            )
        }
        } // end pkceResult match

      case Left(error) =>
        logger.trace(
          s"Authorization code validation FAILED: ${error.error} - ${error.error_description
              .getOrElse("No description")}"
        )
        logger.warn(
          s"Authorization code validation failed: ${error.error} - ${error.error_description
              .getOrElse("No description")}"
        )
        logger.info(
          s"DEBUG: This is why you don't see azp logging - code validation failed!"
        )
        // Track failed authorization code grant
        statsService
          .incrementAuthorizationCodeFailure(error.error)
          .flatMap(_ => BadRequest(error.asJson))
    }
  }

  private def processRefreshTokenGrant(
      refreshToken: String,
      clientId: String
  ): IO[Response[IO]] = {
    logger.info(s"Processing refresh token grant for client: $clientId")

    // Validate the refresh token JWT (stateless validation)
    jwtService.validateRefreshToken(refreshToken).flatMap {
      case Right(tokenClaims) =>
        logger
          .info(s"Refresh token JWT validated for user: ${tokenClaims.sub}")

        // Check if client_id matches
        if (tokenClaims.client_id != clientId) {
          logger.warn(s"Client ID mismatch in refresh token")
          BadRequest(
            OidcError("invalid_grant", Some("Client ID mismatch")).asJson
          )
        } else {
          // Get user information
          authService.getUserById(tokenClaims.sub).flatMap {
            case Some(user) =>
              logger.info(s"User found for refresh: ${user.username}")

              for {
                // Generate new access token (preserving any consent binding)
                newAccessToken <- jwtService
                  .generateAccessToken(user, clientId, tokenClaims.scope, tokenClaims.consent_id)

                // Generate new refresh token (token rotation, consent binding carried over)
                newRefreshTokenJwt <- jwtService
                  .generateRefreshToken(user, clientId, tokenClaims.scope, tokenClaims.consent_id)

                // Get client details for tracking
                clientOpt <- authService.findClientByClientIdThatIsKey(clientId)
                clientName = clientOpt.map(_.client_name).getOrElse(clientId)

                // Record issued tokens in stats
                accessTokenExpiry = java.time.Instant
                  .now()
                  .plusSeconds(config.tokenExpirationSeconds)
                refreshTokenExpiry = java.time.Instant
                  .now()
                  .plusSeconds(config.tokenExpirationSeconds * 720)

                // Generate unique token IDs using SHA-256 hash
                accessTokenId = MessageDigest
                  .getInstance("SHA-256")
                  .digest(newAccessToken.getBytes("UTF-8"))
                  .map("%02x".format(_))
                  .mkString
                  .take(8)
                refreshTokenId = MessageDigest
                  .getInstance("SHA-256")
                  .digest(newRefreshTokenJwt.getBytes("UTF-8"))
                  .map("%02x".format(_))
                  .mkString
                  .take(8)

                _ <- statsService.recordTokenIssued(
                  tokenId = accessTokenId,
                  clientId = clientId,
                  clientName = clientName,
                  username = user.username,
                  expiresAt = accessTokenExpiry,
                  tokenType = "access",
                  scope = tokenClaims.scope
                )

                _ <- statsService.recordTokenIssued(
                  tokenId = refreshTokenId,
                  clientId = clientId,
                  clientName = clientName,
                  username = user.username,
                  expiresAt = refreshTokenExpiry,
                  tokenType = "refresh",
                  scope = tokenClaims.scope
                )

                // Create token response (no ID token for refresh grant)
                tokenResponse = TokenResponse(
                  access_token = newAccessToken,
                  token_type = "Bearer",
                  expires_in = config.tokenExpirationSeconds,
                  id_token = "", // Not included in refresh token response
                  scope = tokenClaims.scope,
                  refresh_token = Some(newRefreshTokenJwt)
                )

                _ <- IO.pure(
                  logger.info(
                    s"Refresh token successfully used for user: ${user.username}, client: $clientId - New tokens issued"
                  )
                )

                // Track successful refresh token usage
                _ <- statsService
                  .incrementRefreshTokenSuccess(clientId, user.username)

                response <- Ok(tokenResponse.asJson)
                  .map(
                    _.putHeaders(
                      Header.Raw(CIString("Cache-Control"), "no-store"),
                      Header.Raw(CIString("Pragma"), "no-cache")
                    )
                  )

              } yield response

            case None =>
              logger.warn(
                s"User not found for refresh token: ${tokenClaims.sub}"
              )
              statsService
                .incrementRefreshTokenFailure("User not found")
                .flatMap(_ =>
                  BadRequest(
                    OidcError("invalid_grant", Some("User not found")).asJson
                  )
                )
          }
        }

      case Left(error) =>
        logger.warn(s"Refresh token validation failed: ${error.error}")
        statsService
          .incrementRefreshTokenFailure(error.error)
          .flatMap(_ => BadRequest(error.asJson))
    }
  }

  private def processClientCredentialsGrant(
      clientId: String,
      clientSecret: String,
      scope: String
  ): IO[Response[IO]] = {
    logger.info(
      s"Processing client credentials grant for client: $clientId"
    )

    // Authenticate the client
    authService.authenticateClient(clientId, clientSecret).flatMap {
      case Right(client) =>
        logger.info(s"Client authenticated: ${client.client_name}")
        issueClientCredentialsToken(clientId, scope)

      case Left(error) =>
        logger.warn(
          s"Client authentication failed: ${error.error} - ${error.error_description.getOrElse("No description")}"
        )
        statsService
          .incrementAuthorizationCodeFailure(error.error)
          .flatMap(_ => BadRequest(error.asJson))
    }
  }

  // Issues the client_credentials access token; the caller is responsible for
  // having already authenticated clientId, whether via client_secret or a
  // verified private_key_jwt client_assertion.
  private def issueClientCredentialsToken(
      clientId: String,
      scope: String
  ): IO[Response[IO]] = {
    for {
      // Generate access token for the client (no user context)
      accessToken <- jwtService
        .generateClientCredentialsToken(clientId, scope)

      // Create token response (no ID token or refresh token for client credentials)
      tokenResponse = TokenResponse(
        access_token = accessToken,
        token_type = "Bearer",
        expires_in = config.tokenExpirationSeconds,
        id_token = "", // Not included in client credentials response
        scope = scope,
        refresh_token = None // No refresh token for client credentials
      )

      _ <- IO.pure(
        logger.info(
          s"Client credentials grant successful for client: $clientId"
        )
      )

      // Track successful client credentials grant
      _ <- statsService
        .incrementAuthorizationCodeSuccess(clientId, clientId)

      response <- Ok(tokenResponse.asJson)
        .map(
          _.putHeaders(
            Header.Raw(CIString("Cache-Control"), "no-store"),
            Header.Raw(CIString("Pragma"), "no-cache")
          )
        )

    } yield response
  }
}

object TokenEndpoint {
  def apply(
      authService: AuthService[IO],
      codeService: CodeService[IO],
      jwtService: JwtService[IO],
      config: OidcConfig,
      statsService: StatsService[IO],
      clientAssertionService: ClientAssertionService[IO]
  ): TokenEndpoint =
    new TokenEndpoint(
      authService,
      codeService,
      jwtService,
      config,
      statsService,
      clientAssertionService
    )
}
