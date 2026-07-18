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
import com.tesobe.oidc.auth.{AuthService, ParService}
import com.tesobe.oidc.config.OidcConfig
import com.tesobe.oidc.models.{OidcError, ParResponse}
import io.circe.syntax._
import org.http4s._
import org.http4s.circe._
import org.http4s.dsl.io._
import org.typelevel.ci.CIString
import org.slf4j.LoggerFactory

/** PAR (RFC 9126) pushed authorization request endpoint: POST /obp-oidc/par.
  *
  * Accepts the same parameters as GET /auth, plus optional client
  * credentials, and returns a `request_uri` the client then passes to
  * GET /auth instead of the individual parameters.
  */
class ParEndpoint(
    authService: AuthService[IO],
    parService: ParService[IO],
    config: OidcConfig
) {

  private val logger = LoggerFactory.getLogger(getClass)

  val routes: HttpRoutes[IO] = HttpRoutes.of[IO] {
    case req @ POST -> Root / "obp-oidc" / "par" =>
      req.as[UrlForm].attempt.flatMap {
        case Right(form) => handleParRequest(req, form)
        case Left(error) =>
          logger.warn(s"Failed to parse PAR form data: ${error.getMessage}")
          BadRequest(
            OidcError("invalid_request", Some("Failed to parse form data")).asJson
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
            val decoded = new String(java.util.Base64.getDecoder.decode(encoded), "UTF-8")
            decoded.split(":", 2) match {
              case Array(clientId, clientSecret) => Some((clientId, clientSecret))
              case _                              => None
            }
          } catch {
            case _: Exception => None
          }
        } else None
      }
  }

  private def handleParRequest(
      req: Request[IO],
      form: UrlForm
  ): IO[Response[IO]] = {
    val formData = form.values.view.mapValues(_.headOption.getOrElse("")).toMap

    val responseType = formData.get("response_type")
    val redirectUri = formData.get("redirect_uri")
    val scope = formData.get("scope")
    val basicCredentialsOpt = extractBasicAuthCredentials(req)
    val clientIdFromForm = formData.get("client_id")
    val clientSecretFromForm = formData.get("client_secret")
    val resolvedClientId = basicCredentialsOpt.map(_._1).orElse(clientIdFromForm)
    val credentialsOpt: Option[(String, String)] =
      basicCredentialsOpt.orElse {
        (clientIdFromForm, clientSecretFromForm) match {
          case (Some(id), Some(secret)) => Some((id, secret))
          case _                        => None
        }
      }
    val state = formData.get("state")
    val nonce = formData.get("nonce")
    val consentRequestId = formData.get("consent_request_id")
    val bankId = formData.get("bank_id")
    val consentId = formData.get("consent_id")
    val codeChallenge = formData.get("code_challenge")
    val codeChallengeMethod = formData.get("code_challenge_method")

    (responseType, resolvedClientId, redirectUri, scope) match {
      case (Some(rt), Some(clientId), Some(ru), Some(sc)) =>
        if (codeChallengeMethod.exists(_ != "S256")) {
          BadRequest(
            OidcError("invalid_request", Some("code_challenge_method must be S256")).asJson
          )
        } else {
          val authenticated: IO[Either[OidcError, Unit]] = credentialsOpt match {
            case Some((id, secret)) =>
              if (id != clientId) {
                IO.pure(Left(OidcError("invalid_client", Some("Client ID mismatch"))))
              } else {
                authService.authenticateClient(id, secret).map(_.map(_ => ()))
              }
            case None =>
              // Public client (no secret) — same lenient acceptance as the token endpoint.
              IO.pure(Right(()))
          }

          authenticated.flatMap {
            case Left(error) =>
              logger.warn(s"PAR client authentication failed: ${error.error}")
              BadRequest(error.asJson)
            case Right(()) =>
              authService.validateClient(clientId, ru).flatMap { isValid =>
                if (!isValid) {
                  logger.warn(
                    s"PAR client validation failed for clientId: $clientId, redirectUri: $ru"
                  )
                  BadRequest(
                    OidcError("invalid_client", Some("Invalid client_id or redirect_uri")).asJson
                  )
                } else if (rt != "code" && rt != "code id_token") {
                  BadRequest(
                    OidcError("unsupported_response_type", Some("Supported response types: 'code', 'code id_token'")).asJson
                  )
                } else if (!sc.contains("openid")) {
                  BadRequest(
                    OidcError("invalid_scope", Some("'openid' scope is required")).asJson
                  )
                } else {
                  parService
                    .pushAuthorizationRequest(
                      clientId = clientId,
                      responseType = rt,
                      redirectUri = ru,
                      scope = sc,
                      state = state,
                      nonce = nonce,
                      consentRequestId = consentRequestId,
                      bankId = bankId,
                      consentId = consentId,
                      codeChallenge = codeChallenge,
                      codeChallengeMethod = codeChallengeMethod
                    )
                    .flatMap { par =>
                      Created(ParResponse(par.request_uri, config.parExpirationSeconds).asJson)
                    }
                }
              }
          }
        }
      case _ =>
        BadRequest(
          OidcError("invalid_request", Some("Missing required parameters: response_type, client_id, redirect_uri, scope")).asJson
        )
    }
  }
}

object ParEndpoint {
  def apply(
      authService: AuthService[IO],
      parService: ParService[IO],
      config: OidcConfig
  ): ParEndpoint = new ParEndpoint(authService, parService, config)
}
