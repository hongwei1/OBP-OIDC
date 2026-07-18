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

package com.tesobe.oidc.auth

import cats.effect.{IO, Ref}
import cats.syntax.either._
import com.tesobe.oidc.models.{OidcError, PushedAuthorizationRequest}
import com.tesobe.oidc.config.OidcConfig

import java.time.Instant
import java.util.UUID
import org.slf4j.LoggerFactory

/** PAR (RFC 9126): lets a client push authorization-request parameters to the
  * server ahead of time and get back a `request_uri` to reference them from
  * GET /auth, instead of exposing them (and, with FAPI, a signed request
  * object) on the front-channel query string.
  */
trait ParService[F[_]] {
  def pushAuthorizationRequest(
      clientId: String,
      responseType: String,
      redirectUri: String,
      scope: String,
      state: Option[String] = None,
      nonce: Option[String] = None,
      consentRequestId: Option[String] = None,
      bankId: Option[String] = None,
      consentId: Option[String] = None,
      codeChallenge: Option[String] = None,
      codeChallengeMethod: Option[String] = None
  ): F[PushedAuthorizationRequest]

  def consumeRequest(
      requestUri: String,
      clientId: String
  ): F[Either[OidcError, PushedAuthorizationRequest]]
}

class InMemoryParService(
    config: OidcConfig,
    requestsRef: Ref[IO, Map[String, PushedAuthorizationRequest]]
) extends ParService[IO] {

  private val logger = LoggerFactory.getLogger(getClass)
  private val requestUriPrefix = "urn:ietf:params:oauth:request_uri:"

  def pushAuthorizationRequest(
      clientId: String,
      responseType: String,
      redirectUri: String,
      scope: String,
      state: Option[String] = None,
      nonce: Option[String] = None,
      consentRequestId: Option[String] = None,
      bankId: Option[String] = None,
      consentId: Option[String] = None,
      codeChallenge: Option[String] = None,
      codeChallengeMethod: Option[String] = None
  ): IO[PushedAuthorizationRequest] = {
    for {
      requestUri <- IO(requestUriPrefix + UUID.randomUUID().toString)
      exp = Instant.now().plusSeconds(config.parExpirationSeconds).getEpochSecond
      par = PushedAuthorizationRequest(
        request_uri = requestUri,
        client_id = clientId,
        response_type = responseType,
        redirect_uri = redirectUri,
        scope = scope,
        state = state,
        nonce = nonce,
        consent_request_id = consentRequestId,
        bank_id = bankId,
        consent_id = consentId,
        code_challenge = codeChallenge,
        code_challenge_method = codeChallengeMethod,
        exp = exp
      )
      _ <- requestsRef.update(_ + (requestUri -> par))
      _ = logger.info(
        s"Pushed authorization request for clientId: $clientId, request_uri: ${requestUri.takeRight(8)}..., expires in ${config.parExpirationSeconds}s"
      )
    } yield par
  }

  def consumeRequest(
      requestUri: String,
      clientId: String
  ): IO[Either[OidcError, PushedAuthorizationRequest]] = {
    for {
      requests <- requestsRef.get
      result <- requests.get(requestUri) match {
        case None =>
          logger.warn(s"PAR request_uri not found: ${requestUri.takeRight(8)}...")
          IO.pure(
            OidcError("invalid_request_uri", Some("Unknown or expired request_uri")).asLeft[PushedAuthorizationRequest]
          )
        case Some(par) =>
          // One-time use regardless of outcome (RFC 9126 SS4).
          requestsRef.update(_ - requestUri) *> {
            val now = Instant.now().getEpochSecond
            if (par.exp < now) {
              logger.warn(s"PAR request_uri expired: ${requestUri.takeRight(8)}...")
              IO.pure(
                OidcError("invalid_request_uri", Some("request_uri has expired")).asLeft[PushedAuthorizationRequest]
              )
            } else if (par.client_id != clientId) {
              logger.warn(
                s"PAR client_id mismatch (expected: ${par.client_id}, got: $clientId)"
              )
              IO.pure(
                OidcError("invalid_request_uri", Some("client_id does not match the pushed request")).asLeft[PushedAuthorizationRequest]
              )
            } else {
              IO.pure(par.asRight[OidcError])
            }
          }
      }
    } yield result
  }

  def cleanupExpiredRequests: IO[Unit] = {
    val now = Instant.now().getEpochSecond
    requestsRef.update(_.filter(_._2.exp > now))
  }
}

object ParService {
  def apply(config: OidcConfig): IO[ParService[IO]] = {
    for {
      requestsRef <- Ref.of[IO, Map[String, PushedAuthorizationRequest]](Map.empty)
    } yield new InMemoryParService(config, requestsRef)
  }
}
