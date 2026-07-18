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
import com.tesobe.oidc.models.{AuthorizationCode, OidcError}
import com.tesobe.oidc.config.OidcConfig

import java.time.Instant
import java.util.UUID
import scala.concurrent.duration._
import org.slf4j.LoggerFactory

trait CodeService[F[_]] {
  def generateCode(
      clientId: String,
      redirectUri: String,
      sub: String,
      scope: String,
      state: Option[String] = None,
      nonce: Option[String] = None,
      provider: Option[String] = None,
      consentId: Option[String] = None,
      codeChallenge: Option[String] = None,
      codeChallengeMethod: Option[String] = None
  ): F[String]
  def validateAndConsumeCode(
      code: String,
      clientId: String,
      redirectUri: String
  ): F[Either[OidcError, AuthorizationCode]]
}

class InMemoryCodeService(
    config: OidcConfig,
    codesRef: Ref[IO, Map[String, AuthorizationCode]]
) extends CodeService[IO] {

  private val logger = LoggerFactory.getLogger(getClass)

  def generateCode(
      clientId: String,
      redirectUri: String,
      sub: String,
      scope: String,
      state: Option[String] = None,
      nonce: Option[String] = None,
      provider: Option[String] = None,
      consentId: Option[String] = None,
      codeChallenge: Option[String] = None,
      codeChallengeMethod: Option[String] = None
  ): IO[String] = {
    for {
      code <- IO(UUID.randomUUID().toString.replace("-", ""))
      exp = Instant
        .now()
        .plusSeconds(config.codeExpirationSeconds)
        .getEpochSecond

      authCode = AuthorizationCode(
        code = code,
        client_id = clientId,
        redirect_uri = redirectUri,
        sub = sub,
        scope = scope,
        state = state,
        nonce = nonce,
        provider = provider,
        exp = exp,
        consent_id = consentId,
        code_challenge = codeChallenge,
        code_challenge_method = codeChallengeMethod
      )

      _ <- codesRef.update(_ + (code -> authCode))
      _ = logger.info(
        s"Generated authorization code: ${code.take(8)}... for clientId: $clientId, redirectUri: $redirectUri, sub: $sub, expires in ${config.codeExpirationSeconds}s"
      )
      totalCodes <- codesRef.get.map(_.size)
      _ = logger.info(s"Total codes in memory: $totalCodes")
    } yield code
  }

  def validateAndConsumeCode(
      code: String,
      clientId: String,
      redirectUri: String
  ): IO[Either[OidcError, AuthorizationCode]] = {
    logger.trace(
      s"validateAndConsumeCode ENTRY - code: ${code.take(8)}..., clientId: $clientId"
    )
    logger.info(
      s"DEBUG: validateAndConsumeCode called with code: ${code.take(8)}..., clientId: $clientId"
    )
    for {
      codes <- codesRef.get
      _ = logger.trace(
        s"Found ${codes.size} stored codes in memory"
      )
      _ = logger.info(s"DEBUG: Found ${codes.size} stored codes")
      result <- codes.get(code) match {
        case Some(authCode) =>
          logger.trace(
            s"FOUND authorization code for client: ${authCode.client_id}, sub: ${authCode.sub}"
          )
          logger.info(
            s"DEBUG: Found authorization code for client: ${authCode.client_id}, sub: ${authCode.sub}"
          )
          logger.info(
            s"DEBUG: Code expires at: ${authCode.exp}, current time: ${Instant.now().getEpochSecond}"
          )
          validateCode(authCode, clientId, redirectUri).flatMap {
            case Right(validCode) =>
              logger.trace(
                s"Authorization code validation SUCCESS for sub: ${validCode.sub}"
              )
              logger.info(
                s"DEBUG: Authorization code validated successfully for sub: ${validCode.sub}"
              )
              // Consume the code (remove it after use)
              codesRef.update(_ - code).as(validCode.asRight[OidcError])
            case Left(error) =>
              logger.trace(
                s"Authorization code validation FAILED: ${error.error} - ${error.error_description
                    .getOrElse("No description")}"
              )
              logger.warn(
                s"DEBUG: Authorization code validation failed: ${error.error} - ${error.error_description
                    .getOrElse("No description")}"
              )
              // Remove invalid code
              codesRef.update(_ - code).as(error.asLeft[AuthorizationCode])
          }
        case None =>
          logger.trace(
            s"Authorization code NOT FOUND: ${code.take(8)}..."
          )
          logger.warn(
            s"DEBUG: Authorization code not found: ${code.take(8)}..."
          )
          logger.warn(
            s"DEBUG: Available codes in memory: ${codes.keys.map(_.take(8)).mkString(", ")}"
          )
          logger.warn(
            s"DEBUG: Looking for exact code match for clientId: $clientId, redirectUri: $redirectUri"
          )
          IO.pure(
            OidcError("invalid_grant", Some("Authorization code not found"))
              .asLeft[AuthorizationCode]
          )
      }
    } yield result
  }

  private def validateCode(
      authCode: AuthorizationCode,
      clientId: String,
      redirectUri: String
  ): IO[Either[OidcError, AuthorizationCode]] = {
    IO {
      val now = Instant.now().getEpochSecond

      logger.info(
        s"DEBUG: Validating code - Expected clientId: ${authCode.client_id}, Provided: $clientId"
      )
      logger.info(
        s"DEBUG: Validating code - Expected redirectUri: ${authCode.redirect_uri}, Provided: $redirectUri"
      )

      if (authCode.exp < now) {
        logger.warn(
          s"DEBUG: Authorization code expired (exp: ${authCode.exp}, now: $now)"
        )
        OidcError("invalid_grant", Some("Authorization code expired"))
          .asLeft[AuthorizationCode]
      } else if (authCode.client_id != clientId) {
        logger.warn(
          s"DEBUG: Client ID mismatch (expected: ${authCode.client_id}, got: $clientId)"
        )
        OidcError("invalid_grant", Some("Client ID mismatch"))
          .asLeft[AuthorizationCode]
      } else if (authCode.redirect_uri != redirectUri) {
        logger.warn(
          s"DEBUG: Redirect URI mismatch (expected: ${authCode.redirect_uri}, got: $redirectUri)"
        )
        OidcError("invalid_grant", Some("Redirect URI mismatch"))
          .asLeft[AuthorizationCode]
      } else {
        logger.info(s"DEBUG: All validations passed for code")
        authCode.asRight[OidcError]
      }
    }
  }

  // Helper method to clean up expired codes
  def cleanupExpiredCodes: IO[Unit] = {
    val now = Instant.now().getEpochSecond
    codesRef.update(_.filter(_._2.exp > now))
  }
}

object CodeService {
  def apply(config: OidcConfig): IO[CodeService[IO]] = {
    for {
      codesRef <- Ref.of[IO, Map[String, AuthorizationCode]](Map.empty)
    } yield new InMemoryCodeService(config, codesRef)
  }
}
