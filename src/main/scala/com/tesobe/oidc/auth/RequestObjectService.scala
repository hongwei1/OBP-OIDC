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

import cats.effect.IO
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jwt.SignedJWT
import com.tesobe.oidc.config.OidcConfig
import com.tesobe.oidc.models.OidcError
import org.slf4j.LoggerFactory

import scala.jdk.CollectionConverters._
import scala.util.Try

/** Authorization parameters carried inside a verified signed request object. */
case class RequestObjectClaims(
    responseType: String,
    clientId: String,
    redirectUri: String,
    scope: String,
    state: Option[String],
    nonce: Option[String],
    consentRequestId: Option[String],
    bankId: Option[String],
    consentId: Option[String],
    codeChallenge: Option[String],
    codeChallengeMethod: Option[String]
)

/** Signals a request-object validation failure through an IO chain, carrying
  * the OidcError to report back to the client. Caught and unwrapped at the
  * boundary in resolve() — never leaks past this file.
  */
private case class RequestObjectRejected(oidcError: OidcError) extends RuntimeException(oidcError.error)

/** Verifies signed request objects (JAR / RFC 9101), a FAPI 1.0 Advanced
  * requirement: instead of authorization parameters travelling as plain
  * query params, the client signs them as a JWT with its own private key.
  * OBP-OIDC verifies the signature against the client's published JWKS
  * (resolved via its jwks_uri) rather than trusting the query string.
  */
trait RequestObjectService[F[_]] {
  def resolve(
      requestJws: String,
      expectedClientId: String
  ): F[Either[OidcError, RequestObjectClaims]]
}

class DefaultRequestObjectService(
    authService: AuthService[IO],
    jwksClient: JwksClient[IO],
    config: OidcConfig
) extends RequestObjectService[IO] {

  private val logger = LoggerFactory.getLogger(getClass)

  // FAPI 1.0 Advanced: request object lifetime must not exceed 60 minutes.
  private val maxLifetimeSeconds = 60 * 60L

  private def reject[A](error: OidcError): IO[A] = IO.raiseError(RequestObjectRejected(error))

  private def require(cond: Boolean, error: => OidcError): IO[Unit] =
    if (cond) IO.unit else reject(error)

  private def requireSome[A](opt: Option[A], error: => OidcError): IO[A] =
    opt.fold(reject[A](error))(IO.pure)

  def resolve(
      requestJws: String,
      expectedClientId: String
  ): IO[Either[OidcError, RequestObjectClaims]] = {
    val validated = for {
      signedJwt <- Try(SignedJWT.parse(requestJws)).toOption match {
        case Some(jwt) => IO.pure(jwt)
        case None       => reject[SignedJWT](OidcError("invalid_request_object", Some("Malformed request object")))
      }
      claims = signedJwt.getJWTClaimsSet

      clientIdClaim = Option(claims.getStringClaim("client_id"))
      _ <- require(
        clientIdClaim.contains(expectedClientId),
        OidcError("invalid_request_object", Some("client_id claim does not match the request's client_id"))
      )

      issuer = Option(claims.getIssuer)
      _ <- require(
        issuer.contains(expectedClientId),
        OidcError("invalid_request_object", Some("iss claim must equal client_id"))
      )

      audience = Option(claims.getAudience).map(_.asScala.toList).getOrElse(Nil)
      _ <- require(
        audience.contains(config.issuer),
        OidcError("invalid_request_object", Some("aud claim must include this server's issuer"))
      )

      now = java.time.Instant.now()
      exp = Option(claims.getExpirationTime).map(_.toInstant)
      _ <- exp match {
        case None =>
          reject[Unit](OidcError("invalid_request_object", Some("exp claim is required")))
        case Some(e) if e.isBefore(now) =>
          reject[Unit](OidcError("invalid_request_object", Some("request object has expired")))
        case Some(e) if e.isAfter(now.plusSeconds(maxLifetimeSeconds)) =>
          reject[Unit](OidcError("invalid_request_object", Some("exp claim exceeds the maximum request object lifetime")))
        case Some(_) => IO.unit
      }
      nbf = Option(claims.getNotBeforeTime).map(_.toInstant)
      _ <- nbf match {
        case Some(n) if n.isAfter(now) =>
          reject[Unit](OidcError("invalid_request_object", Some("nbf claim is in the future")))
        case _ => IO.unit
      }

      client <- authService.findClientByClientIdThatIsKey(expectedClientId)
      jwksUri <- requireSome(
        client.flatMap(_.jwks_uri),
        OidcError("invalid_request_object", Some(s"Client $expectedClientId has no registered jwks_uri"))
      )

      jwksResult <- jwksClient.fetch(jwksUri)
      jwks <- jwksResult match {
        case Right(k)    => IO.pure(k)
        case Left(msg)   => reject[JWKSet](OidcError("invalid_request_object", Some(msg)))
      }

      verified = JwsClientVerifier.verify(signedJwt, jwks)
      _ <- require(verified, OidcError("invalid_request_object", Some("Signature verification failed")))

      responseType <- requireSome(
        Option(claims.getStringClaim("response_type")),
        OidcError("invalid_request_object", Some("response_type claim is required"))
      )
      redirectUri <- requireSome(
        Option(claims.getStringClaim("redirect_uri")),
        OidcError("invalid_request_object", Some("redirect_uri claim is required"))
      )
      scope <- requireSome(
        Option(claims.getStringClaim("scope")),
        OidcError("invalid_request_object", Some("scope claim is required"))
      )
    } yield RequestObjectClaims(
      responseType = responseType,
      clientId = expectedClientId,
      redirectUri = redirectUri,
      scope = scope,
      state = Option(claims.getStringClaim("state")),
      nonce = Option(claims.getStringClaim("nonce")),
      consentRequestId = Option(claims.getStringClaim("consent_request_id")),
      bankId = Option(claims.getStringClaim("bank_id")),
      consentId = Option(claims.getStringClaim("consent_id")),
      codeChallenge = Option(claims.getStringClaim("code_challenge")),
      codeChallengeMethod = Option(claims.getStringClaim("code_challenge_method"))
    )

    validated.attempt.map {
      case Right(value)                     => Right(value)
      case Left(RequestObjectRejected(err)) => Left(err)
      case Left(other) =>
        logger.warn(s"Unexpected error verifying request object: ${other.getMessage}")
        Left(OidcError("invalid_request_object", Some("Failed to verify request object")))
    }
  }

}

object RequestObjectService {
  def apply(
      authService: AuthService[IO],
      jwksClient: JwksClient[IO],
      config: OidcConfig
  ): RequestObjectService[IO] =
    new DefaultRequestObjectService(authService, jwksClient, config)
}
