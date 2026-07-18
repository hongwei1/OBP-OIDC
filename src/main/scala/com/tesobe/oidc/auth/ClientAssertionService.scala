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
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jwt.SignedJWT
import com.tesobe.oidc.models.OidcError
import org.slf4j.LoggerFactory

import java.time.Instant
import scala.jdk.CollectionConverters._
import scala.util.Try

/** Verifies private_key_jwt client assertions (RFC 7523 / OAuth2 JWT client
  * authentication), a FAPI 1.0 Advanced client authentication method: instead
  * of a shared client_secret, the client signs a short-lived assertion JWT
  * with its own private key, verified here against its published JWKS. On
  * success returns the asserted client_id — the caller treats this exactly
  * like a successful authService.authenticateClient.
  */
trait ClientAssertionService[F[_]] {
  def verify(clientAssertion: String, expectedAudience: String): F[Either[OidcError, String]]
}

private case class ClientAssertionRejected(oidcError: OidcError) extends RuntimeException(oidcError.error)

class DefaultClientAssertionService(
    authService: AuthService[IO],
    jwksClient: JwksClient[IO],
    usedJtiRef: Ref[IO, Map[String, Instant]]
) extends ClientAssertionService[IO] {

  private val logger = LoggerFactory.getLogger(getClass)

  // RFC 7523 recommends a short assertion lifetime; this server enforces a hard cap.
  private val maxLifetimeSeconds = 5 * 60L

  private def reject[A](error: OidcError): IO[A] = IO.raiseError(ClientAssertionRejected(error))

  private def require(cond: Boolean, error: => OidcError): IO[Unit] =
    if (cond) IO.unit else reject(error)

  private def requireSome[A](opt: Option[A], error: => OidcError): IO[A] =
    opt.fold(reject[A](error))(IO.pure)

  def verify(clientAssertion: String, expectedAudience: String): IO[Either[OidcError, String]] = {
    val validated = for {
      signedJwt <- Try(SignedJWT.parse(clientAssertion)).toOption match {
        case Some(jwt) => IO.pure(jwt)
        case None       => reject[SignedJWT](OidcError("invalid_client", Some("Malformed client_assertion")))
      }
      claims = signedJwt.getJWTClaimsSet

      issuer = Option(claims.getIssuer)
      subject = Option(claims.getSubject)
      _ <- require(
        issuer.isDefined && issuer == subject,
        OidcError("invalid_client", Some("iss and sub claims must both be present and equal to client_id"))
      )
      clientId <- requireSome(issuer, OidcError("invalid_client", Some("iss claim is required")))

      audience = Option(claims.getAudience).map(_.asScala.toList).getOrElse(Nil)
      _ <- require(
        audience.contains(expectedAudience),
        OidcError("invalid_client", Some("aud claim must equal the token endpoint"))
      )

      now = Instant.now()
      expOpt = Option(claims.getExpirationTime).map(_.toInstant)
      expInstant <- requireSome(expOpt, OidcError("invalid_client", Some("exp claim is required")))
      _ <- require(!expInstant.isBefore(now), OidcError("invalid_client", Some("client_assertion has expired")))
      _ <- require(
        !expInstant.isAfter(now.plusSeconds(maxLifetimeSeconds)),
        OidcError("invalid_client", Some("exp claim exceeds the maximum client_assertion lifetime"))
      )

      jti <- requireSome(Option(claims.getJWTID), OidcError("invalid_client", Some("jti claim is required")))
      alreadyUsed <- usedJtiRef.get.map(_.contains(jti))
      _ <- require(!alreadyUsed, OidcError("invalid_client", Some("client_assertion has already been used")))

      client <- authService.findClientByClientIdThatIsKey(clientId)
      jwksUri <- requireSome(
        client.flatMap(_.jwks_uri),
        OidcError("invalid_client", Some(s"Client $clientId has no registered jwks_uri"))
      )
      jwksResult <- jwksClient.fetch(jwksUri)
      jwks <- jwksResult match {
        case Right(k)  => IO.pure(k)
        case Left(msg) => reject[JWKSet](OidcError("invalid_client", Some(msg)))
      }

      verified = JwsClientVerifier.verify(signedJwt, jwks)
      _ <- require(verified, OidcError("invalid_client", Some("client_assertion signature verification failed")))

      // Record the jti as used only once the assertion is fully verified, so a
      // failed/forged attempt never burns a legitimate future replay slot.
      _ <- usedJtiRef.update(_ + (jti -> expInstant))
      _ <- usedJtiRef.update(_.filter { case (_, exp) => exp.isAfter(now) })
    } yield clientId

    validated.attempt.map {
      case Right(clientId)                    => Right(clientId)
      case Left(ClientAssertionRejected(err)) => Left(err)
      case Left(other) =>
        logger.warn(s"Unexpected error verifying client_assertion: ${other.getMessage}")
        Left(OidcError("invalid_client", Some("Failed to verify client_assertion")))
    }
  }
}

object ClientAssertionService {
  val JwtBearerAssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

  def create(authService: AuthService[IO], jwksClient: JwksClient[IO]): IO[ClientAssertionService[IO]] =
    Ref.of[IO, Map[String, Instant]](Map.empty).map(new DefaultClientAssertionService(authService, jwksClient, _))
}
