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

package com.tesobe.oidc.tokens

import scala.language.higherKinds
import cats.effect.{IO, Ref}
import cats.syntax.either._
import com.auth0.jwt.JWT
import com.auth0.jwt.algorithms.Algorithm
import com.auth0.jwt.exceptions.JWTVerificationException
import com.auth0.jwt.interfaces.DecodedJWT
import com.tesobe.oidc.models.{
  AccessTokenClaims,
  IdTokenClaims,
  JsonWebKey,
  OidcError,
  RefreshTokenClaims,
  User
}
import com.tesobe.oidc.config.OidcConfig

import java.security.interfaces.{RSAPrivateKey, RSAPublicKey}
import java.security.{KeyPair, KeyPairGenerator, MessageDigest, SecureRandom}
import java.time.Instant
import java.util.{Base64, Date}
import scala.util.{Failure, Success, Try}
import org.slf4j.LoggerFactory

trait JwtService[F[_]] {
  def generateIdToken(
      user: User,
      clientId: String,
      nonce: Option[String] = None,
      consentId: Option[String] = None
  ): F[String]
  def generateHybridIdToken(
      user: User,
      clientId: String,
      code: String,
      state: Option[String] = None,
      nonce: Option[String] = None,
      consentId: Option[String] = None
  ): F[String]
  def generateAccessToken(
      user: User,
      clientId: String,
      scope: String
  ): F[String]
  def generateRefreshToken(
      user: User,
      clientId: String,
      scope: String
  ): F[String]
  def generateClientCredentialsToken(
      clientId: String,
      scope: String
  ): F[String]
  def validateAccessToken(
      token: String
  ): F[Either[OidcError, AccessTokenClaims]]
  def validateRefreshToken(
      token: String
  ): F[Either[OidcError, RefreshTokenClaims]]
  def getJsonWebKey: F[JsonWebKey]
}

class JwtServiceImpl(config: OidcConfig, keyPairRef: Ref[IO, KeyPair])
    extends JwtService[IO] {

  private val logger = LoggerFactory.getLogger(getClass)
  private val secureRandom = new SecureRandom()

  private def getAlgorithm: IO[Algorithm] =
    keyPairRef.get.map { keyPair =>
      Algorithm.RSA256(
        keyPair.getPublic.asInstanceOf[RSAPublicKey],
        keyPair.getPrivate.asInstanceOf[RSAPrivateKey]
      )
    }

  def generateIdToken(
      user: User,
      clientId: String,
      nonce: Option[String] = None,
      consentId: Option[String] = None
  ): IO[String] = {
    for {
      algorithm <- getAlgorithm
      now = Instant.now()
      exp = now.plusSeconds(config.tokenExpirationSeconds)

      // Even though the user might been generated in  OBP database,
      // the issuer of this token is this application.
      issuer = config.issuer

      _ = logger.trace(
        s"Generating ID token for user: ${user.sub}, client: $clientId"
      )
      _ = logger.trace(
        s"Setting azp (Authorized Party) claim to: $clientId"
      )
      _ = logger.info(
        s"Generating ID token for user: ${user.sub}, client: $clientId"
      )
      _ = logger.info(s"Setting azp (Authorized Party) claim to: $clientId")

      // Create Identity token (to identify the user at the resource server)
      token = JWT
        .create()
        .withIssuer(issuer)
        .withSubject(user.sub)
        .withAudience(user.provider.filter(_.trim.nonEmpty).getOrElse(config.issuer))
        .withIssuedAt(Date.from(now))
        .withExpiresAt(Date.from(exp))
        .withKeyId(config.keyId)
        .withClaim("azp", clientId)
        .withClaim("name", user.name.orNull)
        .withClaim("email", user.email.getOrElse(s"${user.sub}@noemail.local"))
        .withClaim(
          "provider",
          user.provider.filter(_.trim.nonEmpty).getOrElse(config.issuer)
        )

      _ = logger.trace(s"Added azp claim with value: $clientId")
      tokenWithNonce = nonce.fold(token)(n => token.withClaim("nonce", n))
      tokenWithConsent = consentId.fold(tokenWithNonce)(cid => tokenWithNonce.withClaim("consent_id", cid))
      signedToken = tokenWithConsent.sign(algorithm)

      _ = logger.trace(
        s"ID token generated successfully with azp: $clientId"
      )
      _ = logger.trace(s"ID Token JWT: $signedToken")
      _ = logger.info(s"ID token generated successfully with azp: $clientId")
    } yield signedToken
  }

  /** Compute the left-half hash for OIDC hybrid flow claims (c_hash, at_hash, s_hash).
    * Per OIDC Core 3.3.2.11: SHA-256 the input, take the left half, base64url-encode.
    */
  private def computeHalfHash(value: String): String = {
    val digest = MessageDigest.getInstance("SHA-256").digest(value.getBytes("ASCII"))
    val leftHalf = digest.take(digest.length / 2)
    Base64.getUrlEncoder.withoutPadding().encodeToString(leftHalf)
  }

  /** Generate an ID token for the hybrid flow (response_type=code id_token).
    * Includes c_hash (code hash) and optionally s_hash (state hash).
    * at_hash is not included because no access token is returned from the authorization endpoint.
    */
  def generateHybridIdToken(
      user: User,
      clientId: String,
      code: String,
      state: Option[String] = None,
      nonce: Option[String] = None,
      consentId: Option[String] = None
  ): IO[String] = {
    for {
      algorithm <- getAlgorithm
      now = Instant.now()
      exp = now.plusSeconds(config.tokenExpirationSeconds)
      issuer = config.issuer

      _ = logger.info(s"Generating hybrid ID token for user: ${user.sub}, client: $clientId")

      cHash = computeHalfHash(code)
      _ = logger.info(s"Computed c_hash for hybrid ID token: $cHash")

      token = JWT
        .create()
        .withIssuer(issuer)
        .withSubject(user.sub)
        .withAudience(user.provider.filter(_.trim.nonEmpty).getOrElse(config.issuer))
        .withIssuedAt(Date.from(now))
        .withExpiresAt(Date.from(exp))
        .withKeyId(config.keyId)
        .withClaim("azp", clientId)
        .withClaim("name", user.name.orNull)
        .withClaim("email", user.email.getOrElse(s"${user.sub}@noemail.local"))
        .withClaim("provider", user.provider.filter(_.trim.nonEmpty).getOrElse(config.issuer))
        .withClaim("c_hash", cHash)

      tokenWithState = state.fold(token)(s => token.withClaim("s_hash", computeHalfHash(s)))
      tokenWithNonce = nonce.fold(tokenWithState)(n => tokenWithState.withClaim("nonce", n))
      tokenWithConsent = consentId.fold(tokenWithNonce)(cid => tokenWithNonce.withClaim("consent_id", cid))
      signedToken = tokenWithConsent.sign(algorithm)

      _ = logger.info(s"Hybrid ID token generated successfully with azp: $clientId, c_hash: $cHash")
    } yield signedToken
  }

  def generateAccessToken(
      user: User,
      clientId: String,
      scope: String
  ): IO[String] = {
    for {
      algorithm <- getAlgorithm
      now = Instant.now()
      exp = now.plusSeconds(config.tokenExpirationSeconds)

      issuer = config.issuer

      // my_audience = user.provider

      _ = logger.trace(
        s"issuer is : $issuer"
      )

      _ = logger.trace(
        s"Generating Access token for user: ${user.sub}, client: $clientId"
      )
      _ = logger.trace(
        s"Setting azp (Authorized Party) claim to: $clientId"
      )
      _ = logger.info(
        s"Generating Access token for user: ${user.sub}, client: $clientId"
      )
      _ = logger.info(s"Setting azp (Authorized Party) claim to: $clientId")

      // Create Access token (to access a resource)
      token = JWT
        .create()
        .withIssuer(issuer)
        .withSubject(user.sub)
        .withAudience(user.provider.filter(_.trim.nonEmpty).getOrElse(config.issuer))
        .withIssuedAt(Date.from(now))
        .withExpiresAt(Date.from(exp))
        .withKeyId(config.keyId)
        .withClaim("azp", clientId)
        .withClaim("scope", scope)
        .withClaim("client_id", clientId)
        .withClaim(
          "provider",
          user.provider.filter(_.trim.nonEmpty).getOrElse(config.issuer)
        )

      _ = logger.trace(
        s"Added azp claim to access token with value: $clientId"
      )
      signedToken = token.sign(algorithm)

      _ = logger.trace(
        s"Access token generated successfully with azp: $clientId"
      )
      _ = logger.trace(s"Access Token JWT: $signedToken")
      _ = logger.info(
        s"Access token generated successfully with azp: $clientId"
      )
    } yield signedToken
  }

  def generateClientCredentialsToken(
      clientId: String,
      scope: String
  ): IO[String] = {
    for {
      algorithm <- getAlgorithm
      now = Instant.now()
      exp = now.plusSeconds(config.tokenExpirationSeconds)

      issuer = config.issuer

      _ = logger.info(
        s"Generating client credentials token for client: $clientId"
      )

      // Create Access token for client credentials (no user context)
      token = JWT
        .create()
        .withIssuer(issuer)
        .withSubject(
          clientId
        ) // client_id is the subject for client credentials
        .withAudience(issuer) // audience is the issuer for client credentials
        .withIssuedAt(Date.from(now))
        .withExpiresAt(Date.from(exp))
        .withKeyId(config.keyId)
        .withClaim("azp", clientId)
        .withClaim("scope", scope)
        .withClaim("client_id", clientId)
        .withClaim("grant_type", "client_credentials")

      signedToken = token.sign(algorithm)

      _ = logger.info(
        s"Client credentials token generated successfully for client: $clientId"
      )
    } yield signedToken
  }

  def generateRefreshToken(
      user: User,
      clientId: String,
      scope: String
  ): IO[String] = {
    for {
      algorithm <- getAlgorithm
      now = Instant.now()
      // Refresh tokens typically have longer expiration (30 days)
      exp = now.plusSeconds(
        config.tokenExpirationSeconds * 720
      ) // 30 days if access token is 1 hour

      // Generate unique JWT ID for refresh token
      jti = generateJwtId()

      issuer = config.issuer

      _ = logger.info(
        s"Generating refresh token for user: ${user.sub}, client: $clientId"
      )

      // Create Refresh token
      token = JWT
        .create()
        .withIssuer(issuer)
        .withSubject(user.sub)
        .withAudience(clientId)
        .withIssuedAt(Date.from(now))
        .withExpiresAt(Date.from(exp))
        .withKeyId(config.keyId)
        .withJWTId(jti)
        .withClaim("azp", clientId)
        .withClaim("scope", scope)
        .withClaim("client_id", clientId)

      signedToken = token.sign(algorithm)

      _ = logger.info(
        s"Refresh token generated successfully for user: ${user.sub}, client: $clientId"
      )
    } yield signedToken
  }

  private def generateJwtId(): String = {
    val bytes = new Array[Byte](32)
    secureRandom.nextBytes(bytes)
    Base64.getUrlEncoder.withoutPadding().encodeToString(bytes)
  }

  def validateAccessToken(
      token: String
  ): IO[Either[OidcError, AccessTokenClaims]] = {
    getAlgorithm.flatMap { algorithm =>
      IO {
        Try {
          // First decode token without verification to check issuer
          val unverifiedJWT = JWT.decode(token)
          val tokenIssuer = unverifiedJWT.getIssuer

          // Create verifier that accepts either config issuer or provider-based issuer
          val verifier = JWT
            .require(algorithm)
            .acceptIssuedAt(config.tokenExpirationSeconds)
            .build()

          val decodedJWT: DecodedJWT = verifier.verify(token)

          // Validate that issuer is either our config issuer or a reasonable provider value
          val issuer = decodedJWT.getIssuer
          if (issuer == null || issuer.trim.isEmpty) {
            throw new JWTVerificationException("Missing or empty issuer")
          }

          val azpClaim = Option(decodedJWT.getClaim("azp")).map(_.asString())
          logger.info(
            s"Validating access token with azp: ${azpClaim.getOrElse("NONE")}"
          )

          AccessTokenClaims(
            iss = decodedJWT.getIssuer,
            sub = decodedJWT.getSubject,
            aud = decodedJWT.getAudience.get(0), // Take first audience
            exp = decodedJWT.getExpiresAt.toInstant.getEpochSecond,
            iat = decodedJWT.getIssuedAt.toInstant.getEpochSecond,
            scope = decodedJWT.getClaim("scope").asString(),
            client_id = decodedJWT.getClaim("client_id").asString(),
            azp = azpClaim
          )
        } match {
          case Success(claims) => claims.asRight[OidcError]
          case Failure(_: JWTVerificationException) =>
            OidcError("invalid_token", Some("Token validation failed"))
              .asLeft[AccessTokenClaims]
          case Failure(ex) =>
            OidcError(
              "server_error",
              Some(s"Token validation error: ${ex.getMessage}")
            ).asLeft[AccessTokenClaims]
        }
      }
    }
  }

  def validateRefreshToken(
      token: String
  ): IO[Either[OidcError, RefreshTokenClaims]] = {
    getAlgorithm.flatMap { algorithm =>
      IO {
        Try {
          val verifier = JWT
            .require(algorithm)
            .acceptIssuedAt(
              config.tokenExpirationSeconds * 720
            ) // Allow longer expiration for refresh tokens
            .build()

          val decodedJWT: DecodedJWT = verifier.verify(token)

          // Validate that issuer matches our config
          val issuer = decodedJWT.getIssuer
          if (
            issuer == null || issuer.trim.isEmpty || issuer != config.issuer
          ) {
            throw new JWTVerificationException(
              "Invalid issuer for refresh token"
            )
          }

          logger.info(
            s"Validating refresh token for user: ${decodedJWT.getSubject}, client: ${decodedJWT.getClaim("client_id").asString()}"
          )

          RefreshTokenClaims(
            iss = decodedJWT.getIssuer,
            sub = decodedJWT.getSubject,
            aud = decodedJWT.getAudience.get(
              0
            ), // Take first audience (should be client_id)
            exp = decodedJWT.getExpiresAt.toInstant.getEpochSecond,
            iat = decodedJWT.getIssuedAt.toInstant.getEpochSecond,
            jti = decodedJWT.getId,
            scope = decodedJWT.getClaim("scope").asString(),
            client_id = decodedJWT.getClaim("client_id").asString()
          )
        } match {
          case Success(claims) => claims.asRight[OidcError]
          case Failure(_: JWTVerificationException) =>
            OidcError("invalid_grant", Some("Invalid refresh token"))
              .asLeft[RefreshTokenClaims]
          case Failure(ex) =>
            OidcError(
              "server_error",
              Some(s"Refresh token validation error: ${ex.getMessage}")
            ).asLeft[RefreshTokenClaims]
        }
      }
    }
  }

  def getJsonWebKey: IO[JsonWebKey] = {
    keyPairRef.get.map { keyPair =>
      val publicKey = keyPair.getPublic.asInstanceOf[RSAPublicKey]

      // Get RSA modulus and exponent as Base64URL encoded strings
      val modulus = Base64.getUrlEncoder
        .withoutPadding()
        .encodeToString(publicKey.getModulus.toByteArray)
      val exponent = Base64.getUrlEncoder
        .withoutPadding()
        .encodeToString(publicKey.getPublicExponent.toByteArray)

      JsonWebKey(
        kty = "RSA",
        use = "sig",
        kid = config.keyId,
        alg = "RS256",
        n = modulus,
        e = exponent
      )
    }
  }
}

object JwtService {

  def apply(config: OidcConfig): IO[JwtService[IO]] = {
    for {
      keyPair <- generateKeyPair
      keyPairRef <- Ref.of[IO, KeyPair](keyPair)
    } yield new JwtServiceImpl(config, keyPairRef)
  }

  private def generateKeyPair: IO[KeyPair] = IO {
    val keyPairGenerator = KeyPairGenerator.getInstance("RSA")
    keyPairGenerator.initialize(2048)
    keyPairGenerator.generateKeyPair()
  }
}
