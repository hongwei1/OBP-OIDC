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
import cats.effect.unsafe.implicits.global
import com.nimbusds.jose.{JWSAlgorithm, JWSHeader}
import com.nimbusds.jose.crypto.RSASSASigner
import com.nimbusds.jose.jwk.{JWKSet, RSAKey}
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator
import com.nimbusds.jwt.{JWTClaimsSet, SignedJWT}
import com.tesobe.oidc.models.OidcClient
import org.scalatest.funsuite.AnyFunSuite
import org.scalatest.matchers.should.Matchers

import java.util.{Date, UUID}

class ClientAssertionServiceTest extends AnyFunSuite with Matchers {

  private val testJwksUri = "https://client.example.com/.well-known/jwks.json"
  private val testClientId = "fapi-test-client"
  private val tokenEndpointUrl = "http://localhost:9000/obp-oidc/token"

  private val rsaJwk: RSAKey =
    new RSAKeyGenerator(2048).keyID("test-client-key-1").generate()

  private val testJwks = new JWKSet(rsaJwk)

  private def mockAuthService(jwksUri: Option[String]): AuthService[IO] =
    new MockAuthService() {
      override def findClientByClientIdThatIsKey(
          clientId: String
      ): IO[Option[OidcClient]] =
        IO.pure(
          Some(
            OidcClient(
              client_id = clientId,
              client_secret = Some("test-secret"),
              client_name = "FAPI Test Client",
              consumer_id = "test-consumer",
              redirect_uris = List("https://example.com/callback"),
              jwks_uri = jwksUri
            )
          )
        )
    }

  private def mockJwksClient(uri: String, jwks: JWKSet): JwksClient[IO] =
    new JwksClient[IO] {
      def fetch(jwksUri: String): IO[Either[String, JWKSet]] =
        if (jwksUri == uri) IO.pure(Right(jwks))
        else IO.pure(Left(s"no JWKS configured for $jwksUri in this test double"))
    }

  private def signedAssertion(
      claimsBuilder: JWTClaimsSet.Builder => JWTClaimsSet.Builder,
      key: RSAKey = rsaJwk
  ): String = {
    val now = new Date()
    val builder = new JWTClaimsSet.Builder()
      .issuer(testClientId)
      .subject(testClientId)
      .audience(tokenEndpointUrl)
      .jwtID(UUID.randomUUID().toString)
      .expirationTime(new Date(now.getTime + 60 * 1000)) // 1 minute

    val claims = claimsBuilder(builder).build()
    val header = new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(key.getKeyID).build()
    val jwt = new SignedJWT(header, claims)
    jwt.sign(new RSASSASigner(key.toPrivateKey))
    jwt.serialize()
  }

  private def newService(jwksUri: Option[String] = Some(testJwksUri)): IO[ClientAssertionService[IO]] =
    ClientAssertionService.create(mockAuthService(jwksUri), mockJwksClient(testJwksUri, testJwks))

  test("verify should accept a validly signed client_assertion") {
    val result = (for {
      service <- newService()
      r <- service.verify(signedAssertion(identity), tokenEndpointUrl)
    } yield r).unsafeRunSync()

    result shouldBe Right(testClientId)
  }

  test("verify should reject a replayed jti") {
    val result = (for {
      service <- newService()
      assertion = signedAssertion(identity)
      first <- service.verify(assertion, tokenEndpointUrl)
      second <- service.verify(assertion, tokenEndpointUrl)
    } yield (first, second)).unsafeRunSync()

    result._1 shouldBe Right(testClientId)
    result._2.isLeft shouldBe true
    result._2.left.getOrElse(throw new Exception("expected Left")).error_description.getOrElse("") should include(
      "already been used"
    )
  }

  test("verify should reject an expired assertion") {
    val result = (for {
      service <- newService()
      r <- service.verify(
        signedAssertion(_.expirationTime(new Date(System.currentTimeMillis() - 60000))),
        tokenEndpointUrl
      )
    } yield r).unsafeRunSync()

    result.isLeft shouldBe true
    result.left.getOrElse(throw new Exception("expected Left")).error_description shouldBe Some(
      "client_assertion has expired"
    )
  }

  test("verify should reject an assertion exceeding the max lifetime") {
    val result = (for {
      service <- newService()
      r <- service.verify(
        signedAssertion(_.expirationTime(new Date(System.currentTimeMillis() + 60 * 60 * 1000))), // 1 hour
        tokenEndpointUrl
      )
    } yield r).unsafeRunSync()

    result.isLeft shouldBe true
  }

  test("verify should reject a wrong audience") {
    val result = (for {
      service <- newService()
      r <- service.verify(signedAssertion(_.audience("https://not-the-token-endpoint.example.com")), tokenEndpointUrl)
    } yield r).unsafeRunSync()

    result.isLeft shouldBe true
  }

  test("verify should reject iss/sub mismatch") {
    val result = (for {
      service <- newService()
      r <- service.verify(signedAssertion(_.subject("a-different-client")), tokenEndpointUrl)
    } yield r).unsafeRunSync()

    result.isLeft shouldBe true
  }

  test("verify should reject a signature from an untrusted key") {
    val otherKey = new RSAKeyGenerator(2048).keyID("untrusted-key").generate()
    val result = (for {
      service <- newService()
      r <- service.verify(signedAssertion(identity, key = otherKey), tokenEndpointUrl)
    } yield r).unsafeRunSync()

    result.isLeft shouldBe true
  }

  test("verify should reject when the client has no registered jwks_uri") {
    val result = (for {
      service <- newService(jwksUri = None)
      r <- service.verify(signedAssertion(identity), tokenEndpointUrl)
    } yield r).unsafeRunSync()

    result.isLeft shouldBe true
    result.left.getOrElse(throw new Exception("expected Left")).error_description.getOrElse("") should include(
      "no registered jwks_uri"
    )
  }

  test("verify should reject a malformed assertion") {
    val result = (for {
      service <- newService()
      r <- service.verify("not-a-jwt", tokenEndpointUrl)
    } yield r).unsafeRunSync()

    result.isLeft shouldBe true
  }
}
