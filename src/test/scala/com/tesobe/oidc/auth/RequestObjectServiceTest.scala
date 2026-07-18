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
import com.tesobe.oidc.config.{DatabaseConfig, OidcConfig, ServerConfig}
import com.tesobe.oidc.models.OidcClient
import org.scalatest.funsuite.AnyFunSuite
import org.scalatest.matchers.should.Matchers

import java.util.Date

class RequestObjectServiceTest extends AnyFunSuite with Matchers {

  val testConfig = OidcConfig(
    issuer = "http://localhost:9000/obp-oidc",
    server = ServerConfig("localhost", 9000),
    database = DatabaseConfig("localhost", 5432, "test", "test", "test"),
    adminDatabase =
      DatabaseConfig("localhost", 5432, "test", "test_admin", "test_admin")
  )

  private val testJwksUri = "https://client.example.com/.well-known/jwks.json"
  private val testClientId = "fapi-test-client"

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

  private def signedRequestObject(
      claimsBuilder: JWTClaimsSet.Builder => JWTClaimsSet.Builder,
      key: RSAKey = rsaJwk
  ): String = {
    val now = new Date()
    val builder = new JWTClaimsSet.Builder()
      .issuer(testClientId)
      .audience(testConfig.issuer)
      .claim("client_id", testClientId)
      .claim("response_type", "code")
      .claim("redirect_uri", "https://example.com/callback")
      .claim("scope", "openid profile")
      .notBeforeTime(now)
      .expirationTime(new Date(now.getTime + 5 * 60 * 1000)) // 5 minutes

    val claims = claimsBuilder(builder).build()
    val header = new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(key.getKeyID).build()
    val jwt = new SignedJWT(header, claims)
    jwt.sign(new RSASSASigner(key.toPrivateKey))
    jwt.serialize()
  }

  test("resolve should accept a validly signed request object") {
    val service = RequestObjectService(
      mockAuthService(Some(testJwksUri)),
      mockJwksClient(testJwksUri, testJwks),
      testConfig
    )
    val jws = signedRequestObject(identity)

    val result = service.resolve(jws, testClientId).unsafeRunSync()

    result.isRight shouldBe true
    val claims = result.getOrElse(throw new Exception("expected Right"))
    claims.responseType shouldBe "code"
    claims.clientId shouldBe testClientId
    claims.redirectUri shouldBe "https://example.com/callback"
    claims.scope shouldBe "openid profile"
  }

  test("resolve should carry through optional UK consent claims") {
    val service = RequestObjectService(
      mockAuthService(Some(testJwksUri)),
      mockJwksClient(testJwksUri, testJwks),
      testConfig
    )
    val jws = signedRequestObject(_.claim("consent_id", "consent-abc").claim("state", "xyz"))

    val result = service.resolve(jws, testClientId).unsafeRunSync()

    result.isRight shouldBe true
    val claims = result.getOrElse(throw new Exception("expected Right"))
    claims.consentId shouldBe Some("consent-abc")
    claims.state shouldBe Some("xyz")
  }

  test("resolve should reject a request object signed with an untrusted key") {
    val otherKey = new RSAKeyGenerator(2048).keyID("untrusted-key").generate()
    val service = RequestObjectService(
      mockAuthService(Some(testJwksUri)),
      mockJwksClient(testJwksUri, testJwks), // only trusts rsaJwk
      testConfig
    )
    val jws = signedRequestObject(identity, key = otherKey)

    val result = service.resolve(jws, testClientId).unsafeRunSync()

    result.isLeft shouldBe true
    result.left.getOrElse(throw new Exception("expected Left")).error shouldBe "invalid_request_object"
  }

  test("resolve should reject an expired request object") {
    val service = RequestObjectService(
      mockAuthService(Some(testJwksUri)),
      mockJwksClient(testJwksUri, testJwks),
      testConfig
    )
    val jws = signedRequestObject(_.expirationTime(new Date(System.currentTimeMillis() - 60000)))

    val result = service.resolve(jws, testClientId).unsafeRunSync()

    result.isLeft shouldBe true
    result.left.getOrElse(throw new Exception("expected Left")).error_description shouldBe Some(
      "request object has expired"
    )
  }

  test("resolve should reject a request object exceeding the max lifetime") {
    val service = RequestObjectService(
      mockAuthService(Some(testJwksUri)),
      mockJwksClient(testJwksUri, testJwks),
      testConfig
    )
    val jws = signedRequestObject(
      _.expirationTime(new Date(System.currentTimeMillis() + 2 * 60 * 60 * 1000)) // 2 hours
    )

    val result = service.resolve(jws, testClientId).unsafeRunSync()

    result.isLeft shouldBe true
  }

  test("resolve should reject a wrong audience") {
    val service = RequestObjectService(
      mockAuthService(Some(testJwksUri)),
      mockJwksClient(testJwksUri, testJwks),
      testConfig
    )
    val jws = signedRequestObject(_.audience("https://not-this-server.example.com"))

    val result = service.resolve(jws, testClientId).unsafeRunSync()

    result.isLeft shouldBe true
  }

  test("resolve should reject a client_id mismatch between claim and query param") {
    val service = RequestObjectService(
      mockAuthService(Some(testJwksUri)),
      mockJwksClient(testJwksUri, testJwks),
      testConfig
    )
    val jws = signedRequestObject(identity)

    val result = service.resolve(jws, "a-different-client-id").unsafeRunSync()

    result.isLeft shouldBe true
  }

  test("resolve should reject when the client has no registered jwks_uri") {
    val service = RequestObjectService(
      mockAuthService(None),
      mockJwksClient(testJwksUri, testJwks),
      testConfig
    )
    val jws = signedRequestObject(identity)

    val result = service.resolve(jws, testClientId).unsafeRunSync()

    result.isLeft shouldBe true
    result.left.getOrElse(throw new Exception("expected Left")).error_description.getOrElse("") should include(
      "no registered jwks_uri"
    )
  }

  test("resolve should reject a malformed request object") {
    val service = RequestObjectService(
      mockAuthService(Some(testJwksUri)),
      mockJwksClient(testJwksUri, testJwks),
      testConfig
    )

    val result = service.resolve("not-a-jwt", testClientId).unsafeRunSync()

    result.isLeft shouldBe true
  }
}
