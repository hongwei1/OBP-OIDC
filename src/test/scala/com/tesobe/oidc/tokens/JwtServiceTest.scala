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

import cats.effect.unsafe.implicits.global
import com.auth0.jwt.JWT
import com.tesobe.oidc.config.{DatabaseConfig, OidcConfig, ServerConfig}
import com.tesobe.oidc.models.User
import org.scalatest.funsuite.AnyFunSuite
import org.scalatest.matchers.should.Matchers

/** Gap 8: issued tokens must carry the standard openbanking_intent_id claim
  * alongside OBP-OIDC's proprietary consent_id claim (same value), so UK
  * Open Banking resource servers that only look for the standard claim name
  * still find the consent binding.
  */
class JwtServiceTest extends AnyFunSuite with Matchers {

  val testConfig = OidcConfig(
    issuer = "http://localhost:9000/obp-oidc",
    server = ServerConfig("localhost", 9000),
    database = DatabaseConfig("localhost", 5432, "test", "test", "test"),
    adminDatabase =
      DatabaseConfig("localhost", 5432, "test", "test_admin", "test_admin"),
    keyId = "test-key-1"
  )

  val testUser = User(
    sub = "alice123",
    username = "alice123",
    password = "secret123456",
    name = Some("Alice Smith"),
    email = Some("alice@example.com"),
    email_verified = Some(true),
    provider = Some("obp-test")
  )

  test("generateIdToken should mirror consent_id into openbanking_intent_id") {
    val test = for {
      jwtService <- JwtService(testConfig)
      token <- jwtService.generateIdToken(testUser, "test-client", consentId = Some("consent-abc-123"))
    } yield {
      val decoded = JWT.decode(token)
      decoded.getClaim("consent_id").asString shouldBe "consent-abc-123"
      decoded.getClaim("openbanking_intent_id").asString shouldBe "consent-abc-123"
    }

    test.unsafeRunSync()
  }

  test("generateIdToken should omit both claims when no consent_id is given") {
    val test = for {
      jwtService <- JwtService(testConfig)
      token <- jwtService.generateIdToken(testUser, "test-client")
    } yield {
      val decoded = JWT.decode(token)
      decoded.getClaim("consent_id").asString shouldBe null
      decoded.getClaim("openbanking_intent_id").asString shouldBe null
    }

    test.unsafeRunSync()
  }

  test("generateAccessToken should mirror consent_id into openbanking_intent_id") {
    val test = for {
      jwtService <- JwtService(testConfig)
      token <- jwtService.generateAccessToken(
        testUser,
        "test-client",
        "openid profile",
        consentId = Some("consent-xyz-789")
      )
    } yield {
      val decoded = JWT.decode(token)
      decoded.getClaim("consent_id").asString shouldBe "consent-xyz-789"
      decoded.getClaim("openbanking_intent_id").asString shouldBe "consent-xyz-789"
    }

    test.unsafeRunSync()
  }

  test("generateRefreshToken should mirror consent_id into openbanking_intent_id") {
    val test = for {
      jwtService <- JwtService(testConfig)
      token <- jwtService.generateRefreshToken(
        testUser,
        "test-client",
        "openid profile",
        consentId = Some("consent-refresh-456")
      )
    } yield {
      val decoded = JWT.decode(token)
      decoded.getClaim("consent_id").asString shouldBe "consent-refresh-456"
      decoded.getClaim("openbanking_intent_id").asString shouldBe "consent-refresh-456"
    }

    test.unsafeRunSync()
  }

  // FAPI 1.0 Advanced's strict profile requires PS256 instead of plain RS256.
  test("default config signs with RS256") {
    val test = for {
      jwtService <- JwtService(testConfig)
      token <- jwtService.generateIdToken(testUser, "test-client")
    } yield {
      JWT.decode(token).getAlgorithm shouldBe "RS256"
    }

    test.unsafeRunSync()
  }

  test("PS256 config signs with PS256 and the token verifies") {
    val ps256Config = testConfig.copy(signingAlgorithm = "PS256")
    val test = for {
      jwtService <- JwtService(ps256Config)
      idToken <- jwtService.generateIdToken(testUser, "test-client")
      accessToken <- jwtService.generateAccessToken(testUser, "test-client", "openid profile")
      verified <- jwtService.validateAccessToken(accessToken)
    } yield {
      JWT.decode(idToken).getAlgorithm shouldBe "PS256"
      JWT.decode(accessToken).getAlgorithm shouldBe "PS256"
      verified.isRight shouldBe true
    }

    test.unsafeRunSync()
  }

  test("PS256 config is reflected in the published JWKS") {
    val ps256Config = testConfig.copy(signingAlgorithm = "PS256")
    val test = for {
      jwtService <- JwtService(ps256Config)
      jwk <- jwtService.getJsonWebKey
    } yield {
      jwk.alg shouldBe "PS256"
    }

    test.unsafeRunSync()
  }

  test("a PS256 token rejects tampering (signature no longer verifies)") {
    val ps256Config = testConfig.copy(signingAlgorithm = "PS256")
    val test = for {
      jwtService <- JwtService(ps256Config)
      token <- jwtService.generateAccessToken(testUser, "test-client", "openid profile")
      tampered = token.dropRight(4) + "AAAA" // corrupt the signature segment
      verified <- jwtService.validateAccessToken(tampered)
    } yield {
      verified.isLeft shouldBe true
    }

    test.unsafeRunSync()
  }
}
