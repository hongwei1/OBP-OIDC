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

package com.tesobe.oidc

import cats.effect.{IO, Ref}
import com.tesobe.oidc.auth.{CodeService, ParService, JwksClient, RequestObjectService, ClientAssertionService, MtlsService, MockAuthService}
import com.tesobe.oidc.config.{DatabaseConfig, OidcConfig, ServerConfig}
import com.tesobe.oidc.endpoints._
import com.tesobe.oidc.models._
import com.tesobe.oidc.tokens.JwtService
import com.tesobe.oidc.stats.StatsService
import com.tesobe.oidc.ratelimit.{RateLimitConfig, InMemoryRateLimitService}
import io.circe.parser._
import org.http4s._

import org.http4s.implicits._
import org.http4s.server.Router
import org.scalatest.flatspec.AnyFlatSpec
import org.scalatest.matchers.should.Matchers
import cats.effect.unsafe.implicits.global
import org.typelevel.ci.CIString

class OidcProviderIntegrationTest extends AnyFlatSpec with Matchers {

  val testConfig = OidcConfig(
    issuer = "http://localhost:9000/obp-oidc",
    server = ServerConfig("localhost", 9000),
    database = DatabaseConfig("localhost", 5432, "test", "test", "test"),
    adminDatabase =
      DatabaseConfig("localhost", 5432, "test", "test_admin", "test_admin"),
    keyId = "test-key-1",
    tokenExpirationSeconds = 3600,
    codeExpirationSeconds = 600
  )

  def createTestApp: IO[HttpApp[IO]] = {
    for {
      authService <- IO(MockAuthService())
      codeService <- CodeService(testConfig)
      parService <- ParService(testConfig)
      jwksClient <- JwksClient.create().allocated.map(_._1)
      requestObjectService = RequestObjectService(authService, jwksClient, testConfig)
      clientAssertionService <- ClientAssertionService.create(authService, jwksClient)
      mtlsService = MtlsService(testConfig)
      jwtService <- JwtService(testConfig)
      statsService <- StatsService()
      rateLimitConfig = RateLimitConfig()
      rateLimitService <- InMemoryRateLimitService(rateLimitConfig)

      consentChallengesRef <- Ref.of[IO, Map[String, ConsentChallenge]](Map.empty)
      discoveryEndpoint = DiscoveryEndpoint(testConfig)
      jwksEndpoint = JwksEndpoint(jwtService)
      authEndpoint = AuthEndpoint(
        authService,
        codeService,
        statsService,
        rateLimitService,
        testConfig,
        jwtService,
        consentChallengesRef,
        parService,
        requestObjectService
      )
      tokenEndpoint = TokenEndpoint(
        authService,
        codeService,
        jwtService,
        testConfig,
        statsService,
        clientAssertionService,
        mtlsService
      )
      userInfoEndpoint = UserInfoEndpoint(authService, jwtService)
      parEndpoint = ParEndpoint(authService, parService, testConfig)

      routes = Router(
        "/" -> discoveryEndpoint.routes,
        "/" -> jwksEndpoint.routes,
        "/" -> authEndpoint.routes,
        "/" -> tokenEndpoint.routes,
        "/" -> userInfoEndpoint.routes,
        "/" -> parEndpoint.routes
      ).orNotFound
    } yield routes
  }

  "OIDC Discovery Endpoint" should "return valid discovery document" in {
    val test = for {
      app <- createTestApp
      request = Request[IO](
        Method.GET,
        uri"/obp-oidc/.well-known/openid-configuration"
      )
      response <- app(request)
      body <- response.as[String]
    } yield {
      response.status should be(Status.Ok)
      response.contentType.map(_.mediaType) should be(
        Some(MediaType.application.json)
      )

      val config = decode[OidcConfiguration](body)
      config.isRight should be(true)
      val configObj =
        config.getOrElse(throw new Exception("Failed to decode config"))
      configObj.issuer should be(testConfig.issuer)
      configObj.authorization_endpoint should be(s"${testConfig.issuer}/auth")
      configObj.token_endpoint should be(s"${testConfig.issuer}/token")
      configObj.userinfo_endpoint should be(s"${testConfig.issuer}/userinfo")
      configObj.jwks_uri should be(s"${testConfig.issuer}/jwks")
    }

    test.unsafeRunSync()
  }

  "OIDC Discovery Endpoint" should "support HEAD requests" in {
    val test = for {
      app <- createTestApp
      request = Request[IO](
        Method.HEAD,
        uri"/obp-oidc/.well-known/openid-configuration"
      )
      response <- app(request)
      body <- response.as[String]
    } yield {
      response.status should be(Status.Ok)
      response.contentType.map(_.mediaType) should be(
        Some(MediaType.application.json)
      )
      // HEAD request should have Content-Length header but empty body
      response.headers.get[headers.`Content-Length`] should not be None
      body should be(empty)
    }

    test.unsafeRunSync()
  }

  "JWKS Endpoint" should "return valid JSON Web Key Set" in {
    val test = for {
      app <- createTestApp
      request = Request[IO](Method.GET, uri"/obp-oidc/jwks")
      response <- app(request)
      body <- response.as[String]
    } yield {
      response.status should be(Status.Ok)
      response.contentType.map(_.mediaType) should be(
        Some(MediaType.application.json)
      )

      val jwks = decode[JsonWebKeySet](body)
      jwks.isRight should be(true)
      val jwksObj = jwks.getOrElse(throw new Exception("Failed to decode JWKS"))
      jwksObj.keys should have size 1

      val jwk = jwksObj.keys.head
      jwk.kty should be("RSA")
      jwk.use should be("sig")
      jwk.alg should be("RS256")
      jwk.kid should be(testConfig.keyId)
      jwk.n should not be empty
      jwk.e should not be empty
    }

    test.unsafeRunSync()
  }

  "JWKS Endpoint" should "support HEAD requests" in {
    val test = for {
      app <- createTestApp
      request = Request[IO](Method.HEAD, uri"/obp-oidc/jwks")
      response <- app(request)
      body <- response.as[String]
    } yield {
      response.status should be(Status.Ok)
      response.contentType.map(_.mediaType) should be(
        Some(MediaType.application.json)
      )
      // HEAD request should have Content-Length header but empty body
      response.headers.get[headers.`Content-Length`] should not be None
      body should be(empty)
    }

    test.unsafeRunSync()
  }

  "Authorization Endpoint" should "show login form for valid authorization request" in {
    val test = for {
      app <- createTestApp
      uri = uri"/obp-oidc/auth"
        .withQueryParam("response_type", "code")
        .withQueryParam("client_id", "test-client")
        .withQueryParam("redirect_uri", "https://example.com/callback")
        .withQueryParam("scope", "openid profile email")
        .withQueryParam("state", "test-state")

      request = Request[IO](Method.GET, uri)
      response <- app(request)
      body <- response.as[String]
    } yield {
      response.status should be(Status.Ok)
      response.contentType.map(_.mediaType) should be(Some(MediaType.text.html))

      body should include("Sign In")
      body should include("test-client")
      body should include("openid profile email")
      body should include("Sign In")
      body should include("test-client")
      body should include("openid profile email")
    }

    test.unsafeRunSync()
  }

  "Authorization Endpoint" should "redirect with error for invalid response type" in {
    val test = for {
      app <- createTestApp
      uri = uri"/obp-oidc/auth"
        .withQueryParam("response_type", "token")
        .withQueryParam("client_id", "test-client")
        .withQueryParam("redirect_uri", "https://example.com/callback")
        .withQueryParam("scope", "openid")
        .withQueryParam("state", "test-state")

      request = Request[IO](Method.GET, uri)
      response <- app(request)
      location = response.headers.get(CIString("Location")).map(_.head.value)
    } yield {
      response.status should be(Status.SeeOther)
      location should be(defined)
      location.get should include("error=unsupported_response_type")
      location.get should include("state=test-state")
    }

    test.unsafeRunSync()
  }

  "Token Endpoint" should "return error for invalid grant type" in {
    val test = for {
      app <- createTestApp
      formData = UrlForm(
        "grant_type" -> "password",
        "username" -> "alice",
        "password" -> "secret123"
      )
      request = Request[IO](Method.POST, uri"/obp-oidc/token")
        .withEntity(formData)
      response <- app(request)
      body <- response.as[String]
    } yield {
      response.status should be(Status.BadRequest)
      response.contentType.map(_.mediaType) should be(
        Some(MediaType.application.json)
      )

      val error = decode[OidcError](body)
      error.isRight should be(true)
      error
        .getOrElse(throw new Exception("Failed to decode error"))
        .error should be("unsupported_grant_type")
    }

    test.unsafeRunSync()
  }

  "UserInfo Endpoint" should "return error without authorization header" in {
    val test = for {
      app <- createTestApp
      request = Request[IO](Method.GET, uri"/obp-oidc/userinfo")
      response <- app(request)
      body <- response.as[String]
    } yield {
      response.status should be(Status.BadRequest)
      body should include("Missing authorization header")
    }

    test.unsafeRunSync()
  }

  "Complete OIDC Flow" should "work end-to-end" in {
    val clientId = "test-client"
    val redirectUri = "https://example.com/callback"
    val scope = "openid profile email"
    val state = "test-state-123"
    val nonce = "test-nonce-456"

    val test = for {
      app <- createTestApp

      // Step 1: Login with valid credentials
      loginForm = UrlForm(
        "username" -> "alice123",
        "password" -> "secret123456",
        "provider" -> "obp-test",
        "client_id" -> clientId,
        "redirect_uri" -> redirectUri,
        "scope" -> scope,
        "state" -> state,
        "nonce" -> nonce
      )

      loginRequest = Request[IO](Method.POST, uri"/obp-oidc/auth").withEntity(
        loginForm
      )
      loginResponse <- app(loginRequest)
      location = loginResponse.headers
        .get(CIString("Location"))
        .map(_.head.value)

      // Extract authorization code from redirect
      _ = loginResponse.status should be(Status.SeeOther)
      _ = location should be(defined)
      uriFromLocation = Uri.unsafeFromString(location.get)
      codeParam = uriFromLocation.query.params.get("code")
      stateParam = uriFromLocation.query.params.get("state")

      _ = codeParam should be(defined)
      _ = stateParam should be(Some(state))
      code = codeParam.get

      // Step 2: Exchange code for tokens
      tokenForm = UrlForm(
        "grant_type" -> "authorization_code",
        "code" -> code,
        "redirect_uri" -> redirectUri,
        "client_id" -> clientId
      )

      tokenRequest = Request[IO](Method.POST, uri"/obp-oidc/token").withEntity(
        tokenForm
      )
      tokenResponse <- app(tokenRequest)
      tokenBody <- tokenResponse.as[String]

      _ = tokenResponse.status should be(Status.Ok)
      tokenResponseObj = decode[TokenResponse](tokenBody)

      _ = tokenResponseObj.isRight should be(true)
      tokens = tokenResponseObj.getOrElse(
        throw new Exception("Failed to decode token response")
      )

      // Step 3: Use access token to get user info
      userInfoRequest = Request[IO](Method.GET, uri"/obp-oidc/userinfo")
        .putHeaders(
          Header.Raw(
            CIString("Authorization"),
            s"Bearer ${tokens.access_token}"
          )
        )
      userInfoResponse <- app(userInfoRequest)
      userInfoBody <- userInfoResponse.as[String]

      _ = userInfoResponse.status should be(Status.Ok)
      userInfo = decode[UserInfo](userInfoBody)
      _ = userInfo.isRight should be(true)
      user = userInfo.getOrElse(
        throw new Exception("Failed to decode user info")
      )

    } yield {
      // Verify token response
      tokens.token_type should be("Bearer")
      tokens.expires_in should be(testConfig.tokenExpirationSeconds)
      tokens.scope should be(scope)
      tokens.access_token should not be empty
      tokens.id_token should not be empty

      // Verify user info
      user.sub should be("alice123")
      user.name should be(Some("Alice Smith"))
      user.email should be(Some("alice@example.com"))
      user.email_verified should be(Some(true))
    }

    test.unsafeRunSync()
  }

  "PAR Endpoint" should "issue a request_uri for a valid pushed authorization request" in {
    val test = for {
      app <- createTestApp
      parForm = UrlForm(
        "response_type" -> "code",
        "client_id" -> "test-client",
        "redirect_uri" -> "https://example.com/callback",
        "scope" -> "openid profile email",
        "state" -> "par-state-123",
        "code_challenge" -> "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
        "code_challenge_method" -> "S256"
      )
      parRequest = Request[IO](Method.POST, uri"/obp-oidc/par").withEntity(parForm)
      parResponse <- app(parRequest)
      body <- parResponse.as[String]
    } yield {
      parResponse.status should be(Status.Created)
      val par = decode[ParResponse](body)
      par.isRight should be(true)
      val parObj = par.getOrElse(throw new Exception("Failed to decode PAR response"))
      parObj.request_uri should startWith("urn:ietf:params:oauth:request_uri:")
      parObj.expires_in should be(testConfig.parExpirationSeconds)
    }

    test.unsafeRunSync()
  }

  it should "reject a code_challenge_method other than S256" in {
    val test = for {
      app <- createTestApp
      parForm = UrlForm(
        "response_type" -> "code",
        "client_id" -> "test-client",
        "redirect_uri" -> "https://example.com/callback",
        "scope" -> "openid profile email",
        "code_challenge" -> "somechallenge",
        "code_challenge_method" -> "plain"
      )
      parRequest = Request[IO](Method.POST, uri"/obp-oidc/par").withEntity(parForm)
      parResponse <- app(parRequest)
    } yield {
      parResponse.status should be(Status.BadRequest)
    }

    test.unsafeRunSync()
  }

  "Authorization Endpoint" should "resolve a pushed request_uri into a login form" in {
    val test = for {
      app <- createTestApp
      parForm = UrlForm(
        "response_type" -> "code",
        "client_id" -> "test-client",
        "redirect_uri" -> "https://example.com/callback",
        "scope" -> "openid profile email",
        "state" -> "par-resolve-state"
      )
      parRequest = Request[IO](Method.POST, uri"/obp-oidc/par").withEntity(parForm)
      parResponse <- app(parRequest)
      parBody <- parResponse.as[String]
      requestUri = decode[ParResponse](parBody)
        .getOrElse(throw new Exception("Failed to decode PAR response"))
        .request_uri

      authRequest = Request[IO](
        Method.GET,
        Uri
          .unsafeFromString("/obp-oidc/auth")
          .withQueryParam("client_id", "test-client")
          .withQueryParam("request_uri", requestUri)
      )
      authResponse <- app(authRequest)
      authBody <- authResponse.as[String]
    } yield {
      authResponse.status should be(Status.Ok)
      authBody should include("Sign In")
    }

    test.unsafeRunSync()
  }

  it should "reject an unknown request_uri" in {
    val test = for {
      app <- createTestApp
      authRequest = Request[IO](
        Method.GET,
        Uri
          .unsafeFromString("/obp-oidc/auth")
          .withQueryParam("client_id", "test-client")
          .withQueryParam(
            "request_uri",
            "urn:ietf:params:oauth:request_uri:does-not-exist"
          )
      )
      authResponse <- app(authRequest)
    } yield {
      authResponse.status should be(Status.BadRequest)
    }

    test.unsafeRunSync()
  }

  it should "reject a request_uri reused for a second request (one-time use)" in {
    val test = for {
      app <- createTestApp
      parForm = UrlForm(
        "response_type" -> "code",
        "client_id" -> "test-client",
        "redirect_uri" -> "https://example.com/callback",
        "scope" -> "openid profile email"
      )
      parRequest = Request[IO](Method.POST, uri"/obp-oidc/par").withEntity(parForm)
      parResponse <- app(parRequest)
      parBody <- parResponse.as[String]
      requestUri = decode[ParResponse](parBody)
        .getOrElse(throw new Exception("Failed to decode PAR response"))
        .request_uri

      authUri = Uri
        .unsafeFromString("/obp-oidc/auth")
        .withQueryParam("client_id", "test-client")
        .withQueryParam("request_uri", requestUri)

      firstResponse <- app(Request[IO](Method.GET, authUri))
      secondResponse <- app(Request[IO](Method.GET, authUri))
    } yield {
      firstResponse.status should be(Status.Ok)
      secondResponse.status should be(Status.BadRequest)
    }

    test.unsafeRunSync()
  }
}
