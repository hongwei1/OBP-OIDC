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
import cats.syntax.all._
import com.tesobe.oidc.auth.HybridAuthService
import com.tesobe.oidc.config.OidcConfig
import com.tesobe.oidc.models._
import com.tesobe.oidc.ratelimit.RateLimitService
import io.circe.syntax._
import org.http4s._
import org.http4s.circe._
import org.http4s.circe.CirceEntityDecoder._
import org.http4s.dsl.io._
import org.http4s.headers.`Cache-Control`
import org.http4s.CacheDirective
import org.slf4j.LoggerFactory

import java.security.SecureRandom
import java.util.{Base64, UUID}
import scala.util.Try

/** Dynamic Client Registration Endpoint (RFC 7591)
  *
  * Allows OAuth 2.0 clients to register themselves programmatically.
  * Endpoint: POST /obp-oidc/connect/register
  */
class RegistrationEndpoint(
    authService: HybridAuthService,
    rateLimitService: RateLimitService[IO],
    config: OidcConfig
) {

  private val logger = LoggerFactory.getLogger(getClass)
  private val secureRandom = new SecureRandom()

  val routes: HttpRoutes[IO] = HttpRoutes.of[IO] {
    case req @ POST -> Root / "obp-oidc" / "connect" / "register" =>
      logger.info("Dynamic Client Registration request received")
      handleRegistrationRequest(req)
  }

  private def handleRegistrationRequest(req: Request[IO]): IO[Response[IO]] = {
    // Extract IP for rate limiting
    val clientIp = extractClientIp(req)

    // Check rate limit first
    rateLimitService.isBlocked(clientIp, "registration").flatMap { blocked =>
      if (blocked) {
        logger.warn(s"Rate limit exceeded for IP: $clientIp")
        TooManyRequests(
          ClientRegistrationError(
            "invalid_request",
            Some("Too many registration requests. Please try again later.")
          ).asJson
        )
      } else {
        processRegistration(req, clientIp)
      }
    }
  }

  private def processRegistration(
      req: Request[IO],
      clientIp: String
  ): IO[Response[IO]] = {
    req
      .as[ClientRegistrationRequest]
      .attempt
      .flatMap {
        case Right(registrationRequest) =>
          logger.info(
            s"Processing registration for client: ${registrationRequest.client_name}"
          )
          validateAndRegister(registrationRequest)

        case Left(error) =>
          logger.error(s"Failed to parse registration request: ${error.getMessage}")
          BadRequest(
            ClientRegistrationError(
              ClientRegistrationError.INVALID_CLIENT_METADATA,
              Some("Invalid JSON request body. Please check the request format.")
            ).asJson
          ).map(addNoCacheHeaders)
      }
  }

  private def validateAndRegister(
      request: ClientRegistrationRequest
  ): IO[Response[IO]] = {
    // Validate the request
    validateRequest(request) match {
      case Left(error) =>
        logger.warn(s"Validation failed: ${error.error_description.getOrElse(error.error)}")
        BadRequest(error.asJson).map(addNoCacheHeaders)

      case Right(validatedRequest) =>
        // Generate credentials
        val clientId = generateClientId()
        val clientSecret = generateClientSecret()
        val issuedAt = System.currentTimeMillis() / 1000

        // Resolve defaults
        val grantTypes = validatedRequest.grant_types.getOrElse(
          ClientRegistrationRequest.DEFAULT_GRANT_TYPES
        )
        val responseTypes = validatedRequest.response_types.getOrElse(
          ClientRegistrationRequest.DEFAULT_RESPONSE_TYPES
        )
        val authMethod = validatedRequest.token_endpoint_auth_method.getOrElse(
          ClientRegistrationRequest.DEFAULT_AUTH_METHOD
        )
        val scopes = validatedRequest.scope
          .map(_.split("\\s+").toList)
          .getOrElse(ClientRegistrationRequest.DEFAULT_SCOPES)

        // Create OidcClient for persistence
        val oidcClient = OidcClient(
          client_id = clientId,
          client_secret = Some(clientSecret),
          client_name = validatedRequest.client_name,
          consumer_id = clientId, // Use client_id as consumer_id for DCR clients
          redirect_uris = validatedRequest.redirect_uris,
          grant_types = grantTypes,
          response_types = responseTypes,
          scopes = scopes,
          token_endpoint_auth_method = authMethod,
          created_at = Some(java.time.Instant.now().toString),
          jwks_uri = validatedRequest.jwks_uri,
          client_certificate = validatedRequest.client_certificate
        )

        // Persist the client
        authService.createClient(oidcClient).flatMap {
          case Right(createdClient) =>
            // Use the client_id and secret from the created client.
            // When created via OBP API, these come from the OBP consumer
            // (consumer_key/consumer_secret) rather than the locally generated ones.
            val effectiveClientId = createdClient.client_id
            val effectiveClientSecret = createdClient.client_secret.getOrElse(clientSecret)
            logger.info(s"Successfully registered client: $effectiveClientId (${validatedRequest.client_name})")

            // Build response
            val response = ClientRegistrationResponse(
              client_id = effectiveClientId,
              client_secret = Some(effectiveClientSecret),
              client_id_issued_at = issuedAt,
              client_secret_expires_at = 0, // Never expires
              client_name = validatedRequest.client_name,
              redirect_uris = validatedRequest.redirect_uris,
              grant_types = grantTypes,
              response_types = responseTypes,
              scope = scopes.mkString(" "),
              token_endpoint_auth_method = authMethod,
              logo_uri = validatedRequest.logo_uri,
              client_uri = validatedRequest.client_uri,
              contacts = validatedRequest.contacts,
              jwks_uri = createdClient.jwks_uri,
              client_certificate = createdClient.client_certificate
            )

            Created(response.asJson).map(addNoCacheHeaders)

          case Left(error) =>
            logger.error(s"Failed to persist client: ${error.error_description.getOrElse(error.error)}")
            InternalServerError(
              ClientRegistrationError(
                "server_error",
                Some("Registration failed. Please try again later.")
              ).asJson
            ).map(addNoCacheHeaders)
        }
    }
  }

  /** Validate the registration request per RFC 7591 */
  private def validateRequest(
      request: ClientRegistrationRequest
  ): Either[ClientRegistrationError, ClientRegistrationRequest] = {
    // Validate client_name is not empty
    if (request.client_name.trim.isEmpty) {
      return Left(
        ClientRegistrationError(
          ClientRegistrationError.INVALID_CLIENT_METADATA,
          Some("client_name is required and cannot be empty")
        )
      )
    }

    // Validate redirect_uris
    if (request.redirect_uris.isEmpty) {
      return Left(
        ClientRegistrationError(
          ClientRegistrationError.INVALID_REDIRECT_URI,
          Some("At least one redirect_uri is required")
        )
      )
    }

    // Validate each redirect_uri
    for (uri <- request.redirect_uris) {
      validateRedirectUri(uri) match {
        case Left(error) => return Left(error)
        case Right(_)    => // Continue
      }
    }

    // Validate grant_types if provided
    request.grant_types.foreach { grantTypes =>
      val unsupported = grantTypes.toSet -- ClientRegistrationRequest.SUPPORTED_GRANT_TYPES
      if (unsupported.nonEmpty) {
        return Left(
          ClientRegistrationError(
            ClientRegistrationError.INVALID_CLIENT_METADATA,
            Some(s"Unsupported grant_types: ${unsupported.mkString(", ")}. Supported: ${ClientRegistrationRequest.SUPPORTED_GRANT_TYPES.mkString(", ")}")
          )
        )
      }
    }

    // Validate response_types if provided
    request.response_types.foreach { responseTypes =>
      val unsupported = responseTypes.toSet -- ClientRegistrationRequest.SUPPORTED_RESPONSE_TYPES
      if (unsupported.nonEmpty) {
        return Left(
          ClientRegistrationError(
            ClientRegistrationError.INVALID_CLIENT_METADATA,
            Some(s"Unsupported response_types: ${unsupported.mkString(", ")}. Supported: ${ClientRegistrationRequest.SUPPORTED_RESPONSE_TYPES.mkString(", ")}")
          )
        )
      }
    }

    // Validate token_endpoint_auth_method if provided
    request.token_endpoint_auth_method.foreach { authMethod =>
      if (!ClientRegistrationRequest.SUPPORTED_AUTH_METHODS.contains(authMethod)) {
        return Left(
          ClientRegistrationError(
            ClientRegistrationError.INVALID_CLIENT_METADATA,
            Some(s"Unsupported token_endpoint_auth_method: $authMethod. Supported: ${ClientRegistrationRequest.SUPPORTED_AUTH_METHODS.mkString(", ")}")
          )
        )
      }

      // private_key_jwt / tls_client_auth need something to verify future requests
      // against — without it the client could never actually authenticate this way.
      if (authMethod == "private_key_jwt" && request.jwks_uri.isEmpty) {
        return Left(
          ClientRegistrationError(
            ClientRegistrationError.INVALID_CLIENT_METADATA,
            Some("jwks_uri is required when token_endpoint_auth_method is private_key_jwt")
          )
        )
      }
      if (authMethod == "tls_client_auth" && request.client_certificate.isEmpty) {
        return Left(
          ClientRegistrationError(
            ClientRegistrationError.INVALID_CLIENT_METADATA,
            Some("client_certificate is required when token_endpoint_auth_method is tls_client_auth")
          )
        )
      }
    }

    // Validate jwks_uri if provided (must be a valid HTTPS URL, per FAPI's TLS requirement)
    request.jwks_uri.foreach { jwksUri =>
      if (!isValidHttpUrl(jwksUri)) {
        return Left(
          ClientRegistrationError(
            ClientRegistrationError.INVALID_CLIENT_METADATA,
            Some(s"jwks_uri must be a valid HTTP/HTTPS URL: $jwksUri")
          )
        )
      }
    }

    // Validate logo_uri if provided (must be valid URL)
    request.logo_uri.foreach { logoUri =>
      if (!isValidHttpUrl(logoUri)) {
        return Left(
          ClientRegistrationError(
            ClientRegistrationError.INVALID_CLIENT_METADATA,
            Some(s"logo_uri must be a valid HTTP/HTTPS URL: $logoUri")
          )
        )
      }
    }

    // Validate client_uri if provided (must be valid URL)
    request.client_uri.foreach { clientUri =>
      if (!isValidHttpUrl(clientUri)) {
        return Left(
          ClientRegistrationError(
            ClientRegistrationError.INVALID_CLIENT_METADATA,
            Some(s"client_uri must be a valid HTTP/HTTPS URL: $clientUri")
          )
        )
      }
    }

    Right(request)
  }

  /** Validate a redirect URI per RFC 7591 / OAuth 2.1 security best practices */
  private def validateRedirectUri(
      uri: String
  ): Either[ClientRegistrationError, String] = {
    Try(new java.net.URI(uri)).toEither match {
      case Left(_) =>
        Left(
          ClientRegistrationError(
            ClientRegistrationError.INVALID_REDIRECT_URI,
            Some(s"Invalid redirect_uri format: $uri")
          )
        )

      case Right(parsedUri) =>
        val scheme = Option(parsedUri.getScheme).map(_.toLowerCase)

        // Must have a scheme
        if (scheme.isEmpty) {
          return Left(
            ClientRegistrationError(
              ClientRegistrationError.INVALID_REDIRECT_URI,
              Some(s"redirect_uri must have a scheme: $uri")
            )
          )
        }

        // Allow http, https, and custom schemes (for native apps)
        // But reject javascript: and data: schemes
        val dangerousSchemes = Set("javascript", "data", "vbscript")
        if (dangerousSchemes.contains(scheme.get)) {
          return Left(
            ClientRegistrationError(
              ClientRegistrationError.INVALID_REDIRECT_URI,
              Some(s"Dangerous redirect_uri scheme not allowed: ${scheme.get}")
            )
          )
        }

        // For http(s) URIs, must be absolute (have a host)
        if (scheme.contains("http") || scheme.contains("https")) {
          if (Option(parsedUri.getHost).isEmpty) {
            return Left(
              ClientRegistrationError(
                ClientRegistrationError.INVALID_REDIRECT_URI,
                Some(s"HTTP(S) redirect_uri must have a host: $uri")
              )
            )
          }

          // Warn about localhost in non-development mode (but still allow it)
          val host = parsedUri.getHost.toLowerCase
          if (!config.localDevelopmentMode && (host == "localhost" || host == "127.0.0.1")) {
            logger.warn(s"Localhost redirect_uri registered in non-development mode: $uri")
          }
        }

        // No fragment allowed in redirect_uri (OAuth 2.1 requirement)
        if (Option(parsedUri.getFragment).isDefined) {
          return Left(
            ClientRegistrationError(
              ClientRegistrationError.INVALID_REDIRECT_URI,
              Some(s"redirect_uri must not contain a fragment: $uri")
            )
          )
        }

        Right(uri)
    }
  }

  /** Check if a URL is a valid HTTP/HTTPS URL */
  private def isValidHttpUrl(url: String): Boolean = {
    Try(new java.net.URI(url)).toOption.exists { uri =>
      val scheme = Option(uri.getScheme).map(_.toLowerCase)
      (scheme.contains("http") || scheme.contains("https")) && Option(uri.getHost).isDefined
    }
  }

  /** Generate a secure client_id (UUID format) */
  private def generateClientId(): String = {
    s"dcr-${UUID.randomUUID().toString}"
  }

  /** Generate a secure client_secret (32 bytes, Base64 encoded) */
  private def generateClientSecret(): String = {
    val bytes = new Array[Byte](32)
    secureRandom.nextBytes(bytes)
    Base64.getUrlEncoder.withoutPadding.encodeToString(bytes)
  }

  /** Extract client IP from request headers */
  private def extractClientIp(req: Request[IO]): String = {
    req.headers
      .get(org.typelevel.ci.CIString("X-Forwarded-For"))
      .map(_.head.value.split(",").head.trim)
      .orElse(
        req.headers
          .get(org.typelevel.ci.CIString("X-Real-IP"))
          .map(_.head.value)
      )
      .getOrElse(
        req.remoteAddr.map(_.toUriString).getOrElse("unknown")
      )
  }

  /** Add Cache-Control: no-store header per RFC 7591 */
  private def addNoCacheHeaders(response: Response[IO]): Response[IO] = {
    response.putHeaders(`Cache-Control`(CacheDirective.`no-store`))
  }
}

object RegistrationEndpoint {
  def apply(
      authService: HybridAuthService,
      rateLimitService: RateLimitService[IO],
      config: OidcConfig
  ): RegistrationEndpoint =
    new RegistrationEndpoint(authService, rateLimitService, config)
}
