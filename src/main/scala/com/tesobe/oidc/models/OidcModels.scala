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

package com.tesobe.oidc.models

import io.circe.{Decoder, Encoder}
import io.circe.generic.semiauto.{deriveDecoder, deriveEncoder}

// OIDC Discovery Document
case class OidcConfiguration(
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    userinfo_endpoint: String,
    jwks_uri: String,
    revocation_endpoint: String,
    registration_endpoint: Option[String] = None, // RFC 7591 Dynamic Client Registration
    response_types_supported: List[String],
    subject_types_supported: List[String],
    id_token_signing_alg_values_supported: List[String],
    scopes_supported: List[String],
    token_endpoint_auth_methods_supported: List[String],
    claims_supported: List[String],
    grant_types_supported: List[String],
    revocation_endpoint_auth_methods_supported: List[String],
    // PKCE (RFC 7636 / RFC 8414): advertised code_challenge methods. FAPI requires S256.
    code_challenge_methods_supported: List[String] = List("S256"),
    // PAR (RFC 9126)
    pushed_authorization_request_endpoint: Option[String] = None,
    require_pushed_authorization_requests: Boolean = false
)

object OidcConfiguration {
  implicit val encoder: Encoder[OidcConfiguration] = deriveEncoder
  implicit val decoder: Decoder[OidcConfiguration] = deriveDecoder
}

// JWT Claims for ID Token
case class IdTokenClaims(
    iss: String, // Issuer
    sub: String, // Subject (user ID)
    aud: String, // Audience (client ID)
    exp: Long, // Expiration time
    iat: Long, // Issued at time
    azp: Option[String] = None, // Authorized Party (client ID)
    nonce: Option[String] = None, // Nonce from authorization request
    // Standard claims
    name: Option[String] = None,
    email: Option[String] = None,
    email_verified: Option[Boolean] = None
)

object IdTokenClaims {
  implicit val encoder: Encoder[IdTokenClaims] = deriveEncoder
  implicit val decoder: Decoder[IdTokenClaims] = deriveDecoder
}

// Access Token Claims
case class AccessTokenClaims(
    iss: String,
    sub: String,
    aud: String,
    exp: Long,
    iat: Long,
    scope: String,
    client_id: String,
    azp: Option[String] = None, // Authorized Party (client ID)
    provider: Option[String] = None, // Identity provider name
    consent_id: Option[String] = None // OBP Consent bound to this token (consent authorisation flow)
)

object AccessTokenClaims {
  implicit val encoder: Encoder[AccessTokenClaims] = deriveEncoder
  implicit val decoder: Decoder[AccessTokenClaims] = deriveDecoder
}

// User info for mocked service
case class User(
    sub: String,
    username: String,
    password: String, // In real implementation, this would be hashed
    name: Option[String] = None,
    email: Option[String] = None,
    email_verified: Option[Boolean] = Some(true),
    provider: Option[String] = None
)

object User {
  implicit val encoder: Encoder[User] = deriveEncoder
  implicit val decoder: Decoder[User] = deriveDecoder
}

// UserInfo endpoint response
case class UserInfo(
    sub: String,
    name: Option[String] = None,
    given_name: Option[String] = None,
    family_name: Option[String] = None,
    email: Option[String] = None,
    email_verified: Option[Boolean] = None
)

object UserInfo {
  implicit val encoder: Encoder[UserInfo] = deriveEncoder
  implicit val decoder: Decoder[UserInfo] = deriveDecoder
}

// OIDC Client Registration
case class OidcClient(
    client_id: String,
    client_secret: Option[String] = None,
    client_name: String,
    consumer_id: String,
    redirect_uris: List[String],
    grant_types: List[String] = List("authorization_code"),
    response_types: List[String] = List("code"),
    scopes: List[String] = List("openid", "profile", "email"),
    token_endpoint_auth_method: String = "client_secret_post",
    created_at: Option[String] = None
)

object OidcClient {
  implicit val encoder: Encoder[OidcClient] = deriveEncoder
  implicit val decoder: Decoder[OidcClient] = deriveDecoder
}

// Authorization request parameters
case class AuthorizationRequest(
    response_type: String,
    client_id: String,
    redirect_uri: String,
    scope: String,
    state: Option[String] = None,
    nonce: Option[String] = None
)

object AuthorizationRequest {
  implicit val encoder: Encoder[AuthorizationRequest] = deriveEncoder
  implicit val decoder: Decoder[AuthorizationRequest] = deriveDecoder
}

// Authorization code (temporary)
case class AuthorizationCode(
    code: String,
    client_id: String,
    redirect_uri: String,
    sub: String,
    scope: String,
    state: Option[String] = None,
    nonce: Option[String] = None,
    provider: Option[String] = None,
    exp: Long, // Expiration time
    consent_id: Option[String] = None,
    // PKCE (RFC 7636): the S256 code_challenge captured at the authorization request,
    // verified against the code_verifier at token exchange. None = client did not use PKCE.
    code_challenge: Option[String] = None,
    code_challenge_method: Option[String] = None
)

// PAR (RFC 9126): parameters pushed to /par ahead of the authorization request,
// resolved later at GET /auth via the request_uri it was issued.
case class PushedAuthorizationRequest(
    request_uri: String,
    client_id: String,
    response_type: String,
    redirect_uri: String,
    scope: String,
    state: Option[String] = None,
    nonce: Option[String] = None,
    consent_request_id: Option[String] = None,
    bank_id: Option[String] = None,
    consent_id: Option[String] = None,
    code_challenge: Option[String] = None,
    code_challenge_method: Option[String] = None,
    exp: Long
)

case class ParResponse(request_uri: String, expires_in: Long)

object ParResponse {
  implicit val encoder: Encoder[ParResponse] = deriveEncoder
  implicit val decoder: Decoder[ParResponse] = deriveDecoder
}

object AuthorizationCode {
  implicit val encoder: Encoder[AuthorizationCode] = deriveEncoder
  implicit val decoder: Decoder[AuthorizationCode] = deriveDecoder
}

// Token request
case class TokenRequest(
    grant_type: String,
    code: String,
    redirect_uri: String,
    client_id: String
)

object TokenRequest {
  implicit val encoder: Encoder[TokenRequest] = deriveEncoder
  implicit val decoder: Decoder[TokenRequest] = deriveDecoder
}

// Token response
case class TokenResponse(
    access_token: String,
    token_type: String = "Bearer",
    expires_in: Long,
    id_token: String,
    scope: String,
    refresh_token: Option[String] = None
)

object TokenResponse {
  implicit val encoder: Encoder[TokenResponse] = deriveEncoder
  implicit val decoder: Decoder[TokenResponse] = deriveDecoder
}

// Refresh Token Claims for JWT
case class RefreshTokenClaims(
    iss: String, // Issuer
    sub: String, // Subject (user ID)
    aud: String, // Audience (client ID)
    exp: Long, // Expiration time
    iat: Long, // Issued at time
    jti: String, // JWT ID (unique token identifier)
    scope: String,
    client_id: String,
    consent_id: Option[String] = None // Carried across token rotation so refreshed access tokens stay consent-bound
)

object RefreshTokenClaims {
  implicit val encoder: Encoder[RefreshTokenClaims] = deriveEncoder
  implicit val decoder: Decoder[RefreshTokenClaims] = deriveDecoder
}

// Consent challenge: holds paused authorization state while user approves consent in Portal.
// No user identity at creation time — the user authenticates on Portal, not here.
// Portal passes back user_id on the callback so we can generate the auth code.
case class ConsentChallenge(
    challenge: String,          // Unique ID for this challenge
    clientId: String,           // Hola's client_id
    redirectUri: String,        // Hola's redirect_uri
    scope: String,              // Requested scopes
    state: Option[String],      // Hola's OAuth state
    nonce: Option[String],      // Hola's OAuth nonce
    responseType: String,       // "code" or "code id_token"
    consentRequestId: String,   // OBP consent_request_id
    bankId: String,             // OBP bank_id
    exp: Long                   // Expiration time
)

object ConsentChallenge {
  implicit val encoder: Encoder[ConsentChallenge] = deriveEncoder
  implicit val decoder: Decoder[ConsentChallenge] = deriveDecoder
}

// Error responses
case class OidcError(
    error: String,
    error_description: Option[String] = None,
    error_uri: Option[String] = None,
    state: Option[String] = None
)

object OidcError {
  implicit val encoder: Encoder[OidcError] = deriveEncoder
  implicit val decoder: Decoder[OidcError] = deriveDecoder
}

// JWK (JSON Web Key) for JWKS endpoint
case class JsonWebKey(
    kty: String, // Key type (RSA)
    use: String, // Usage (sig for signing)
    kid: String, // Key ID
    alg: String, // Algorithm (RS256)
    n: String, // RSA modulus
    e: String // RSA public exponent
)

object JsonWebKey {
  implicit val encoder: Encoder[JsonWebKey] = deriveEncoder
  implicit val decoder: Decoder[JsonWebKey] = deriveDecoder
}

// JWKS response
case class JsonWebKeySet(
    keys: List[JsonWebKey]
)

object JsonWebKeySet {
  implicit val encoder: Encoder[JsonWebKeySet] = deriveEncoder
  implicit val decoder: Decoder[JsonWebKeySet] = deriveDecoder
}

// Login form data
case class LoginForm(
    username: String,
    password: String,
    client_id: String,
    redirect_uri: String,
    scope: String,
    state: Option[String] = None,
    nonce: Option[String] = None
)

object LoginForm {
  implicit val encoder: Encoder[LoginForm] = deriveEncoder
  implicit val decoder: Decoder[LoginForm] = deriveDecoder
}

// Token revocation request (RFC 7009)
case class RevocationRequest(
    token: String,
    token_type_hint: Option[String] = None // "access_token" or "refresh_token"
)

object RevocationRequest {
  implicit val encoder: Encoder[RevocationRequest] = deriveEncoder
  implicit val decoder: Decoder[RevocationRequest] = deriveDecoder
}

// Dynamic Client Registration (RFC 7591)
// Request for registering a new OAuth 2.0 client
case class ClientRegistrationRequest(
    client_name: String,
    redirect_uris: List[String],
    grant_types: Option[List[String]] = None,
    response_types: Option[List[String]] = None,
    scope: Option[String] = None,
    token_endpoint_auth_method: Option[String] = None,
    logo_uri: Option[String] = None,
    client_uri: Option[String] = None,
    contacts: Option[List[String]] = None
)

object ClientRegistrationRequest {
  implicit val encoder: Encoder[ClientRegistrationRequest] = deriveEncoder
  implicit val decoder: Decoder[ClientRegistrationRequest] = deriveDecoder

  // Supported values per RFC 7591 / OAuth 2.1
  val SUPPORTED_GRANT_TYPES: Set[String] = Set(
    "authorization_code",
    "refresh_token",
    "client_credentials"
  )

  val SUPPORTED_RESPONSE_TYPES: Set[String] = Set("code")

  val SUPPORTED_AUTH_METHODS: Set[String] = Set(
    "client_secret_post",
    "client_secret_basic",
    "none"
  )

  val DEFAULT_GRANT_TYPES: List[String] = List("authorization_code")
  val DEFAULT_RESPONSE_TYPES: List[String] = List("code")
  val DEFAULT_AUTH_METHOD: String = "client_secret_post"
  val DEFAULT_SCOPES: List[String] = List("openid", "profile", "email")
}

// Response after successfully registering a client (RFC 7591)
case class ClientRegistrationResponse(
    client_id: String,
    client_secret: Option[String],
    client_id_issued_at: Long,
    client_secret_expires_at: Long, // 0 means never expires
    client_name: String,
    redirect_uris: List[String],
    grant_types: List[String],
    response_types: List[String],
    scope: String,
    token_endpoint_auth_method: String,
    logo_uri: Option[String] = None,
    client_uri: Option[String] = None,
    contacts: Option[List[String]] = None
)

object ClientRegistrationResponse {
  implicit val encoder: Encoder[ClientRegistrationResponse] = deriveEncoder
  implicit val decoder: Decoder[ClientRegistrationResponse] = deriveDecoder
}

// Error response for client registration (RFC 7591)
case class ClientRegistrationError(
    error: String,
    error_description: Option[String] = None
)

object ClientRegistrationError {
  implicit val encoder: Encoder[ClientRegistrationError] = deriveEncoder
  implicit val decoder: Decoder[ClientRegistrationError] = deriveDecoder

  // Standard error codes per RFC 7591
  val INVALID_REDIRECT_URI = "invalid_redirect_uri"
  val INVALID_CLIENT_METADATA = "invalid_client_metadata"
  val INVALID_SOFTWARE_STATEMENT = "invalid_software_statement"
  val UNAPPROVED_SOFTWARE_STATEMENT = "unapproved_software_statement"
}
