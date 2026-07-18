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
import com.tesobe.oidc.config.OidcConfig
import com.tesobe.oidc.models.OidcConfiguration
import io.circe.syntax._
import org.http4s._
import org.http4s.circe._
import org.http4s.dsl.io._

class DiscoveryEndpoint(config: OidcConfig) {

  val routes: HttpRoutes[IO] = HttpRoutes.of[IO] {
    case GET -> Root / "obp-oidc" / ".well-known" / "openid-configuration" =>
      getConfiguration
    case HEAD -> Root / "obp-oidc" / ".well-known" / "openid-configuration" =>
      getConfigurationHead
  }

  private def getConfiguration: IO[Response[IO]] = {
    val configuration = OidcConfiguration(
      issuer = config.issuer,
      authorization_endpoint = s"${config.issuer}/auth",
      token_endpoint = s"${config.issuer}/token",
      userinfo_endpoint = s"${config.issuer}/userinfo",
      jwks_uri = s"${config.issuer}/jwks",
      revocation_endpoint = s"${config.issuer}/revoke",
      pushed_authorization_request_endpoint = Some(s"${config.issuer}/par"),
      registration_endpoint = if (config.enableDynamicClientRegistration) Some(s"${config.issuer}/connect/register") else None,
      response_types_supported = List("code", "code id_token"),
      subject_types_supported = List("public"),
      id_token_signing_alg_values_supported = List("RS256"),
      scopes_supported = List("openid", "profile", "email"),
      token_endpoint_auth_methods_supported =
        List("client_secret_post", "client_secret_basic", "none"),
      claims_supported = List("sub", "name", "email", "email_verified", "consent_id"),
      grant_types_supported =
        List("authorization_code", "refresh_token", "client_credentials"),
      revocation_endpoint_auth_methods_supported =
        List("client_secret_post", "client_secret_basic")
    )

    Ok(configuration.asJson)
  }

  private def getConfigurationHead: IO[Response[IO]] = {
    val configuration = OidcConfiguration(
      issuer = config.issuer,
      authorization_endpoint = s"${config.issuer}/auth",
      token_endpoint = s"${config.issuer}/token",
      userinfo_endpoint = s"${config.issuer}/userinfo",
      jwks_uri = s"${config.issuer}/jwks",
      revocation_endpoint = s"${config.issuer}/revoke",
      pushed_authorization_request_endpoint = Some(s"${config.issuer}/par"),
      registration_endpoint = if (config.enableDynamicClientRegistration) Some(s"${config.issuer}/connect/register") else None,
      response_types_supported = List("code", "code id_token"),
      subject_types_supported = List("public"),
      id_token_signing_alg_values_supported = List("RS256"),
      scopes_supported = List("openid", "profile", "email"),
      token_endpoint_auth_methods_supported =
        List("client_secret_post", "client_secret_basic", "none"),
      claims_supported = List("sub", "name", "email", "email_verified", "consent_id"),
      grant_types_supported =
        List("authorization_code", "refresh_token", "client_credentials"),
      revocation_endpoint_auth_methods_supported =
        List("client_secret_post", "client_secret_basic")
    )

    // For HEAD requests, return OK with proper headers but no body
    Ok(configuration.asJson).map(_.withBodyStream(fs2.Stream.empty))
  }
}

object DiscoveryEndpoint {
  def apply(config: OidcConfig): DiscoveryEndpoint = new DiscoveryEndpoint(
    config
  )
}
