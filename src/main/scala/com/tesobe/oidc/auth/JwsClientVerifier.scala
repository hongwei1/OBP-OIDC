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

import com.nimbusds.jose.crypto.{ECDSAVerifier, RSASSAVerifier}
import com.nimbusds.jose.jwk.{ECKey, JWK, JWKSet, RSAKey}
import com.nimbusds.jwt.SignedJWT

import scala.jdk.CollectionConverters._
import scala.util.Try

/** Verifies a JWS against a client's JWKS: finds the signing key (by `kid` if
  * the JWS header carries one, else tries every key in the set) and checks
  * the signature with the matching verifier for that key's type. Shared by
  * signed-request-object and private_key_jwt client-assertion verification —
  * both need exactly this, against the same per-client JWKS source.
  */
object JwsClientVerifier {
  def verify(signedJwt: SignedJWT, jwks: JWKSet): Boolean = {
    val keyId = Option(signedJwt.getHeader.getKeyID)
    val candidates: List[JWK] = keyId match {
      case Some(kid) => Option(jwks.getKeyByKeyId(kid)).toList
      case None       => jwks.getKeys.asScala.toList
    }

    candidates
      .collectFirst {
        case rsaKey: RSAKey => Try(signedJwt.verify(new RSASSAVerifier(rsaKey))).getOrElse(false)
        case ecKey: ECKey   => Try(signedJwt.verify(new ECDSAVerifier(ecKey))).getOrElse(false)
      }
      .getOrElse(false)
  }
}
