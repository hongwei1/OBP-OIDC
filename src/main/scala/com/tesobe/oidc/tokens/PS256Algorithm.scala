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

import com.auth0.jwt.algorithms.Algorithm
import com.auth0.jwt.exceptions.{SignatureGenerationException, SignatureVerificationException}
import com.auth0.jwt.interfaces.DecodedJWT

import java.security.interfaces.{RSAPrivateKey, RSAPublicKey}
import java.security.spec.{MGF1ParameterSpec, PSSParameterSpec}
import java.security.{Signature, SecureRandom}
import java.util.Base64

/** PS256 (RSASSA-PSS with SHA-256, MGF1-SHA256, 32-byte salt) for the auth0
  * java-jwt library, which only ships plain RSASSA (RS256/384/512) — FAPI
  * 1.0 Advanced's strict profile requires PS256 instead. `Algorithm` is
  * designed to be subclassed (protected constructor, abstract sign/verify);
  * this uses the JDK's own "RSASSA-PSS" Signature provider (built in since
  * Java 11) with PS256's exact parameters, so no extra crypto dependency is
  * needed just for this.
  */
class PS256Algorithm(publicKey: RSAPublicKey, privateKey: RSAPrivateKey)
    extends Algorithm("PS256", "RSASSA-PSS256") {

  private val pssParams = new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1)

  def sign(contentBytes: Array[Byte]): Array[Byte] = {
    try {
      val signature = Signature.getInstance("RSASSA-PSS")
      signature.setParameter(pssParams)
      signature.initSign(privateKey, new SecureRandom())
      signature.update(contentBytes)
      signature.sign()
    } catch {
      case e: Exception =>
        throw new SignatureGenerationException(this, e)
    }
  }

  def verify(jwt: DecodedJWT): Unit = {
    try {
      val signature = Signature.getInstance("RSASSA-PSS")
      signature.setParameter(pssParams)
      signature.initVerify(publicKey)
      val signingInput = s"${jwt.getHeader}.${jwt.getPayload}".getBytes("UTF-8")
      signature.update(signingInput)
      val signatureBytes = Base64.getUrlDecoder.decode(jwt.getSignature)
      if (!signature.verify(signatureBytes)) {
        throw new SignatureVerificationException(this)
      }
    } catch {
      case e: SignatureVerificationException => throw e
      case e: Exception                      => throw new SignatureVerificationException(this, e)
    }
  }
}
