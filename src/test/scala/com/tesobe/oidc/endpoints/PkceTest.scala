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

import org.scalatest.funsuite.AnyFunSuite
import org.scalatest.matchers.should.Matchers
import java.security.MessageDigest
import java.nio.charset.StandardCharsets

/** Tests for PKCE (RFC 7636) S256 code_challenge computation, mirroring
  * TokenEndpoint.computeS256Challenge (private, so the logic is duplicated
  * here per this file's existing AuthInputValidationTest convention).
  */
class PkceTest extends AnyFunSuite with Matchers {

  private def computeS256Challenge(codeVerifier: String): String = {
    val digest = MessageDigest
      .getInstance("SHA-256")
      .digest(codeVerifier.getBytes(StandardCharsets.US_ASCII))
    java.util.Base64.getUrlEncoder.withoutPadding.encodeToString(digest)
  }

  // RFC 7636 Appendix B official test vector
  test("computeS256Challenge matches the RFC 7636 Appendix B test vector") {
    val verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    val expectedChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
    computeS256Challenge(verifier) shouldBe expectedChallenge
  }

  test("computeS256Challenge output has no padding and is URL-safe") {
    val challenge = computeS256Challenge("some-random-verifier-value-1234567890")
    challenge should not include "="
    challenge should not include "+"
    challenge should not include "/"
  }

  test("a different verifier produces a different challenge") {
    val challengeA = computeS256Challenge("verifier-a-1234567890123456789012345")
    val challengeB = computeS256Challenge("verifier-b-1234567890123456789012345")
    challengeA should not equal challengeB
  }

  test("the same verifier always produces the same challenge (deterministic)") {
    val verifier = "repeatable-verifier-value-123456789012"
    computeS256Challenge(verifier) shouldBe computeS256Challenge(verifier)
  }
}
