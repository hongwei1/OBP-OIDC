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

import com.tesobe.oidc.config.{DatabaseConfig, OidcConfig, ServerConfig}
import org.http4s.{Header, Method, Request, Uri}
import org.scalatest.funsuite.AnyFunSuite
import org.scalatest.matchers.should.Matchers
import org.typelevel.ci.CIString

import java.net.URLEncoder

/** Two distinct real self-signed test certificates (openssl req -x509),
  * fixed as constants so tests don't depend on any certificate-generation
  * API being available/stable across JDKs.
  */
class MtlsServiceTest extends AnyFunSuite with Matchers {

  private val certPem1 =
    """-----BEGIN CERTIFICATE-----
      |MIICrDCCAZQCCQDYp7easZ19xDANBgkqhkiG9w0BAQsFADAYMRYwFAYDVQQDDA10
      |ZXN0LWNsaWVudC0xMB4XDTI2MDcxODE1NTM0M1oXDTM2MDcxNTE1NTM0M1owGDEW
      |MBQGA1UEAwwNdGVzdC1jbGllbnQtMTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCC
      |AQoCggEBANAW483BfrX+HOY4OYDU2qhOCgRZ7BSMyCsj1ibGGG5kf+Zqfk2kWn4J
      |909G51V6+U0Z4xvVra9Cmtv4AnAlXiVALNFzLeH6T4V/NGcO5ClrBI1fA4kVewZ8
      |1D5bLPYbW07FocDNh26+BuH11I5rnwPnFupXwVumpqNcYpkrJsgtYTN9VKIvtipT
      |aO56UO5Gj/il7VzNllebc/13cCcQSG/FMt6tFC83SP7sXRiCsvqg7noPg2p/shkJ
      |mBdbSDeKKyFqRarJEKKnNLLhLFKQXNYR66qerD62iKFfY0nwxv3bepxtGw+i7a22
      |vedhNVs5pNeKGRJJofyHTGKgdD5r7zUCAwEAATANBgkqhkiG9w0BAQsFAAOCAQEA
      |m9vOWKvDFxSxOmot7GaiwPSPuzP/s17DWX3yOsRNsaKcOBTVr4avhsrIDbFh1C/y
      |PNPDNAoUpdn8+ZxAv25aOll94EPHY9hMlsDHp32SV55hVil4Ep/TQN4LRIXnHGbr
      |nRLSlxt9Bw8Vf4AWlkS0MDsrfb9uMqjOFulGzkZuOa4DwB2xjBp93asXWYRIgPLA
      |CvDQoN4RM+cV0+jnCCztKKTMHqQHMAnHQN6ldJSUk4I7QSAfxJv1V/gZTQUoiEf6
      |ztQGJhq1zIJXdU8njIq4rUrDxBOU/+KyuqCLCGeMcOjwogjsk1NjbGuAlJi5RO0d
      |pXNqTf6QbaDHJQ0Yhi4ZFQ==
      |-----END CERTIFICATE-----""".stripMargin

  private val certPem2 =
    """-----BEGIN CERTIFICATE-----
      |MIICrDCCAZQCCQDcCxn22XqjVzANBgkqhkiG9w0BAQsFADAYMRYwFAYDVQQDDA10
      |ZXN0LWNsaWVudC0yMB4XDTI2MDcxODE1NTM0M1oXDTM2MDcxNTE1NTM0M1owGDEW
      |MBQGA1UEAwwNdGVzdC1jbGllbnQtMjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCC
      |AQoCggEBANpgqaEICzbK790bUCOkY3Tzo6RgZEJ2XCKtjf74LjoQPRQROXZ1rHSf
      |fXfs1mhtv34h1uDFHGlKJ3m/CftcOrniuUk2Y8dsy+eWLbzo9CIloGHN/25w1uW0
      |2+nhZ8lQ577+vco4UaX8g4owvH28AIC9GBZQys1UR2C3YQRs5qj1DvAmg0tqDRlK
      |NmdDS+TMnMhll7djkx9E8H8Dm/ZBZx+NKjBwo0SX32FfYp5xwvA1thySoFSH+HVE
      |k5aI0ekmS/SHydq9OE5xRFhPpDHrWLCFBKTFonPZs54iNtu2SvzbP0NSPD6MheEW
      |2bPyphxWravvReR07F++TlbUDlo08IUCAwEAATANBgkqhkiG9w0BAQsFAAOCAQEA
      |oRdjrlhCIUIE0sid+dl646RVyGWL/q93TrFeSET62jK/xHPtalnX7yYiI93N8hyM
      |H2dZ0HVe8kXzUYHMpEP4J8z7pLZStlQbBsEjFIWR1W+vPZGv1KZr4d9SAAsuxIye
      |h9E+hD2h++UjBeaewRzUiSG/EvFmFGFcWRi+U+xUImR6ObqbM7f7LWWrm9/90ve8
      |5tY3we+sO/zYJTtTVeJC+DNblOIon9qboK6l26dJKKAVEdrzfA3j9NajalpWoDiS
      |zbcb3RBs2ZVn70q7pcTL8s11MaRAmxDDGAXe28sRppqFE5gc+ZzQYpEVENqrIZj/
      |xdOwIUR9a+oAyaTs/Nz7EQ==
      |-----END CERTIFICATE-----""".stripMargin

  private val headerName = "X-SSL-Client-Cert"

  private def config(mtlsEnabled: Boolean): OidcConfig = OidcConfig(
    issuer = "http://localhost:9000/obp-oidc",
    server = ServerConfig("localhost", 9000),
    database = DatabaseConfig("localhost", 5432, "test", "test", "test"),
    adminDatabase =
      DatabaseConfig("localhost", 5432, "test", "test_admin", "test_admin"),
    mtlsEnabled = mtlsEnabled,
    mtlsClientCertHeader = headerName
  )

  test("extractPresentedCertificate returns None when mTLS is disabled, even with a valid header") {
    val service = MtlsService(config(mtlsEnabled = false))
    val req = org.http4s.Request[cats.effect.IO](org.http4s.Method.GET, org.http4s.Uri.unsafeFromString("/obp-oidc/token"))
      .putHeaders(Header.Raw(CIString(headerName), URLEncoder.encode(certPem1, "UTF-8")))

    service.extractPresentedCertificate(req) shouldBe None
  }

  test("extractPresentedCertificate returns None when the header is absent") {
    val service = MtlsService(config(mtlsEnabled = true))
    val req = org.http4s.Request[cats.effect.IO](org.http4s.Method.GET, org.http4s.Uri.unsafeFromString("/obp-oidc/token"))

    service.extractPresentedCertificate(req) shouldBe None
  }

  test("extractPresentedCertificate parses a URL-encoded PEM header") {
    val service = MtlsService(config(mtlsEnabled = true))
    val req = org.http4s.Request[cats.effect.IO](org.http4s.Method.GET, org.http4s.Uri.unsafeFromString("/obp-oidc/token"))
      .putHeaders(Header.Raw(CIString(headerName), URLEncoder.encode(certPem1, "UTF-8")))

    val result = service.extractPresentedCertificate(req)
    result.isDefined shouldBe true
    result.get.thumbprint should not be empty
  }

  test("extractPresentedCertificate parses a raw (non-encoded) PEM header") {
    val service = MtlsService(config(mtlsEnabled = true))
    val req = org.http4s.Request[cats.effect.IO](org.http4s.Method.GET, org.http4s.Uri.unsafeFromString("/obp-oidc/token"))
      .putHeaders(Header.Raw(CIString(headerName), certPem1))

    val result = service.extractPresentedCertificate(req)
    result.isDefined shouldBe true
  }

  test("extractPresentedCertificate returns None for garbage header content") {
    val service = MtlsService(config(mtlsEnabled = true))
    val req = org.http4s.Request[cats.effect.IO](org.http4s.Method.GET, org.http4s.Uri.unsafeFromString("/obp-oidc/token"))
      .putHeaders(Header.Raw(CIString(headerName), "not-a-certificate"))

    service.extractPresentedCertificate(req) shouldBe None
  }

  test("the same certificate always produces the same thumbprint (deterministic)") {
    val service = MtlsService(config(mtlsEnabled = true))
    def extract(): String = {
      val req = org.http4s.Request[cats.effect.IO](org.http4s.Method.GET, org.http4s.Uri.unsafeFromString("/obp-oidc/token"))
        .putHeaders(Header.Raw(CIString(headerName), certPem1))
      service.extractPresentedCertificate(req).get.thumbprint
    }
    extract() shouldBe extract()
  }

  test("different certificates produce different thumbprints") {
    val service = MtlsService(config(mtlsEnabled = true))
    def extract(pem: String): String = {
      val req = org.http4s.Request[cats.effect.IO](org.http4s.Method.GET, org.http4s.Uri.unsafeFromString("/obp-oidc/token"))
        .putHeaders(Header.Raw(CIString(headerName), pem))
      service.extractPresentedCertificate(req).get.thumbprint
    }
    extract(certPem1) should not equal extract(certPem2)
  }

  test("verifyClientCertificate accepts a matching registered certificate") {
    val service = MtlsService(config(mtlsEnabled = true))
    val req = org.http4s.Request[cats.effect.IO](org.http4s.Method.GET, org.http4s.Uri.unsafeFromString("/obp-oidc/token"))
      .putHeaders(Header.Raw(CIString(headerName), certPem1))
    val presented = service.extractPresentedCertificate(req).get

    service.verifyClientCertificate(presented, certPem1) shouldBe Right(())
  }

  test("verifyClientCertificate rejects a non-matching registered certificate") {
    val service = MtlsService(config(mtlsEnabled = true))
    val req = org.http4s.Request[cats.effect.IO](org.http4s.Method.GET, org.http4s.Uri.unsafeFromString("/obp-oidc/token"))
      .putHeaders(Header.Raw(CIString(headerName), certPem1))
    val presented = service.extractPresentedCertificate(req).get

    service.verifyClientCertificate(presented, certPem2).isLeft shouldBe true
  }

  test("verifyClientCertificate rejects an unparseable registered certificate") {
    val service = MtlsService(config(mtlsEnabled = true))
    val req = org.http4s.Request[cats.effect.IO](org.http4s.Method.GET, org.http4s.Uri.unsafeFromString("/obp-oidc/token"))
      .putHeaders(Header.Raw(CIString(headerName), certPem1))
    val presented = service.extractPresentedCertificate(req).get

    service.verifyClientCertificate(presented, "not-a-pem-certificate").isLeft shouldBe true
  }
}
