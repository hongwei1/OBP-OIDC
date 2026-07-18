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
import com.tesobe.oidc.config.OidcConfig
import com.tesobe.oidc.models.OidcError
import org.http4s.Request
import org.typelevel.ci.CIString
import org.slf4j.LoggerFactory

import java.io.ByteArrayInputStream
import java.net.URLDecoder
import java.security.MessageDigest
import java.security.cert.{CertificateFactory, X509Certificate}
import java.util.Base64
import scala.util.Try

/** A parsed mTLS client certificate plus its RFC 8705 x5t#S256 thumbprint
  * (SHA-256 over the DER encoding, base64url, used both to match against a
  * client's registered certificate and as the cnf claim on sender-constrained
  * access tokens).
  */
case class MtlsCertificate(certificate: X509Certificate, thumbprint: String)

/** FAPI 1.0 Advanced tls_client_auth + sender-constrained access tokens
  * (RFC 8705). OBP-OIDC does not terminate TLS itself — the client
  * certificate is read from a header set by a trusted reverse proxy that
  * does terminate it. This is only as safe as that proxy: it must be
  * configured to always overwrite this header from client-supplied values
  * and only forward it when the TLS handshake actually presented and
  * validated a client certificate. mtlsEnabled defaults to false.
  */
trait MtlsService[F[_]] {
  def extractPresentedCertificate(req: Request[IO]): Option[MtlsCertificate]

  def verifyClientCertificate(
      presented: MtlsCertificate,
      registeredCertificatePem: String
  ): Either[OidcError, Unit]
}

class DefaultMtlsService(config: OidcConfig) extends MtlsService[IO] {

  private val logger = LoggerFactory.getLogger(getClass)
  private val certificateFactory = CertificateFactory.getInstance("X.509")

  def extractPresentedCertificate(req: Request[IO]): Option[MtlsCertificate] = {
    if (!config.mtlsEnabled) None
    else
      req.headers.get(CIString(config.mtlsClientCertHeader)).flatMap { header =>
        val raw = header.head.value
        // Reverse proxies commonly URL-encode the PEM (e.g. nginx $ssl_client_escaped_cert).
        // URL-decoding an already-raw PEM would silently corrupt it: '+' (common in
        // base64 bodies) decodes to a space, and URLDecoder rarely throws on plain text,
        // so a try/catch fallback can't detect this. A raw, already-unescaped PEM always
        // contains literal newlines between its base64 lines; an encoded one never does
        // (real newlines become %0A) — that presence is the reliable signal to use.
        val decoded =
          if (raw.contains('\n') || raw.contains('\r')) raw
          else Try(URLDecoder.decode(raw, "UTF-8")).getOrElse(raw)
        val parsed = parseCertificate(decoded)
        if (parsed.isEmpty) {
          logger.warn(s"Could not parse client certificate from header ${config.mtlsClientCertHeader}")
        }
        parsed
      }
  }

  private def parseCertificate(pem: String): Option[MtlsCertificate] = {
    Try {
      val cert = certificateFactory
        .generateCertificate(new ByteArrayInputStream(pem.getBytes("UTF-8")))
        .asInstanceOf[X509Certificate]
      MtlsCertificate(cert, thumbprint(cert))
    }.toOption
  }

  private def thumbprint(cert: X509Certificate): String = {
    val digest = MessageDigest.getInstance("SHA-256").digest(cert.getEncoded)
    Base64.getUrlEncoder.withoutPadding.encodeToString(digest)
  }

  def verifyClientCertificate(
      presented: MtlsCertificate,
      registeredCertificatePem: String
  ): Either[OidcError, Unit] = {
    parseCertificate(registeredCertificatePem) match {
      case None =>
        Left(OidcError("invalid_client", Some("Client's registered certificate is not parseable")))
      case Some(registered) if registered.thumbprint == presented.thumbprint =>
        Right(())
      case Some(_) =>
        Left(OidcError("invalid_client", Some("Presented client certificate does not match the registered certificate")))
    }
  }
}

object MtlsService {
  def apply(config: OidcConfig): MtlsService[IO] = new DefaultMtlsService(config)
}
