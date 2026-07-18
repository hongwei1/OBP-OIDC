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

import cats.effect.{IO, Ref, Resource}
import com.nimbusds.jose.jwk.JWKSet
import org.http4s.Uri
import org.http4s.client.Client
import org.http4s.ember.client.EmberClientBuilder
import org.slf4j.LoggerFactory

import java.time.Instant
import scala.concurrent.duration._

/** Fetches and caches a client's JWKS document (RFC 7517), keyed by its
  * jwks_uri. Used to verify signed request objects (JAR / RFC 9101) and
  * private_key_jwt client assertions against the client's own public key —
  * OBP-OIDC never stores a client's private key, only its published JWKS.
  */
trait JwksClient[F[_]] {
  def fetch(jwksUri: String): F[Either[String, JWKSet]]
}

class HttpJwksClient(
    httpClient: Client[IO],
    cacheRef: Ref[IO, Map[String, (JWKSet, Instant)]],
    ttl: FiniteDuration
) extends JwksClient[IO] {

  private val logger = LoggerFactory.getLogger(getClass)

  def fetch(jwksUri: String): IO[Either[String, JWKSet]] = {
    for {
      cache <- cacheRef.get
      now = Instant.now()
      result <- cache.get(jwksUri) match {
        case Some((jwks, fetchedAt)) if fetchedAt.plusSeconds(ttl.toSeconds).isAfter(now) =>
          IO.pure(Right(jwks))
        case _ =>
          fetchAndCache(jwksUri, now)
      }
    } yield result
  }

  private def fetchAndCache(jwksUri: String, now: Instant): IO[Either[String, JWKSet]] = {
    IO.fromEither(Uri.fromString(jwksUri).left.map(e => new RuntimeException(e.message)))
      .flatMap(httpClient.expect[String](_))
      .attempt
      .flatMap {
        case Right(body) =>
          IO(JWKSet.parse(body)).attempt.flatMap {
            case Right(jwks) =>
              cacheRef.update(_ + (jwksUri -> (jwks, now))).as(Right(jwks))
            case Left(error) =>
              logger.warn(s"Failed to parse JWKS from $jwksUri: ${error.getMessage}")
              IO.pure(Left(s"Invalid JWKS document at $jwksUri"))
          }
        case Left(error) =>
          logger.warn(s"Failed to fetch JWKS from $jwksUri: ${error.getMessage}")
          IO.pure(Left(s"Could not fetch JWKS from $jwksUri"))
      }
  }
}

object JwksClient {
  private val defaultTtl = 10.minutes

  def create(): Resource[IO, JwksClient[IO]] = {
    for {
      httpClient <- EmberClientBuilder.default[IO].build
      cacheRef <- Resource.eval(Ref.of[IO, Map[String, (JWKSet, Instant)]](Map.empty))
    } yield new HttpJwksClient(httpClient, cacheRef, defaultTtl)
  }
}
