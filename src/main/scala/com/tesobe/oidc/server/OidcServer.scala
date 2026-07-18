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

package com.tesobe.oidc.server

import scala.language.higherKinds
import scala.io.Source
import cats.effect.{ExitCode, IO, IOApp}
import cats.syntax.all._
import cats.data.Kleisli
import com.comcast.ip4s.{Host, Port}
import cats.effect.Ref
import org.typelevel.ci._
import com.tesobe.oidc.auth.{CodeService, ParService, JwksClient, RequestObjectService, ClientAssertionService, HybridAuthService, DatabaseClient, ObpApiCredentialsService, ObpApiClientService}
import com.tesobe.oidc.models.{ConsentChallenge, OidcClient}
import com.tesobe.oidc.bootstrap.ClientBootstrap
import com.tesobe.oidc.config.{Config, OidcConfig, VerifyCredentialsMethod, VerifyClientMethod}
import com.tesobe.oidc.endpoints._
import com.tesobe.oidc.tokens.JwtService
import com.tesobe.oidc.stats.StatsService
import com.tesobe.oidc.status.StatusService
import com.tesobe.oidc.ratelimit.{RateLimitConfig, InMemoryRateLimitService}
import com.tesobe.oidc.revocation.InMemoryTokenRevocationService
import org.http4s._
import org.http4s.ember.server.EmberServerBuilder
import org.http4s.implicits._
import org.http4s.server.Router

import scala.concurrent.duration._

object OidcServer extends IOApp {

  import HtmlUtils.htmlEncode

  private def withSecurityHeaders(app: HttpApp[IO]): HttpApp[IO] =
    Kleisli { req =>
      app.run(req).map { resp =>
        resp.putHeaders(
          Header.Raw(ci"X-Content-Type-Options", "nosniff"),
          Header.Raw(ci"X-Frame-Options", "DENY"),
          Header.Raw(ci"Referrer-Policy", "no-referrer"),
          Header.Raw(ci"Content-Security-Policy", "frame-ancestors 'none'")
        )
      }
    }

  private def retryWithBackoff(
      action: IO[Either[String, String]],
      description: String,
      maxAttempts: Int,
      delay: FiniteDuration
  ): IO[String] = {
    def attempt(n: Int, lastError: String): IO[String] = {
      if (n > maxAttempts) {
        IO.raiseError(
          new RuntimeException(
            s"OBP API ($description) not available after $maxAttempts attempts. Last error: $lastError"
          )
        )
      } else {
        action
          .handleErrorWith { ex =>
            IO.pure(Left(s"${ex.getClass.getSimpleName}: ${ex.getMessage}"))
          }
          .flatMap {
            case Right(msg) => IO.pure(msg)
            case Left(error) =>
              if (n < maxAttempts) {
                IO(
                  println(
                    s"Waiting for OBP API ($description): $error. Retrying in ${delay.toSeconds}s (attempt $n/$maxAttempts)..."
                  )
                ) *> IO.sleep(delay) *> attempt(n + 1, error)
              } else {
                IO.raiseError(
                  new RuntimeException(
                    s"OBP API ($description) not available after $maxAttempts attempts. Last error: $error"
                  )
                )
              }
          }
      }
    }
    attempt(1, "no attempts made")
  }

  def run(args: List[String]): IO[ExitCode] = {
    // Check for developer helper commands
    args.headOption match {
      case Some("--generate-config") | Some("--config") =>
        generateDeveloperConfig()
      case Some("--generate-db-config") | Some("--db-config") =>
        generateDatabaseConfig()
      case Some("--help") | Some("-h") =>
        printHelp()
      case _ =>
        startServer(args)
    }
  }

  private def startServer(args: List[String]): IO[ExitCode] = {
    for {
      config <- Config.load
      _ <- IO(
        println(
          s"Starting OIDC Provider on ${config.server.host}:${config.server.port}"
        )
      )
      _ <- IO(println(s"Issuer: ${config.issuer}"))
      _ <- IO(println(s"needsDatabase: ${config.needsDatabase}"))

      // Test database connections (only if database is needed)
      _ <- if (config.needsDatabase) {
        config.verifyCredentialsMethod match {
          case VerifyCredentialsMethod.ViaOidcUsersView =>
            HybridAuthService.testConnection(config).flatMap {
              case Right(msg) => IO(println(msg))
              case Left(error) =>
                IO.raiseError(
                  new RuntimeException(s"User database connection failed: $error")
                )
            }
          case VerifyCredentialsMethod.ViaApiEndpoint =>
            IO(println("Skipping v_oidc_users view test (using OBP API for credential validation)"))
        }
      } else {
        val username = config.obpApiUsername.getOrElse("unknown")
        IO {
          println("No database connection required. Reason:")
          println(s"   OIDC_SKIP_CLIENT_BOOTSTRAP=true")
          println(s"   USE_VERIFY_ENDPOINTS=true")
          println(s"     -> Credentials verified via OBP API (requires OBP_API_USERNAME '$username' to have role CanVerifyUserCredentials)")
          println(s"     -> User lookup via OBP API (requires OBP_API_USERNAME '$username' to have role CanGetAnyUser)")
          println(s"     -> Clients verified via OBP API (requires OBP_API_USERNAME '$username' to have role CanGetOidcClient)")
          println(s"     -> Consumers listed via OBP API (requires OBP_API_USERNAME '$username' to have role CanGetConsumers)")
          println(s"     -> Providers listed via OBP API (GET /obp/v6.0.0/providers - no special role required, just authentication)")
        }
      }

      _ <- if (config.needsDatabase) {
        HybridAuthService.testClientConnection(config).flatMap {
          case Right(msg) => IO(println(msg))
          case Left(error) =>
            IO(
              println(s"Client database warning: $error (using permissive mode)")
            )
        }
      } else IO.unit

      _ <- if (config.needsDatabase) {
        HybridAuthService.testAdminConnection(config).flatMap {
          case Right(msg) => IO(println(msg))
          case Left(error) =>
            IO(
              println(
                s"Admin database warning: $error (client management features disabled)"
              )
            )
        }
      } else IO.unit

      // Test OBP API connection and verify all required roles
      roleCheckRef <- cats.effect.Ref.of[IO, Option[ObpApiCredentialsService.RoleCheckResult]](None)
      _ <- {
        val requiredRoles = List.empty[String] ++
          (config.verifyCredentialsMethod match {
            case VerifyCredentialsMethod.ViaApiEndpoint => List("CanVerifyUserCredentials", "CanGetAnyUser")
            case _ => List.empty
          }) ++
          (config.verifyClientMethod match {
            case VerifyClientMethod.ViaApiEndpoint =>
              val base = List("CanGetOidcClient", "CanVerifyOidcClient", "CanGetConsumers")
              val createConsumer =
                if (config.enableDynamicClientRegistration || !config.skipClientBootstrap)
                  List("CanCreateConsumer")
                else Nil
              base ++ createConsumer
            case _ => List.empty
          })

        if (requiredRoles.nonEmpty) {
          // Step 1: Verify OBP API connectivity (with retry/backoff for when OBP-API is starting up)
          retryWithBackoff(
            ObpApiCredentialsService.testConnection(config),
            "OBP API connection",
            config.obpApiRetryMaxAttempts,
            config.obpApiRetryDelaySeconds.seconds
          ).flatMap(msg => IO(println(msg))) *>
          // Step 2: Check all required roles (abort immediately if any are missing)
          ObpApiCredentialsService.checkRequiredRoles(config, requiredRoles).flatMap {
            case Right(roleCheck) =>
              val username = config.obpApiUsername.getOrElse("unknown")
              val baseUrl = config.obpApiUrl.getOrElse("unknown")
              roleCheckRef.set(Some(roleCheck)) *>
              (if (roleCheck.allPresent) {
                IO(println(s"Role check passed: OBP API user '$username' has all ${requiredRoles.size} required roles"))
              } else {
                IO.raiseError(new RuntimeException(
                  s"STARTUP ABORTED: OBP API user '$username' is missing required role(s): ${roleCheck.missing.mkString(", ")}. " +
                  s"Please grant these roles to user '$username' at $baseUrl and restart."
                ))
              })
            case Left(error) => IO.raiseError(new RuntimeException(error))
          }
        } else {
          IO.unit
        }
      }

      exitCode <- HybridAuthService.create(config).use { authService =>
        for {
          // Initialize standard OBP ecosystem clients (create-only mode)
          _ <- IO(
            println(
              "DEBUG: Starting ClientBootstrap initialization (create-only mode)..."
            )
          )
          _ <- IO(println("Starting ClientBootstrap initialization..."))
          _ <- IO
            .race(
              IO.sleep(15.seconds),
              ClientBootstrap.initialize(authService, config)
            )
            .flatMap {
              case Left(_) =>
                IO(
                  println(
                    "DEBUG: Client initialization TIMED OUT after 15 seconds"
                  )
                )
                IO(
                  println(
                    "Client initialization timed out after 15 seconds - continuing server startup"
                  )
                )
              case Right(_) =>
                IO(
                  println(
                    "DEBUG: Client initialization completed successfully"
                  )
                )
                IO(println("Client initialization completed successfully"))
            }
            .handleErrorWith { error =>
              IO(
                println(
                  s"DEBUG: Client initialization FAILED with error: ${error.getClass.getSimpleName}: ${error.getMessage}"
                )
              )
              IO(
                println(
                  s"Client initialization failed: ${error.getMessage} - continuing server startup"
                )
              )
              IO(error.printStackTrace())
            }

          // Initialize services
          codeService <- CodeService(config)
          parService <- ParService(config)
          jwksClient <- JwksClient.create().allocated.map(_._1)
          requestObjectService = RequestObjectService(authService, jwksClient, config)
          clientAssertionService <- ClientAssertionService.create(authService, jwksClient)
          jwtService <- JwtService(config)
          statsService <- StatsService()
          statusService <- StatusService
            .create(config, jwtService)
            .allocated
            .map(_._1)
          rateLimitConfig = RateLimitConfig.fromEnv
          rateLimitService <- InMemoryRateLimitService(rateLimitConfig)
          revocationService <- InMemoryTokenRevocationService(
            maxTokenLifetimeSeconds =
              config.tokenExpirationSeconds * 720, // Match refresh token lifetime
            cleanupIntervalMinutes = 60 // Cleanup every hour
          )

          _ <- IO(
            println(
              s"Rate limiting enabled: ${rateLimitConfig.maxAttemptsPerIP} attempts per IP, ${rateLimitConfig.maxAttemptsPerUsername} attempts per username"
            )
          )
          _ <- IO(println("Token revocation service initialized"))

          // Initialize endpoints
          consentChallengesRef <- Ref.of[IO, Map[String, ConsentChallenge]](Map.empty)
          discoveryEndpoint = DiscoveryEndpoint(config)
          jwksEndpoint = JwksEndpoint(jwtService)
          authEndpoint = AuthEndpoint(
            authService,
            codeService,
            statsService,
            rateLimitService,
            config,
            jwtService,
            consentChallengesRef,
            parService,
            requestObjectService
          )
          parEndpoint = ParEndpoint(authService, parService, config)
          tokenEndpoint = TokenEndpoint(
            authService,
            codeService,
            jwtService,
            config,
            statsService,
            clientAssertionService
          )
          userInfoEndpoint = UserInfoEndpoint(authService, jwtService)
          revocationEndpoint = RevocationEndpoint(
            authService,
            revocationService,
            config
          )
          clientsEndpoint = ClientsEndpoint(authService)
          statsEndpoint = StatsEndpoint(statsService, config)
          statusEndpoint = StatusEndpoint(statusService)
          staticFilesEndpoint = StaticFilesEndpoint()
          registrationEndpoint = if (config.enableDynamicClientRegistration) {
            Some(RegistrationEndpoint(
              authService,
              rateLimitService,
              config
            ))
          } else None

          _ <- if (config.enableDynamicClientRegistration) 
                 IO(println("Dynamic Client Registration endpoint initialized (enabled)"))
               else 
                 IO(println("Dynamic Client Registration endpoint disabled"))

          // Create all routes in a single HttpRoutes definition
          routes = {
            import org.http4s.dsl.io._

            HttpRoutes
              .of[IO] {
                // Static files - always available
                case req @ GET -> Root / "static" / "css" / _ =>
                  staticFilesEndpoint.routes.run(req).value.flatMap {
                    case Some(response) => IO.pure(response)
                    case None           => NotFound("CSS file not found")
                  }

                // Machine-friendly liveness probe - always available
                case GET -> Root / "health" =>
                  Ok("""{"status":"ok"}""")
                    .map(
                      _.withContentType(
                        org.http4s.headers.`Content-Type`(MediaType.application.json)
                      )
                    )

                // Public status page - always available
                case req @ GET -> Root / "status" =>
                  statusEndpoint.routes.run(req).value.flatMap {
                    case Some(resp) => IO.pure(resp)
                    case None       => NotFound("Status endpoint not found")
                  }

                case req @ GET -> Root / "status.json" =>
                  statusEndpoint.routes.run(req).value.flatMap {
                    case Some(resp) => IO.pure(resp)
                    case None       => NotFound("Status endpoint not found")
                  }

                // Root page - simple landing with links - always available
                case GET -> Root =>
                  val modeStatus =
                    if (config.localDevelopmentMode) "Local Development Mode"
                    else "Production"
                  val modeBadgeColor =
                    if (config.localDevelopmentMode) "#ff9800" else "#26a69a"
                  val modeClass =
                    if (config.localDevelopmentMode) "mode-development"
                    else "mode-production"
                  Ok(s"""<!DOCTYPE html>
                     |<html>
                     |<head>
                     |  <title>OBP OIDC Provider</title>
                     |  <meta name="viewport" content="width=device-width, initial-scale=1.0">
                     |  <link rel="stylesheet" href="/static/css/main.css">
                     |  <style>
                     |    body {
                     |      min-height: 100vh;
                     |      display: flex;
                     |      align-items: center;
                     |      justify-content: center;
                     |    }
                     |    .container {
                     |      max-width: 700px;
                     |      padding: 50px 40px;
                     |      text-align: center;
                     |    }
                     |    .links {
                     |      display: grid;
                     |      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                     |      gap: 15px;
                     |      margin: 30px 0;
                     |    }
                     |    .links a {
                     |      display: block;
                     |      background: #f8f9fa;
                     |      color: #2c3e50;
                     |      text-decoration: none;
                     |      padding: 20px;
                     |      border-radius: 6px;
                     |      font-weight: 600;
                     |      font-size: 1rem;
                     |      transition: all 0.2s;
                     |      border-left: 4px solid #26a69a;
                     |    }
                     |    .links a:hover {
                     |      background: #26a69a;
                     |      color: white;
                     |      transform: translateY(-2px);
                     |      box-shadow: 0 4px 12px rgba(38, 166, 154, 0.3);
                     |    }
                     |    @media (max-width: 600px) {
                     |      .container {
                     |        padding: 30px 20px;
                     |      }
                     |      .links {
                     |        grid-template-columns: 1fr;
                     |      }
                     |    }
                     |  </style>
                     |</head>
                     |<body>
                     |  <div class="container">
                     |    <h1>OBP OIDC Provider</h1>
                     |    <p class="subtitle">OpenID Connect Authentication Server</p>
                     |    <div class="mode-indicator $modeClass">$modeStatus</div>
                     |    <div class="links">
                     |      <a href="/info">Server Info</a>
                     |      <a href="/health">Health Check</a>
                     |      <a href="/status">Status</a>
                     |    </div>
                     |    <div class="version">
                     |      <strong>Version:</strong> v${readVersion()} (${readGitCommit()})
                     |    </div>
                     |  </div>
                     |</body>
                     |</html>""".stripMargin)
                    .map(
                      _.withContentType(
                        org.http4s.headers.`Content-Type`(MediaType.text.html)
                      )
                    )

                // Info page - detailed server information
                case GET -> Root / "info" if config.localDevelopmentMode =>
                  for {
                    clientsResult <- if (config.needsDatabase) authService.listClients()
                      else IO.pure(Right(List.empty[OidcClient]))
                    // Check credential validation method and role status
                    credentialValidationInfo <- config.verifyCredentialsMethod match {
                      case VerifyCredentialsMethod.ViaApiEndpoint =>
                        ObpApiCredentialsService.testConnection(config).map {
                          case Right(msg) =>
                            val hasRole = msg.contains("User has CanVerifyUserCredentials role")
                            val username = config.obpApiUsername.getOrElse("unknown")
                            val roleStatus = if (hasRole) {
                              """<span style="color: #4caf50; font-weight: 600;">Yes</span>"""
                            } else {
                              """<span style="color: #f44336; font-weight: 600;">No</span>"""
                            }
                            s"""
                              |<div class="info-card" style="border-left-color: #2196f3;">
                              |  <strong>Credential Verification Method</strong>
                              |  verify_credentials_endpoint (OBP API)
                              |</div>
                              |<div class="info-card" style="border-left-color: #2196f3;">
                              |  <strong>OBP API Username</strong>
                              |  $username
                              |</div>
                              |<div class="info-card" style="border-left-color: #2196f3;">
                              |  <strong>Has CanVerifyUserCredentials Role</strong>
                              |  $roleStatus
                              |</div>""".stripMargin
                          case Left(_) =>
                            val username = config.obpApiUsername.getOrElse("unknown")
                            s"""
                              |<div class="info-card" style="border-left-color: #f44336;">
                              |  <strong>Credential Verification Method</strong>
                              |  verify_credentials_endpoint (OBP API)
                              |</div>
                              |<div class="info-card" style="border-left-color: #f44336;">
                              |  <strong>OBP API Username</strong>
                              |  $username
                              |</div>
                              |<div class="info-card" style="border-left-color: #f44336;">
                              |  <strong>OBP API Connection</strong>
                              |  <span style="color: #f44336; font-weight: 600;">Failed</span>
                              |</div>""".stripMargin
                        }
                      case VerifyCredentialsMethod.ViaOidcUsersView =>
                        IO.pure(s"""
                          |<div class="info-card">
                          |  <strong>Credential Verification Method</strong>
                          |  v_oidc_users (database view)
                          |</div>""".stripMargin)
                    }
                    appsSection = clientsResult match {
                      case Right(clients) if clients.nonEmpty =>
                        val clientsWithRedirects =
                          clients.filter(_.redirect_uris.nonEmpty)
                        val clientsHtml = clientsWithRedirects
                          .map { client =>
                            val redirectUrlsList =
                              client.redirect_uris
                                .map { url =>
                                  val baseUrl =
                                    try {
                                      val uri = new java.net.URI(url)
                                      s"${uri.getScheme}://${uri.getHost}${if (uri.getPort > 0)
                                          s":${uri.getPort}"
                                        else ""}"
                                    } catch {
                                      case _: Exception => url
                                    }
                                  baseUrl
                                }
                                .distinct
                                .map(url =>
                                  s"""<a href="${htmlEncode(url)}" target="_blank" rel="noopener noreferrer">${htmlEncode(url)}</a>"""
                                )
                                .mkString(", ")
                            s"""<div class="app">${htmlEncode(client.client_name)}: $redirectUrlsList</div>"""
                          }
                          .mkString("")
                        s"""
                           |<h2>Apps</h2>
                           |<div class="apps-section">
                           |  $clientsHtml
                           |</div>""".stripMargin
                      case Right(_) =>
                        """
                           |<h2>Apps</h2>
                           |<div class="apps-section">
                           |  <p><em>No applications registered</em></p>
                           |</div>""".stripMargin
                      case Left(_) =>
                        """
                           |<h2>Apps</h2>
                           |<div class="apps-section">
                           |  <p><em>Unable to load applications</em></p>
                           |</div>""".stripMargin
                    }
                    response <- Ok(s"""<!DOCTYPE html>
                       |<html>
                       |<head>
                       |  <title>OBP OIDC Provider - Server Info</title>
                       |  <meta name="viewport" content="width=device-width, initial-scale=1.0">
                       |  <style>
                       |    * { margin: 0; padding: 0; box-sizing: border-box; }
                       |    body {
                       |      font-family: "Plus Jakarta Sans", -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
                       |      background: #f8f9fa;
                       |      color: #2c3e50;
                       |      line-height: 1.6;
                       |      padding: 20px;
                       |    }
                       |    .container {
                       |      max-width: 1200px;
                       |      margin: 0 auto;
                       |      background: white;
                       |      border-radius: 8px;
                       |      box-shadow: 0 2px 8px rgba(0,0,0,0.1);
                       |      padding: 40px;
                       |    }
                       |    h1 {
                       |      color: #1a1a1a;
                       |      font-size: 2.5rem;
                       |      font-weight: 700;
                       |      margin-bottom: 10px;
                       |      letter-spacing: -0.02em;
                       |    }
                       |    .subtitle {
                       |      color: #666;
                       |      font-size: 1.1rem;
                       |      margin-bottom: 30px;
                       |    }
                       |    h2 {
                       |      color: #2c3e50;
                       |      font-size: 1.5rem;
                       |      font-weight: 600;
                       |      margin-top: 40px;
                       |      margin-bottom: 20px;
                       |      padding-bottom: 10px;
                       |      border-bottom: 2px solid #e9ecef;
                       |    }
                       |    .info-grid {
                       |      display: grid;
                       |      grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
                       |      gap: 20px;
                       |      margin-bottom: 20px;
                       |    }
                       |    .info-card {
                       |      background: #f8f9fa;
                       |      padding: 20px;
                       |      border-radius: 6px;
                       |      border-left: 4px solid #26a69a;
                       |    }
                       |    .info-card strong {
                       |      display: block;
                       |      color: #2c3e50;
                       |      margin-bottom: 5px;
                       |      font-weight: 600;
                       |    }
                       |    ul {
                       |      list-style: none;
                       |      padding: 0;
                       |    }
                       |    li {
                       |      padding: 12px 0;
                       |      border-bottom: 1px solid #e9ecef;
                       |    }
                       |    li:last-child { border-bottom: none; }
                       |    li strong {
                       |      color: #2c3e50;
                       |      font-weight: 600;
                       |    }
                       |    code {
                       |      background: #f1f3f5;
                       |      padding: 2px 8px;
                       |      border-radius: 4px;
                       |      font-family: 'Monaco', 'Courier New', monospace;
                       |      font-size: 0.9em;
                       |      color: #c7254e;
                       |    }
                       |    a {
                       |      color: #26a69a;
                       |      text-decoration: none;
                       |      font-weight: 500;
                       |    }
                       |    a:hover {
                       |      text-decoration: underline;
                       |      color: #1f8a7e;
                       |    }
                       |    .apps-section { margin: 20px 0; }
                       |    .app {
                       |      background: #f8f9fa;
                       |      padding: 15px;
                       |      margin: 10px 0;
                       |      border-radius: 6px;
                       |      border-left: 4px solid #26a69a;
                       |      word-break: break-all;
                       |    }
                       |    .version-badge {
                       |      display: inline-block;
                       |      background: #26a69a;
                       |      color: white;
                       |      padding: 6px 12px;
                       |      border-radius: 20px;
                       |      font-size: 0.9rem;
                       |      font-weight: 600;
                       |      margin-bottom: 20px;
                       |    }
                       |  </style>
                       |</head>
                       |<body>
                       |<div class="container">
                       |<h1>OBP OIDC Provider</h1>
                       |<p class="subtitle">OpenID Connect Authentication Server</p>
                       |<div class="version-badge">Version: v${readVersion()} (${readGitCommit()})</div>
                       |<h2>Configuration</h2>
                       |<div class="info-grid">
                       |  <div class="info-card">
                       |    <strong>Access Token Lifetime</strong>
                       |    ${config.tokenExpirationSeconds} seconds (${config.tokenExpirationSeconds / 60} minutes)
                       |  </div>
                       |  <div class="info-card">
                       |    <strong>Authorization Code Lifetime</strong>
                       |    ${config.codeExpirationSeconds} seconds (${config.codeExpirationSeconds / 60} minutes)
                       |  </div>
                       |  <div class="info-card">
                       |    <strong>Refresh Token Lifetime</strong>
                       |    ${config.tokenExpirationSeconds * 720} seconds (~${config.tokenExpirationSeconds * 720 / 86400} days)
                       |  </div>
                       |  $credentialValidationInfo
                       |</div>
                       |<h2>SQL Views</h2>
                       |<ul>
                       |<li><code>v_oidc_users</code> - User authentication (read-only) - connected to by <strong>${config.database.username}</strong></li>
                       |<li><code>v_oidc_clients</code> - Client validation (read-only) - connected to by <strong>${config.database.username}</strong></li>
                       |<li><code>v_oidc_admin_clients</code> - Client management (read-write) - connected to by <strong>${config.adminDatabase.username}</strong></li>
                       |</ul>
                       |<h2>OIDC Endpoints</h2>
                       |<div style="background: #e8f5e9; padding: 15px; border-radius: 6px; border-left: 4px solid #4caf50; margin-bottom: 15px;">
                       |  <strong>Well Known Endpoint for Discovery (Start Here):</strong><br>
                       |  <a href="/obp-oidc/.well-known/openid-configuration" style="font-size: 1.1em;">${config.issuer}/.well-known/openid-configuration</a><br>
                       |  <span style="font-size: 0.9em; color: #666;">This endpoint describes all other OIDC endpoints and capabilities</span>
                       |</div>
                       |<ul>
                       |<li><strong>/obp-oidc/auth</strong> - Authorization endpoint (OAuth 2.0 authorization code flow)</li>
                       |<li><strong>/obp-oidc/token</strong> - Token endpoint (supports <code>authorization_code</code> and <code>refresh_token</code> grants)</li>
                       |<li><strong>/obp-oidc/userinfo</strong> - UserInfo endpoint (get user profile with access token)</li>
                       |<li><strong>/obp-oidc/revoke</strong> - Revocation endpoint (RFC 7009 - revoke access/refresh tokens)</li>
                       |<li><a href="/obp-oidc/jwks">JWKS</a> - JSON Web Key Set (for token verification)</li>
                       |</ul>
                       |<h2>Admin Endpoints</h2>
                       |<ul>
                       |<li><a href="/info">Server Info</a> - This page</li>
                       |<li><a href="/clients">OIDC Clients</a> - View registered clients</li>
                       |<li><a href="/stats">Statistics</a> - Real-time usage statistics</li>
                       |<li><a href="/health">Health Check</a> - Service status</li>
                       |<li><a href="/status">Status</a> - Dependency health checks (OBP API, endpoints, databases)</li>
                       |</ul>
                       |<h2>Supported Grant Types</h2>
                       |<ul>
                       |<li><code>authorization_code</code> - Standard OIDC flow for web applications</li>
                       |<li><code>refresh_token</code> - Refresh access tokens without re-authentication</li>
                       |</ul>
                       |$appsSection
                       |</div>
                       |</body>
                       |</html>""".stripMargin)
                      .map(
                        _.withContentType(
                          org.http4s.headers.`Content-Type`(MediaType.text.html)
                        )
                      )
                  } yield response

                // OIDC Discovery
                case GET -> Root / "obp-oidc" / ".well-known" / "openid-configuration" =>
                  discoveryEndpoint.routes
                    .run(
                      org.http4s.Request[IO](
                        org.http4s.Method.GET,
                        org.http4s.Uri.unsafeFromString(
                          "/obp-oidc/.well-known/openid-configuration"
                        )
                      )
                    )
                    .value
                    .flatMap {
                      case Some(resp) => IO.pure(resp)
                      case None => NotFound("Discovery endpoint not found")
                    }

                case HEAD -> Root / "obp-oidc" / ".well-known" / "openid-configuration" =>
                  discoveryEndpoint.routes
                    .run(
                      org.http4s.Request[IO](
                        org.http4s.Method.HEAD,
                        org.http4s.Uri.unsafeFromString(
                          "/obp-oidc/.well-known/openid-configuration"
                        )
                      )
                    )
                    .value
                    .flatMap {
                      case Some(resp) => IO.pure(resp)
                      case None => NotFound("Discovery endpoint not found")
                    }

                // JWKS
                case GET -> Root / "obp-oidc" / "jwks" =>
                  jwksEndpoint.routes
                    .run(
                      org.http4s.Request[IO](
                        org.http4s.Method.GET,
                        org.http4s.Uri.unsafeFromString("/obp-oidc/jwks")
                      )
                    )
                    .value
                    .flatMap {
                      case Some(resp) => IO.pure(resp)
                      case None       => NotFound("JWKS endpoint not found")
                    }

                case HEAD -> Root / "obp-oidc" / "jwks" =>
                  jwksEndpoint.routes
                    .run(
                      org.http4s.Request[IO](
                        org.http4s.Method.HEAD,
                        org.http4s.Uri.unsafeFromString("/obp-oidc/jwks")
                      )
                    )
                    .value
                    .flatMap {
                      case Some(resp) => IO.pure(resp)
                      case None       => NotFound("JWKS endpoint not found")
                    }

                // Revocation endpoint
                case req @ POST -> Root / "obp-oidc" / "revoke" =>
                  revocationEndpoint.routes.run(req).value.flatMap {
                    case Some(resp) => IO.pure(resp)
                    case None       => NotFound("Revocation endpoint not found")
                  }

                // PAR (RFC 9126) endpoint
                case req @ POST -> Root / "obp-oidc" / "par" =>
                  parEndpoint.routes.run(req).value.flatMap {
                    case Some(resp) => IO.pure(resp)
                    case None       => NotFound("PAR endpoint not found")
                  }

                // Dynamic Client Registration endpoint (RFC 7591)
                case req @ POST -> Root / "obp-oidc" / "connect" / "register" =>
                  registrationEndpoint match {
                    case Some(endpoint) =>
                      IO(println("Dynamic Client Registration request received")) *>
                        endpoint.routes.run(req).value.flatMap {
                          case Some(resp) => IO.pure(resp)
                          case None       => NotFound("Registration endpoint not found")
                        }
                    case None =>
                      IO(println("Dynamic Client Registration request received but DCR is disabled")) *>
                        Forbidden("Dynamic Client Registration is disabled on this server")
                  }

                // Delegate other requests to endpoints
                case req =>
                  statsService.incrementTotalRequests *>
                    IO(
                      println(
                        s"Incoming request: ${req.method} ${req.uri} - Content-Type: ${req.headers.get[headers.`Content-Type`].map(_.mediaType).getOrElse("MISSING")}"
                      )
                    ) *>
                    authEndpoint.routes.run(req).value.flatMap {
                      case Some(resp) =>
                        IO(println(s"Request handled by AuthEndpoint")) *>
                          IO.pure(resp)
                      case None =>
                        IO(
                          println(
                            s"AuthEndpoint did not handle request, trying TokenEndpoint"
                          )
                        ) *>
                          tokenEndpoint.routes.run(req).value.flatMap {
                            case Some(resp) =>
                              IO(
                                println(s"Request handled by TokenEndpoint")
                              ) *>
                                IO.pure(resp)
                            case None =>
                              IO(
                                println(
                                  s"TokenEndpoint did not handle request, trying UserInfoEndpoint"
                                )
                              ) *>
                                userInfoEndpoint.routes.run(req).value.flatMap {
                                  case Some(resp) =>
                                    IO(
                                      println(
                                        s"Request handled by UserInfoEndpoint"
                                      )
                                    ) *>
                                      IO.pure(resp)
                                  case None =>
                                    IO(
                                      println(
                                        s"UserInfoEndpoint did not handle request, trying ClientsEndpoint"
                                      )
                                    ) *>
                                      (if (config.localDevelopmentMode) {
                                         clientsEndpoint.routes
                                           .run(req)
                                           .value
                                           .flatMap {
                                             case Some(resp) =>
                                               IO(
                                                 println(
                                                   s"Request handled by ClientsEndpoint"
                                                 )
                                               ) *>
                                                 IO.pure(resp)
                                             case None =>
                                               IO(
                                                 println(
                                                   s"ClientsEndpoint did not handle request, trying StatsEndpoint"
                                                 )
                                               ) *>
                                                 statsEndpoint.routes
                                                   .run(req)
                                                   .value
                                                   .flatMap {
                                                     case Some(resp) =>
                                                       IO(
                                                         println(
                                                           s"Request handled by StatsEndpoint"
                                                         )
                                                       ) *>
                                                         IO.pure(resp)
                                                     case None =>
                                                       IO(
                                                         println(
                                                           s"No endpoint handled the request: ${req.method} ${req.uri}"
                                                         )
                                                       ) *>
                                                         NotFound("OBP-OIDC: no route matches this request")
                                                   }
                                           }
                                       } else {
                                         IO(
                                           println(
                                             s"No endpoint handled the request: ${req.method} ${req.uri}"
                                           )
                                         ) *>
                                           NotFound("OBP-OIDC: no route matches this request")
                                       })
                                }
                          }
                    }
              }
              .orNotFound
          }

          // Start server
          host <- IO.fromOption(Host.fromString(config.server.host))(
            new RuntimeException(s"Invalid host: ${config.server.host}")
          )
          port <- IO.fromOption(Port.fromInt(config.server.port))(
            new RuntimeException(s"Invalid port: ${config.server.port}")
          )

          _ <- EmberServerBuilder
            .default[IO]
            .withHost(host)
            .withPort(port)
            .withHttpApp(withSecurityHeaders(routes))
            .build
            .use { server =>
              val baseUriString = server.baseUri.toString.stripSuffix("/")
              IO(println("Available endpoints:")) *>
                IO(
                  println(
                    s"  Discovery: $baseUriString/obp-oidc/.well-known/openid-configuration"
                  )
                ) *>
                IO(println(s"  Authorization: $baseUriString/obp-oidc/auth")) *>
                IO(println(s"  Token: $baseUriString/obp-oidc/token")) *>
                IO(println(s"  UserInfo: $baseUriString/obp-oidc/userinfo")) *>
                IO(println(s"  Revocation: $baseUriString/obp-oidc/revoke")) *>
                IO(println(s"  JWKS: $baseUriString/obp-oidc/jwks")) *>
                IO(println(s"  Clients: $baseUriString/obp-oidc/clients")) *>
                IO(println(s"  Health Check: $baseUriString/health")) *>
                IO(println(s"  Status (HTML):  $baseUriString/status")) *>
                IO(println(s"  Status (JSON):  $baseUriString/status.json")) *>
                config.obpApiUrl
                  .fold(IO.unit)(url => IO(println(s"  OBP-API: $url"))) *>
                printOBPConfiguration(baseUriString, authService, config) *>
                IO(println(s"OIDC Provider started at ${server.baseUri}")) *>
                IO(
                  println(
                    s"Local Development Mode: ${if (config.localDevelopmentMode) "ENABLED"
                      else "DISABLED"}"
                  )
                ) *>
                IO(println(s"USE_VERIFY_ENDPOINTS: ${config.useVerifyEndpoints}")) *>
                (if (config.useVerifyEndpoints) {
                  val username = config.obpApiUsername.getOrElse("unknown")
                  val baseRoleEndpoints = List(
                    ("CanVerifyUserCredentials", "POST /obp/v6.0.0/users/verify-credentials"),
                    ("CanGetAnyUser", "GET /obp/v6.0.0/users/provider/PROVIDER/username/USERNAME"),
                    ("CanGetOidcClient", "GET /obp/v6.0.0/oidc/clients/CLIENT_ID"),
                    ("CanVerifyOidcClient", "POST /obp/v6.0.0/oidc/clients/verify"),
                    ("CanGetConsumers", "GET /obp/v6.0.0/management/consumers")
                  )
                  val roleEndpoints =
                    if (config.enableDynamicClientRegistration || !config.skipClientBootstrap)
                      baseRoleEndpoints :+
                        ("CanCreateConsumer", "POST /obp/v5.1.0/management/consumers")
                    else baseRoleEndpoints
                  IO(println("  All verification methods use OBP API endpoints")) *>
                  IO(println(s"  OBP API Username: $username")) *>
                  IO(println(s"  Required roles for OBP_API_USERNAME '$username':")) *>
                  roleCheckRef.get.flatMap { roleCheckOpt =>
                    roleEndpoints.foldLeft(IO.unit) { case (acc, (role, endpoint)) =>
                      val status = roleCheckOpt match {
                        case Some(rc) => if (rc.roleStatus(role)) "OK" else "NOT OK"
                        case None => "UNKNOWN"
                      }
                      acc *> IO(println(s"    - $role (for $endpoint) ... $status"))
                    }
                  } *>
                  IO(println(s"  No special role required for GET /obp/v6.0.0/providers (just authentication)"))
                } else {
                  IO(println("  Credential verification: v_oidc_users (database view)")) *>
                  IO(println("  Client verification: v_oidc_clients (database view)")) *>
                  IO(println("  Provider listing: v_oidc_users (database view)"))
                }) *>
                IO.never
            }
        } yield ExitCode.Success
      }
    } yield exitCode
  }.handleErrorWith { error =>
    IO(println(s"Failed to start OIDC Provider: ${error.getMessage}")) >>
      IO(error.printStackTrace()) >>
      IO.pure(ExitCode.Error)
  }

  /** Generate developer configuration (database + OIDC clients)
    */
  private def generateDeveloperConfig(): IO[ExitCode] = {
    for {
      config <- Config.load
      _ <- IO(println("OBP-OIDC Developer Configuration Generator"))
      _ <- IO(println())
      _ <- ClientBootstrap.generateDatabaseConfig(config)
      _ <- IO(
        println(
          "Next, run the database setup commands above, then start OBP-OIDC to generate OIDC client configurations."
        )
      )
      _ <- IO(
        println(
          "Or run: ./mvn exec:java to start the server and auto-generate everything."
        )
      )
    } yield ExitCode.Success
  }

  /** Generate only database configuration
    */
  private def generateDatabaseConfig(): IO[ExitCode] = {
    for {
      config <- Config.load
      _ <- ClientBootstrap.generateDatabaseConfig(config)
    } yield ExitCode.Success
  }

  /** Print help information
    */
  private def printHelp(): IO[ExitCode] = {
    IO {
      println()
      println("OBP-OIDC Developer Helper")
      println("=" * 50)
      println()
      println("Usage:")
      println("  java -jar target/obp-oidc-1.0.0-SNAPSHOT.jar [COMMAND]")
      println()
      println("Commands:")
      println(
        "  --generate-config    Generate database + OIDC client configuration"
      )
      println("  --db-config         Generate only database configuration")
      println("  --help, -h          Show this help")
      println()
      println("Default (no command): Start OIDC server")
      println()
      println("Examples:")
      println("  # Generate all developer configuration")
      println("  java -jar obp-oidc.jar --generate-config")
      println()
      println("  # Start server (auto-generates client configs)")
      println("  java -jar obp-oidc.jar")
      println()
    } *> IO.pure(ExitCode.Success)
  }

  /** Print configuration for all clients from database
    */
  private def printOBPConfiguration(
      baseUri: String,
      authService: HybridAuthService,
      config: OidcConfig
  ): IO[Unit] = {
    if (!config.needsDatabase) {
      IO(println("Skipping database client listing (all methods use API endpoints)"))
    } else {
      for {
        _ <- IO(println("=" * 100))
        _ <- IO(println("OBP clients from the database"))
        _ <- IO(println("=" * 100))
        _ <- IO(println())
        _ <- IO(println("Database Field Mapping (v_oidc_clients view):"))
        _ <- IO(println("=" * 100))
        _ <- IO(println("| Database Column | View Alias(es)      | Purpose"))
        _ <- IO(
          println(
            "|-----------------|---------------------|--------------------------------------------"
          )
        )
        _ <- IO(
          println(
            "| consumerid      | consumer_id         | Internal database ID (auto-generated)"
          )
        )
        _ <- IO(
          println(
            "| key_c           | key, client_id      | OAuth1/OAuth2 identifier (what apps use)"
          )
        )
        _ <- IO(
          println(
            "| secret          | secret, client_secret| Authentication secret"
          )
        )
        _ <- IO(println("=" * 100))
        _ <- IO(println())

        clientsResult <- authService.listClients()
        _ <- clientsResult match {
          case Right(clients) if clients.nonEmpty =>
            clients.foldLeft(IO.unit) { (acc, client) =>
              acc.flatMap(_ => printClient(Some(client)))
            }
          case Right(_) =>
            IO(println("No Clients Found"))
          case Left(error) =>
            IO(println(s"Error retrieving clients: ${error.error}"))
        }

        _ <- IO(println("=" * 100))
      } yield ()
    }
  }

  /** Print client configuration in standardized format
    */
  private def printClient(client: Option[OidcClient]): IO[Unit] = {
    client match {
      case Some(c) =>
        for {
          _ <- IO(println(s"CLIENT_NAME: ${c.client_name}"))
          _ <- IO(println(s"CONSUMER_ID: ${c.consumer_id}"))
          _ <- IO(println(s"CLIENT_ID (KEY): ${c.client_id}"))
          _ <- IO(
            println(s"CLIENT_SECRET: ${c.client_secret.getOrElse("Not Revealed")}")
          )
          _ <- IO(println(s"REDIRECT_URIS: ${c.redirect_uris.mkString(",")}"))
          _ <- IO(println("-" * 50))
        } yield ()
      case None =>
        IO(println("Client not found"))
    }
  }

  private def readVersion(): String = {
    try {
      val source = Source.fromFile("VERSION")
      try {
        val lines = source.getLines()
        if (lines.hasNext) {
          val version = lines.next().trim
          if (version.nonEmpty) version else "unknown"
        } else {
          "unknown"
        }
      } finally {
        source.close()
      }
    } catch {
      case _: Exception => "unknown"
    }
  }

  private def readGitCommit(): String = {
    try {
      val processBuilder =
        new ProcessBuilder("git", "rev-parse", "HEAD")
      processBuilder.directory(new java.io.File("."))
      val process = processBuilder.start()

      val reader = new java.io.BufferedReader(
        new java.io.InputStreamReader(process.getInputStream)
      )
      val errorReader = new java.io.BufferedReader(
        new java.io.InputStreamReader(process.getErrorStream)
      )

      val commit = reader.readLine()
      val exitCode = process.waitFor()

      reader.close()
      errorReader.close()

      if (exitCode == 0 && commit != null && commit.trim.nonEmpty) {
        commit.trim
      } else {
        "no-git"
      }
    } catch {
      case _: Exception => "no-git"
    }
  }

}
