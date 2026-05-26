package com.ProdeMaster.ApiGateWay.integration;

import com.ProdeMaster.ApiGateWay.fixtures.TestTokenFactory;
import com.ProdeMaster.ApiGateWay.security.TokenBlacklistService;
import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.core.WireMockConfiguration;
import org.junit.jupiter.api.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.reactive.AutoConfigureWebTestClient;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.reactive.server.WebTestClient;
import reactor.core.publisher.Mono;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

/**
 * Integration tests that spin up the full Spring Cloud Gateway context and validate
 * the end-to-end JWT authentication pipeline: token validation → header injection →
 * downstream forwarding → structured error responses.
 *
 * WireMock stands in for all downstream microservices.
 * TokenBlacklistService is mocked to avoid a real Redis dependency.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureWebTestClient
@ActiveProfiles("test")
@DisplayName("JWT Gateway Integration")
class JwtGatewayIntegrationTest {

    // ------------------------------------------------------------------
    // Infrastructure bootstrapped in static scope so that @DynamicPropertySource
    // can reference the WireMock port and public-key file path.
    // ------------------------------------------------------------------

    private static final WireMockServer wireMockServer;
    private static final Path           tempPublicKeyFile;

    static {
        wireMockServer = new WireMockServer(WireMockConfiguration.options().dynamicPort());
        wireMockServer.start();
        try {
            tempPublicKeyFile = Files.createTempFile("test-jwt-public-key", ".pem");
            Files.writeString(tempPublicKeyFile, TestTokenFactory.getPublicKeyPem());
        } catch (IOException e) {
            throw new ExceptionInInitializerError(e);
        }
    }

    @DynamicPropertySource
    static void configureProperties(DynamicPropertyRegistry registry) {
        // Override user-service route to point at WireMock
        registry.add("test.wiremock.uri", () -> "http://localhost:" + wireMockServer.port());
        // Provide the matching RSA public key so JwtTokenProvider validates test tokens
        registry.add("jwt.public-key-path",
                () -> "file:" + tempPublicKeyFile.toAbsolutePath().toString().replace("\\", "/"));
    }

    // ------------------------------------------------------------------

    @Autowired
    private WebTestClient webTestClient;

    @MockBean
    private TokenBlacklistService tokenBlacklistService;

    @BeforeEach
    void setUp() {
        wireMockServer.resetAll();
        configureDefaultDownstreamStubs();
        // By default every token is clean (not blacklisted)
        when(tokenBlacklistService.isTokenBlacklisted(any())).thenReturn(Mono.just(false));
    }

    @AfterAll
    static void teardown() throws IOException {
        wireMockServer.stop();
        Files.deleteIfExists(tempPublicKeyFile);
    }

    private void configureDefaultDownstreamStubs() {
        wireMockServer.stubFor(get(urlPathMatching("/users/.*"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", MediaType.APPLICATION_JSON_VALUE)
                        .withBody("{\"id\":\"" + TestTokenFactory.SUBJECT + "\",\"email\":\"test@prodemaster.com\"}")));
    }

    // =========================================================================
    // Group 1 & 10: Public endpoints + route access matrix
    // =========================================================================

    @Nested
    @DisplayName("Public endpoint access")
    class PublicEndpointTests {

        @Test
        @DisplayName("GET /actuator/health without token returns 200")
        void shouldAllowHealthWithoutToken() {
            webTestClient.get()
                    .uri("/actuator/health")
                    .exchange()
                    .expectStatus().isOk();
        }

        @Test
        @DisplayName("GET /users/auth/login without token returns 200 (public auth route)")
        void shouldAllowLoginRouteWithoutToken() {
            wireMockServer.stubFor(post(urlPathEqualTo("/users/auth/login"))
                    .willReturn(aResponse().withStatus(200).withBody("{\"token\":\"...\"}")));
            wireMockServer.stubFor(get(urlPathEqualTo("/users/auth/login"))
                    .willReturn(aResponse().withStatus(200).withBody("{\"token\":\"...\"}")));

            webTestClient.get()
                    .uri("/users/auth/login")
                    .exchange()
                    .expectStatus().isOk();
        }

        @Test
        @DisplayName("GET /users/profile without token returns 401 (protected route)")
        void shouldRejectProtectedRouteWithoutToken() {
            webTestClient.get()
                    .uri("/users/profile")
                    .exchange()
                    .expectStatus().isUnauthorized();
        }

        @Test
        @DisplayName("GET /actuator/prometheus without token returns 401 (protected actuator)")
        void shouldRejectPrometheusWithoutToken() {
            webTestClient.get()
                    .uri("/actuator/prometheus")
                    .exchange()
                    .expectStatus().isUnauthorized();
        }
    }

    // =========================================================================
    // Group 2 & 3: Missing token vs. valid token
    // =========================================================================

    @Nested
    @DisplayName("Token presence enforcement")
    class TokenPresenceTests {

        @Test
        @DisplayName("Missing Authorization header returns 401 with MISSING_TOKEN error code")
        void shouldReturn401WithMissingTokenErrorCode() {
            webTestClient.get()
                    .uri("/users/profile")
                    .exchange()
                    .expectStatus().isUnauthorized()
                    .expectBody()
                    .jsonPath("$.error").isEqualTo("MISSING_TOKEN")
                    .jsonPath("$.message").exists()
                    .jsonPath("$.timestamp").exists()
                    .jsonPath("$.path").isEqualTo("/users/profile");
        }

        @Test
        @DisplayName("Malformed Authorization header (no Bearer prefix) returns 401")
        void shouldReturn401ForMalformedHeader() {
            webTestClient.get()
                    .uri("/users/profile")
                    .header("Authorization", "Basic dXNlcjpwYXNz")
                    .exchange()
                    .expectStatus().isUnauthorized()
                    .expectBody()
                    .jsonPath("$.error").isEqualTo("MISSING_TOKEN");
        }

        @Test
        @DisplayName("Valid token returns 200 and gateway forwards request to downstream")
        void shouldReturn200WithValidToken() {
            webTestClient.get()
                    .uri("/users/profile")
                    .header("Authorization", "Bearer " + TestTokenFactory.generateValidToken())
                    .exchange()
                    .expectStatus().isOk();
        }

        @Test
        @DisplayName("Valid token: downstream receives X-User-Id, X-Roles, X-Auth-Source; no Authorization header")
        void shouldInjectContextHeadersAndRemoveAuthorization() {
            webTestClient.get()
                    .uri("/users/profile")
                    .header("Authorization", "Bearer " + TestTokenFactory.generateValidToken())
                    .exchange()
                    .expectStatus().isOk();

            // Verify what the downstream mock actually received
            wireMockServer.verify(getRequestedFor(urlPathMatching("/users/.*"))
                    .withHeader("X-User-Id", equalTo(TestTokenFactory.SUBJECT))
                    .withHeader("X-Roles", containing("ADMIN"))
                    .withHeader("X-Auth-Source", equalTo("jwt"))
                    .withHeader("X-Token-Issued-At", matching("\\d+"))
                    .withoutHeader("Authorization"));
        }

        @Test
        @DisplayName("Valid token response includes structured JSON body from downstream")
        void shouldForwardDownstreamResponseBody() {
            webTestClient.get()
                    .uri("/users/profile")
                    .header("Authorization", "Bearer " + TestTokenFactory.generateValidToken())
                    .exchange()
                    .expectStatus().isOk()
                    .expectBody()
                    .jsonPath("$.id").isEqualTo(TestTokenFactory.SUBJECT);
        }
    }

    // =========================================================================
    // Group 4 & 5: Expired and malformed tokens
    // =========================================================================

    @Nested
    @DisplayName("Invalid token responses")
    class InvalidTokenTests {

        @Test
        @DisplayName("Expired token returns 401 with EXPIRED_TOKEN error code")
        void shouldReturn401ForExpiredToken() {
            webTestClient.get()
                    .uri("/users/profile")
                    .header("Authorization", "Bearer " + TestTokenFactory.generateExpiredToken())
                    .exchange()
                    .expectStatus().isUnauthorized()
                    .expectBody()
                    .jsonPath("$.error").isEqualTo("EXPIRED_TOKEN");
        }

        @Test
        @DisplayName("Malformed token returns 401 with INVALID_TOKEN error code")
        void shouldReturn401ForMalformedToken() {
            webTestClient.get()
                    .uri("/users/profile")
                    .header("Authorization", "Bearer " + TestTokenFactory.generateMalformedToken())
                    .exchange()
                    .expectStatus().isUnauthorized()
                    .expectBody()
                    .jsonPath("$.error").isEqualTo("INVALID_TOKEN");
        }

        @Test
        @DisplayName("Token with invalid signature returns 401 with INVALID_SIGNATURE error code")
        void shouldReturn401ForInvalidSignature() {
            webTestClient.get()
                    .uri("/users/profile")
                    .header("Authorization", "Bearer " + TestTokenFactory.generateInvalidSignatureToken())
                    .exchange()
                    .expectStatus().isUnauthorized()
                    .expectBody()
                    .jsonPath("$.error").isEqualTo("INVALID_SIGNATURE");
        }

        @Test
        @DisplayName("HS256 token returns 401 with ALGORITHM_MISMATCH error code")
        void shouldReturn401ForHS256Token() {
            webTestClient.get()
                    .uri("/users/profile")
                    .header("Authorization", "Bearer " + TestTokenFactory.generateHS256Token())
                    .exchange()
                    .expectStatus().isUnauthorized()
                    .expectBody()
                    .jsonPath("$.error").isEqualTo("ALGORITHM_MISMATCH");
        }

        @Test
        @DisplayName("Error response contains traceId and path fields")
        void errorResponseShouldIncludeTraceIdAndPath() {
            webTestClient.get()
                    .uri("/users/profile")
                    .header("Authorization", "Bearer " + TestTokenFactory.generateExpiredToken())
                    .exchange()
                    .expectStatus().isUnauthorized()
                    .expectBody()
                    .jsonPath("$.traceId").exists()
                    .jsonPath("$.path").isEqualTo("/users/profile");
        }
    }

    // =========================================================================
    // Group 6: Revoked / blacklisted token
    // =========================================================================

    @Nested
    @DisplayName("Blacklisted (revoked) token")
    class RevokedTokenTests {

        @Test
        @DisplayName("Blacklisted token returns 401 with TOKEN_REVOKED error code")
        void shouldReturn401ForRevokedToken() {
            String jti   = "revoked-jti-001";
            String token = TestTokenFactory.generateTokenWithJti(jti);
            // Override default mock: this specific jti is revoked
            when(tokenBlacklistService.isTokenBlacklisted(jti)).thenReturn(Mono.just(true));

            webTestClient.get()
                    .uri("/users/profile")
                    .header("Authorization", "Bearer " + token)
                    .exchange()
                    .expectStatus().isUnauthorized()
                    .expectBody()
                    .jsonPath("$.error").isEqualTo("TOKEN_REVOKED");
        }

        @Test
        @DisplayName("Non-blacklisted token with same format passes through")
        void shouldAllowNonBlacklistedToken() {
            String jti   = "active-jti-002";
            String token = TestTokenFactory.generateTokenWithJti(jti);
            when(tokenBlacklistService.isTokenBlacklisted(jti)).thenReturn(Mono.just(false));

            webTestClient.get()
                    .uri("/users/profile")
                    .header("Authorization", "Bearer " + token)
                    .exchange()
                    .expectStatus().isOk();
        }
    }

    // =========================================================================
    // Group 7: Rate limiting
    // =========================================================================

    @Nested
    @DisplayName("Rate limiting")
    class RateLimitingTests {

        /**
         * Uses a dedicated X-Forwarded-For IP so this bucket starts fresh regardless of
         * requests made by other test groups.
         */
        private static final String RL_CLIENT_IP = "10.0.0.222";

        @Test
        @DisplayName("Requests within burst limit succeed; request beyond limit returns 429")
        void shouldReturn429WhenRateLimitExceeded() {
            // Exhaust the configured burst (security.rate-limit.burst in application-test.properties)
            int burst = 10;
            for (int i = 0; i < burst; i++) {
                webTestClient.get()
                        .uri("/actuator/health")
                        .header("X-Forwarded-For", RL_CLIENT_IP)
                        .exchange()
                        .expectStatus().isOk();
            }

            // The very next request must be rate-limited
            webTestClient.get()
                    .uri("/actuator/health")
                    .header("X-Forwarded-For", RL_CLIENT_IP)
                    .exchange()
                    .expectStatus().isEqualTo(429)
                    .expectBody()
                    .jsonPath("$.error").isEqualTo("TOO_MANY_REQUESTS");
        }

        @Test
        @DisplayName("Rate-limited response includes X-RateLimit-Remaining and Retry-After headers")
        void rateLimitedResponseShouldIncludeHeaders() {
            int burst = 10;
            for (int i = 0; i < burst; i++) {
                webTestClient.get()
                        .uri("/actuator/health")
                        .header("X-Forwarded-For", RL_CLIENT_IP + "1")
                        .exchange()
                        .expectStatus().isOk();
            }

            webTestClient.get()
                    .uri("/actuator/health")
                    .header("X-Forwarded-For", RL_CLIENT_IP + "1")
                    .exchange()
                    .expectStatus().isEqualTo(429)
                    .expectHeader().exists("X-RateLimit-Remaining")
                    .expectHeader().exists("Retry-After")
                    .expectHeader().exists("X-RateLimit-Limit");
        }
    }

    // =========================================================================
    // Group 8: Security headers on every response
    // =========================================================================

    @Nested
    @DisplayName("OWASP security headers")
    class SecurityHeaderTests {

        @Test
        @DisplayName("Every response includes X-Frame-Options: DENY")
        void shouldIncludeXFrameOptions() {
            webTestClient.get()
                    .uri("/actuator/health")
                    .exchange()
                    .expectHeader().valueEquals("X-Frame-Options", "DENY");
        }

        @Test
        @DisplayName("Every response includes X-Content-Type-Options: nosniff")
        void shouldIncludeXContentTypeOptions() {
            webTestClient.get()
                    .uri("/actuator/health")
                    .exchange()
                    .expectHeader().valueEquals("X-Content-Type-Options", "nosniff");
        }

        @Test
        @DisplayName("Every response includes Strict-Transport-Security header")
        void shouldIncludeHSTS() {
            webTestClient.get()
                    .uri("/actuator/health")
                    .exchange()
                    .expectHeader().exists("Strict-Transport-Security");
        }

        @Test
        @DisplayName("Every response includes Cache-Control: no-store")
        void shouldIncludeCacheControl() {
            webTestClient.get()
                    .uri("/actuator/health")
                    .exchange()
                    .expectHeader().value("Cache-Control", v ->
                            assertThat(v).contains("no-store"));
        }

        @Test
        @DisplayName("401 error responses also carry security headers")
        void shouldIncludeSecurityHeadersOnErrorResponses() {
            webTestClient.get()
                    .uri("/users/profile")
                    .exchange()
                    .expectStatus().isUnauthorized()
                    .expectHeader().exists("X-Frame-Options")
                    .expectHeader().exists("X-Content-Type-Options");
        }
    }

    // =========================================================================
    // Group 9: Micrometer / Prometheus metrics
    // =========================================================================

    @Nested
    @DisplayName("Micrometer metrics")
    class MetricsTests {

        @Test
        @DisplayName("/actuator/prometheus is protected — requires JWT")
        void prometheusShouldRequireJwt() {
            webTestClient.get()
                    .uri("/actuator/prometheus")
                    .exchange()
                    .expectStatus().isUnauthorized();
        }

        @Test
        @DisplayName("After validation events, jwt_validations_total counter appears in Prometheus output")
        void shouldExposejwtValidationsTotalMetric() {
            // Trigger a successful validation
            webTestClient.get()
                    .uri("/users/profile")
                    .header("Authorization", "Bearer " + TestTokenFactory.generateValidToken())
                    .exchange()
                    .expectStatus().isOk();

            // Trigger an expired-token failure
            webTestClient.get()
                    .uri("/users/profile")
                    .header("Authorization", "Bearer " + TestTokenFactory.generateExpiredToken())
                    .exchange()
                    .expectStatus().isUnauthorized();

            // Retrieve Prometheus scrape with a valid JWT
            webTestClient.get()
                    .uri("/actuator/prometheus")
                    .header("Authorization", "Bearer " + TestTokenFactory.generateValidToken())
                    .exchange()
                    .expectStatus().isOk()
                    .expectBody(String.class)
                    .value(body -> {
                        assertThat(body)
                                .as("Prometheus output must include jwt_validations_total counter")
                                .contains("jwt_validations_total");
                    });
        }

        @Test
        @DisplayName("Prometheus output contains jwt_validations_duration_seconds histogram")
        void shouldExposeValidationDurationMetric() {
            webTestClient.get()
                    .uri("/users/profile")
                    .header("Authorization", "Bearer " + TestTokenFactory.generateValidToken())
                    .exchange()
                    .expectStatus().isOk();

            webTestClient.get()
                    .uri("/actuator/prometheus")
                    .header("Authorization", "Bearer " + TestTokenFactory.generateValidToken())
                    .exchange()
                    .expectStatus().isOk()
                    .expectBody(String.class)
                    .value(body ->
                            assertThat(body).contains("jwt_validations_duration_seconds"));
        }
    }
}
