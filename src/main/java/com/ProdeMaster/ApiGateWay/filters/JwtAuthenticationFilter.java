package com.ProdeMaster.ApiGateWay.filters;

import com.ProdeMaster.ApiGateWay.Config.JwtProperties;
import com.ProdeMaster.ApiGateWay.dto.ErrorCode;
import com.ProdeMaster.ApiGateWay.dto.ErrorResponse;
import com.ProdeMaster.ApiGateWay.security.JwtTokenProvider;
import com.ProdeMaster.ApiGateWay.security.TokenBlacklistService;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.SignatureException;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

/**
 * GlobalFilter (order -100) that enforces JWT authentication on all non-public routes.
 * Validates tokens via JwtTokenProvider and injects user context headers for downstream services.
 *
 * Items 2.4 (headers), 2.7 (logging), 2.9 (error responses) from Phase 2.
 * Items 3.1 (blacklist check), 3.2 (MDC role for sampler), 3.3 (Prometheus metrics) from Phase 3.
 */
@Component
public class JwtAuthenticationFilter implements GlobalFilter, Ordered {

    private static final Logger log = LoggerFactory.getLogger(JwtAuthenticationFilter.class);
    private static final AntPathMatcher PATH_MATCHER = new AntPathMatcher();

    private final JwtTokenProvider jwtTokenProvider;
    private final TokenBlacklistService tokenBlacklistService;
    private final ObjectMapper objectMapper;
    private final JwtProperties jwtProperties;
    private final MeterRegistry meterRegistry;

    public JwtAuthenticationFilter(JwtTokenProvider jwtTokenProvider,
                                    TokenBlacklistService tokenBlacklistService,
                                    ObjectMapper objectMapper,
                                    JwtProperties jwtProperties,
                                    MeterRegistry meterRegistry) {
        this.jwtTokenProvider = jwtTokenProvider;
        this.tokenBlacklistService = tokenBlacklistService;
        this.objectMapper = objectMapper;
        this.jwtProperties = jwtProperties;
        this.meterRegistry = meterRegistry;
    }

    @Override
    public int getOrder() {
        return -100;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();
        String path = request.getPath().value();

        if (isPublicPath(path)) {
            return chain.filter(exchange);
        }

        String authHeader = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            logMissingToken(path, resolveClientIp(request));
            recordValidationMetric("missing");
            return rejectWithError(exchange, ErrorCode.MISSING_TOKEN, HttpStatus.UNAUTHORIZED,
                    "Token not present in Authorization header");
        }

        String token = authHeader.substring(7);
        long startMs = System.currentTimeMillis();

        return jwtTokenProvider.validateAndExtract(token)
                .flatMap(claims -> {
                    // Item 3.1: check blacklist using jti (preferred) or token fingerprint
                    String blacklistKey = claims.getId() != null
                            ? claims.getId()
                            : TokenBlacklistService.tokenFingerprint(token);

                    return tokenBlacklistService.isTokenBlacklisted(blacklistKey)
                            .flatMap(blacklisted -> {
                                if (blacklisted) {
                                    recordValidationMetric("blacklisted");
                                    log.warn("TOKEN_BLACKLIST revoked_token_detected userId={}", claims.getSubject());
                                    return rejectWithError(exchange, ErrorCode.TOKEN_REVOKED,
                                            HttpStatus.UNAUTHORIZED, "Token has been revoked");
                                }

                                long durationMs = System.currentTimeMillis() - startMs;
                                recordValidationMetric("success");
                                recordValidationTime(durationMs);
                                logValidationSuccess(claims, durationMs);

                                // Item 3.2: populate MDC so DynamicTracingSampler can read the role
                                List<String> roles = extractRoles(claims);
                                MDC.put("user_role", String.join(",", roles));

                                return injectHeadersAndContinue(exchange, chain, request, claims, roles)
                                        .doFinally(sig -> MDC.remove("user_role"));
                            });
                })
                .onErrorResume(ExpiredJwtException.class, e -> {
                    recordValidationMetric("expired");
                    logValidationFailure(path, "EXPIRED_TOKEN", e.getMessage());
                    return rejectWithError(exchange, ErrorCode.EXPIRED_TOKEN, HttpStatus.UNAUTHORIZED,
                            "Token expired");
                })
                .onErrorResume(SignatureException.class, e -> {
                    recordValidationMetric("invalid");
                    logValidationFailure(path, "INVALID_SIGNATURE", e.getMessage());
                    return rejectWithError(exchange, ErrorCode.INVALID_SIGNATURE, HttpStatus.UNAUTHORIZED,
                            "Token signature is invalid");
                })
                .onErrorResume(UnsupportedJwtException.class, e -> {
                    recordValidationMetric("invalid");
                    logValidationFailure(path, "ALGORITHM_MISMATCH", e.getMessage());
                    return rejectWithError(exchange, ErrorCode.ALGORITHM_MISMATCH, HttpStatus.UNAUTHORIZED,
                            "Algorithm not permitted. Only RSA algorithms accepted.");
                })
                .onErrorResume(MalformedJwtException.class, e -> {
                    recordValidationMetric("invalid");
                    logValidationFailure(path, "INVALID_TOKEN", e.getMessage());
                    return rejectWithError(exchange, ErrorCode.INVALID_TOKEN, HttpStatus.UNAUTHORIZED,
                            "Token is malformed or corrupted");
                })
                .onErrorResume(JwtException.class, e -> {
                    recordValidationMetric("invalid");
                    logValidationFailure(path, "CLAIM_VALIDATION_FAILED", e.getMessage());
                    return rejectWithError(exchange, ErrorCode.CLAIM_VALIDATION_FAILED, HttpStatus.UNAUTHORIZED,
                            e.getMessage());
                });
    }

    // Item 3.3: Micrometer counters — one per validation outcome

    private void recordValidationMetric(String result) {
        Counter.builder("jwt.validations.total")
                .tag("result", result)
                .register(meterRegistry)
                .increment();
    }

    private void recordValidationTime(long durationMillis) {
        Timer.builder("jwt.validations.duration_seconds")
                .publishPercentiles(0.95, 0.99)
                .register(meterRegistry)
                .record(durationMillis, TimeUnit.MILLISECONDS);
    }

    /**
     * Item 2.4: Injects user context headers for downstream microservices and removes Authorization.
     * Also stores userId as an exchange attribute so RateLimitingFilter can use it for per-user buckets.
     */
    private Mono<Void> injectHeadersAndContinue(ServerWebExchange exchange,
                                                  GatewayFilterChain chain,
                                                  ServerHttpRequest request,
                                                  Claims claims,
                                                  List<String> roles) {
        String userId = claims.getSubject();
        String issuedAtMs = claims.getIssuedAt() != null
                ? String.valueOf(claims.getIssuedAt().toInstant().toEpochMilli())
                : "";

        if (jwtProperties.isLoggingVerbose()) {
            log.debug("JWT_HEADERS injecting userId={} rolesCount={}", userId, roles.size());
        }

        // Exchange attributes are visible to subsequent GlobalFilters (e.g., RateLimitingFilter)
        exchange.getAttributes().put("userId", userId);
        exchange.getAttributes().put("userRoles", roles);

        ServerHttpRequest mutated = request.mutate()
                .header("X-User-Id", userId)
                .header("X-Roles", String.join(",", roles))
                .header("X-Token-Issued-At", issuedAtMs)
                .header("X-Auth-Source", "jwt")
                .headers(h -> h.remove(HttpHeaders.AUTHORIZATION))  // never forward raw token downstream
                .build();

        return chain.filter(exchange.mutate().request(mutated).build());
    }

    @SuppressWarnings("unchecked")
    private List<String> extractRoles(Claims claims) {
        Object roles = claims.get("roles");
        if (roles instanceof List<?> list) {
            return (List<String>) list;
        }
        return List.of();
    }

    private boolean isPublicPath(String path) {
        return jwtProperties.getPublicPaths().stream()
                .anyMatch(pattern -> PATH_MATCHER.match(pattern.trim(), path));
    }

    private Mono<Void> rejectWithError(ServerWebExchange exchange, ErrorCode errorCode,
                                        HttpStatus status, String message) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(status);
        response.getHeaders().setContentType(MediaType.APPLICATION_JSON);

        String traceId = Optional.ofNullable(MDC.get("traceId"))
                .filter(s -> !s.isBlank())
                .orElse(UUID.randomUUID().toString());

        ErrorResponse body = ErrorResponse.builder()
                .error(errorCode.name())
                .message(message)
                .traceId(traceId)
                .timestamp(Instant.now().toString())
                .path(exchange.getRequest().getPath().value())
                .build();

        String json;
        try {
            json = objectMapper.writeValueAsString(body);
        } catch (JsonProcessingException e) {
            json = "{\"error\":\"INTERNAL_ERROR\",\"message\":\"Error serializing response\"}";
        }

        DataBuffer buffer = response.bufferFactory().wrap(json.getBytes(StandardCharsets.UTF_8));
        return response.writeWith(Mono.just(buffer));
    }

    // Item 2.7: Logging with token masking — never log the full token value

    private void logValidationSuccess(Claims claims, long durationMs) {
        log.info("JWT_VALIDATION status=SUCCESS userId={} roles={} duration_ms={}",
                claims.getSubject(), extractRoles(claims).size(), durationMs);
    }

    private void logValidationFailure(String path, String reason, String detail) {
        if (jwtProperties.isLoggingVerbose()) {
            log.warn("JWT_VALIDATION status=FAILED reason={} path={} detail={}", reason, path, detail);
        } else {
            log.warn("JWT_VALIDATION status=FAILED reason={} path={}", reason, path);
        }
    }

    private void logMissingToken(String path, String clientIp) {
        log.warn("JWT_VALIDATION status=FAILED reason=MISSING_TOKEN path={} clientIp={}", path, clientIp);
    }

    private String resolveClientIp(ServerHttpRequest request) {
        String forwarded = request.getHeaders().getFirst("X-Forwarded-For");
        if (forwarded != null && !forwarded.isBlank()) {
            return forwarded.split(",")[0].trim();
        }
        return Optional.ofNullable(request.getRemoteAddress())
                .map(InetSocketAddress::getAddress)
                .map(java.net.InetAddress::getHostAddress)
                .orElse("unknown");
    }
}
