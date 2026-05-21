package com.ProdeMaster.ApiGateWay.security;

import com.ProdeMaster.ApiGateWay.dto.ErrorCode;
import io.github.bucket4j.Bandwidth;
import io.github.bucket4j.Bucket;
import io.github.bucket4j.Bucket4j;
import io.github.bucket4j.ConsumptionProbe;
import io.github.bucket4j.Refill;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;

/**
 * Per-client rate limiting using Bucket4j (token-bucket algorithm).
 *
 * Order -90 (after JwtAuthenticationFilter at -100) so that the userId
 * attribute
 * set by the auth filter is available for per-user bucket keying.
 * Anonymous / public requests fall back to IP-based keying.
 *
 * Limits are configurable via:
 * security.rate-limit.requests-per-minute (default 100)
 * security.rate-limit.burst (default 150)
 *
 * Response headers:
 * X-RateLimit-Limit — configured maximum
 * X-RateLimit-Remaining — tokens left after this request
 * X-RateLimit-Reset — epoch second when the window resets (~60s from now)
 */
@Component
public class RateLimitingFilter implements GlobalFilter, Ordered {

    private static final Logger log = LoggerFactory.getLogger(RateLimitingFilter.class);

    @Value("${security.rate-limit.requests-per-minute:100}")
    private int requestsPerMinute;

    @Value("${security.rate-limit.burst:150}")
    private int burst;

    private final Map<String, Bucket> buckets = new ConcurrentHashMap<>();

    @Override
    public int getOrder() {
        return -90;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        String clientKey = resolveClientKey(exchange);
        Bucket bucket = buckets.computeIfAbsent(clientKey, k -> createBucket());

        ConsumptionProbe probe = bucket.tryConsumeAndReturnRemaining(1);
        long resetEpoch = Instant.now().plusSeconds(60).getEpochSecond();

        if (!probe.isConsumed()) {
            long retryAfterSeconds = TimeUnit.NANOSECONDS.toSeconds(probe.getNanosToWaitForRefill()) + 1;
            log.warn("RATE_LIMIT exceeded key={} retry_after_s={}", clientKey, retryAfterSeconds);

            exchange.getResponse().setStatusCode(HttpStatus.TOO_MANY_REQUESTS);
            exchange.getResponse().getHeaders().setContentType(MediaType.APPLICATION_JSON);
            setRateLimitHeaders(exchange, 0, resetEpoch);
            exchange.getResponse().getHeaders().set("Retry-After", String.valueOf(retryAfterSeconds));

            String body = String.format(
                    "{\"error\":\"%s\",\"message\":\"Rate limit exceeded. Max %d requests per minute.\",\"timestamp\":\"%s\"}",
                    ErrorCode.TOO_MANY_REQUESTS.name(), requestsPerMinute, Instant.now());
            DataBuffer buffer = exchange.getResponse().bufferFactory()
                    .wrap(body.getBytes(StandardCharsets.UTF_8));
            return exchange.getResponse().writeWith(Mono.just(buffer));
        }

        setRateLimitHeaders(exchange, probe.getRemainingTokens(), resetEpoch);
        return chain.filter(exchange);
    }

    private void setRateLimitHeaders(ServerWebExchange exchange, long remaining, long resetEpoch) {
        exchange.getResponse().getHeaders().set("X-RateLimit-Limit", String.valueOf(requestsPerMinute));
        exchange.getResponse().getHeaders().set("X-RateLimit-Remaining", String.valueOf(remaining));
        exchange.getResponse().getHeaders().set("X-RateLimit-Reset", String.valueOf(resetEpoch));
    }

    private String resolveClientKey(ServerWebExchange exchange) {
        Object userId = exchange.getAttributes().get("userId");
        if (userId instanceof String uid && !uid.isBlank()) {
            return "user:" + uid;
        }
        return "anon:" + resolveClientIp(exchange);
    }

    private String resolveClientIp(ServerWebExchange exchange) {
        String forwarded = exchange.getRequest().getHeaders().getFirst("X-Forwarded-For");
        if (forwarded != null && !forwarded.isBlank()) {
            return forwarded.split(",")[0].trim();
        }
        return Optional.ofNullable(exchange.getRequest().getRemoteAddress())
                .map(InetSocketAddress::getAddress)
                .map(java.net.InetAddress::getHostAddress)
                .orElse("unknown");
    }

    private Bucket createBucket() {
        // Burst allows a short spike above the per-minute rate; refill is
        // interval-based (not greedy).
        Bandwidth burstLimit = Bandwidth.classic(burst,
                Refill.intervally(requestsPerMinute, Duration.ofMinutes(1)));
        return Bucket4j.builder()
                .addLimit(burstLimit)
                .build();
    }
}
