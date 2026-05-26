package com.ProdeMaster.ApiGateWay.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

/**
 * Injects OWASP-recommended security headers on all HTTP responses.
 * Uses {@code beforeCommit} to guarantee headers are set right before the response is written.
 * Runs at order -50: after JwtAuthenticationFilter (-100) but before routing.
 */
@Component
public class SecurityHeadersFilter implements GlobalFilter, Ordered {

    private static final Logger log = LoggerFactory.getLogger(SecurityHeadersFilter.class);

    @Value("${security.headers.hsts.max-age:31536000}")
    private long hstsMaxAge;

    @Value("${security.headers.hsts.include-subdomains:true}")
    private boolean hstsIncludeSubdomains;

    @Value("${security.headers.csp:default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'}")
    private String contentSecurityPolicy;

    @Override
    public int getOrder() {
        return -50;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        String path = exchange.getRequest().getPath().value();
        exchange.getResponse().beforeCommit(() -> {
            addSecurityHeaders(exchange.getResponse(), path);
            return Mono.empty();
        });
        return chain.filter(exchange);
    }

    private void addSecurityHeaders(ServerHttpResponse response, String path) {
        HttpHeaders headers = response.getHeaders();

        // Prevent MIME-type sniffing
        headers.set("X-Content-Type-Options", "nosniff");
        // Prevent clickjacking
        headers.set("X-Frame-Options", "DENY");
        // Legacy XSS protection (modern browsers ignore, kept for older clients)
        headers.set("X-XSS-Protection", "1; mode=block");
        // Force HTTPS for max-age duration
        headers.set("Strict-Transport-Security",
                String.format("max-age=%d%s", hstsMaxAge, hstsIncludeSubdomains ? "; includeSubDomains" : ""));
        // Prevent caching of sensitive API responses
        headers.set("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate");
        headers.set("Pragma", "no-cache");
        // Content Security Policy
        headers.set("Content-Security-Policy", contentSecurityPolicy);

        log.debug("Security headers injected for path={}", path);
    }
}
