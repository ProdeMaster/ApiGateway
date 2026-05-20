package com.ProdeMaster.ApiGateWay.Config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.context.NoOpServerSecurityContextRepository;

/**
 * Spring WebFlux Security configuration (stateless, JWT-based).
 *
 * Design: Spring Security is permissive at this layer (anyExchange().permitAll()).
 * Actual auth enforcement is done by JwtAuthenticationFilter (GlobalFilter, order -100)
 * which intercepts BEFORE routing and returns 401/403 with structured JSON responses.
 *
 * Public routes (no JWT required): configured via jwt.public-paths in application.properties
 * Protected Actuator endpoints (/prometheus, /metrics, /env, /loggers): NOT in jwt.public-paths,
 *   so JwtAuthenticationFilter will enforce JWT for those routes.
 *
 * Item 2.5: public vs protected paths. Item 2.8: actuator protection.
 */
@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {

    @Bean
    public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {
        return http
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .httpBasic(ServerHttpSecurity.HttpBasicSpec::disable)
                .formLogin(ServerHttpSecurity.FormLoginSpec::disable)
                .logout(ServerHttpSecurity.LogoutSpec::disable)
                // Stateless API: no server-side session, no security context stored
                .securityContextRepository(NoOpServerSecurityContextRepository.getInstance())
                .authorizeExchange(exchanges -> exchanges
                        // Public: health check (no JWT required)
                        .pathMatchers(
                                "/actuator/health",
                                "/actuator/health/**"
                        ).permitAll()
                        // Public: authentication flows (login, register, refresh)
                        .pathMatchers(
                                "/users/auth/login",
                                "/users/auth/register",
                                "/users/auth/refresh"
                        ).permitAll()
                        // Protected Actuator: sensitive endpoints require JWT
                        // JwtAuthenticationFilter enforces the 401 since these are NOT in jwt.public-paths
                        // Note: if ops team uses Prometheus scraping, consider mTLS or API key instead of JWT
                        .pathMatchers(
                                "/actuator/prometheus",
                                "/actuator/metrics",
                                "/actuator/env",
                                "/actuator/loggers"
                        ).permitAll()   // Spring Security allows; JWT GlobalFilter enforces
                        // All other paths: Spring Security defers to JwtAuthenticationFilter
                        .anyExchange().permitAll()
                )
                .build();
    }
}
