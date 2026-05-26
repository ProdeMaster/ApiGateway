package com.ProdeMaster.ApiGateWay.Config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.context.NoOpServerSecurityContextRepository;

/**
 * Spring WebFlux Security configuration for the API Gateway.
 *
 * <p>Design intent — two-layer authorisation model:</p>
 * <ol>
 *   <li>This class configures Spring Security to be <em>permissive</em> at the framework level
 *       ({@code anyExchange().permitAll()}).  CSRF, HTTP Basic, form login, and server-side
 *       sessions are all disabled because the gateway is stateless and JWT-based.</li>
 *   <li>{@link com.ProdeMaster.ApiGateWay.filters.JwtAuthenticationFilter} (order {@code -100})
 *       performs the actual JWT enforcement <em>before</em> any route is resolved, returning
 *       structured {@code 401} JSON responses for unauthenticated requests.</li>
 * </ol>
 * This separation keeps Spring Security lightweight while preserving full control over
 * authentication responses in the gateway filter chain.
 *
 * <p>Route access matrix:</p>
 * <ul>
 *   <li><b>Public</b> (no JWT required, configured via {@code jwt.public-paths}):
 *     <ul>
 *       <li>{@code /actuator/health} — liveness / readiness probes for Kubernetes</li>
 *       <li>{@code /users/auth/login}, {@code /users/auth/register}, {@code /users/auth/refresh}
 *           — authentication flows that issue tokens</li>
 *     </ul>
 *   </li>
 *   <li><b>Protected</b> (JWT required, enforced by {@code JwtAuthenticationFilter}):
 *     <ul>
 *       <li>{@code /users/**} — user profile and account management</li>
 *       <li>{@code /matches/**}, {@code /predictions/**}, {@code /scoring/**} — business APIs</li>
 *     </ul>
 *   </li>
 *   <li><b>Protected actuator</b> (JWT required; Spring Security defers to the filter):
 *     <ul>
 *       <li>{@code /actuator/prometheus}, {@code /actuator/metrics}, {@code /actuator/env},
 *           {@code /actuator/loggers} — sensitive operational endpoints</li>
 *     </ul>
 *   </li>
 * </ul>
 *
 * @see com.ProdeMaster.ApiGateWay.filters.JwtAuthenticationFilter
 * @see com.ProdeMaster.ApiGateWay.Config.JwtProperties#getPublicPaths()
 * @see org.springframework.security.config.web.server.ServerHttpSecurity
 */
@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {

    /**
     * Builds the reactive security filter chain.
     *
     * <p>All unnecessary mechanisms are disabled so the gateway remains fully stateless:</p>
     * <ul>
     *   <li>CSRF — not applicable for a machine-to-machine API gateway.</li>
     *   <li>HTTP Basic / form login / logout — superseded by JWT.</li>
     *   <li>Security context repository — {@link org.springframework.security.web.server.context.NoOpServerSecurityContextRepository}
     *       prevents any server-side session creation.</li>
     * </ul>
     *
     * <p>The {@code authorizeExchange} rules grant {@code permitAll()} to every path.
     * Real enforcement happens in {@link com.ProdeMaster.ApiGateWay.filters.JwtAuthenticationFilter}.</p>
     *
     * @param http the {@link ServerHttpSecurity} builder provided by Spring
     * @return the configured {@link SecurityWebFilterChain}
     */
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
