package com.ProdeMaster.ApiGateWay.Config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.context.NoOpServerSecurityContextRepository;

/**
 * Configures Spring WebFlux Security in stateless mode.
 *
 * Auth enforcement (JWT validation, 401 responses, header injection) is handled
 * by JwtAuthenticationFilter, which runs as a GlobalFilter at order -100 —
 * before
 * any Gateway routing. Spring Security here disables CSRF/sessions/form-login
 * and
 * defers to that filter rather than duplicating auth logic.
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
                                // Stateless API: no server-side session or security context storage
                                .securityContextRepository(NoOpServerSecurityContextRepository.getInstance())
                                .authorizeExchange(exchanges -> exchanges
                                                .pathMatchers(
                                                                "/api/public/**",
                                                                "/actuator/health",
                                                                "/actuator/info",
                                                                "/test")
                                                .permitAll()
                                                // JwtAuthenticationFilter (GlobalFilter, order -100) enforces JWT
                                                // and returns 401 for invalid/missing tokens on all other routes
                                                .anyExchange().permitAll())
                                .build();
        }
}
