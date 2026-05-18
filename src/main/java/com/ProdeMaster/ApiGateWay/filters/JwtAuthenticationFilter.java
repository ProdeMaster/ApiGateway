package com.ProdeMaster.ApiGateWay.filters;

import com.ProdeMaster.ApiGateWay.security.JwtTokenProvider;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
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

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

@Component
public class JwtAuthenticationFilter implements GlobalFilter, Ordered {

    private static final Logger log = LoggerFactory.getLogger(JwtAuthenticationFilter.class);
    private static final AntPathMatcher PATH_MATCHER = new AntPathMatcher();

    private final JwtTokenProvider jwtTokenProvider;
    private final ObjectMapper objectMapper;

    @Value("${jwt.issuer}")
    private String issuer;

    @Value("${jwt.audience}")
    private String audience;

    @Value("${jwt.public-paths:/actuator/health,/actuator/info}")
    private String[] publicPaths;

    public JwtAuthenticationFilter(JwtTokenProvider jwtTokenProvider, ObjectMapper objectMapper) {
        this.jwtTokenProvider = jwtTokenProvider;
        this.objectMapper = objectMapper;
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
            return rejectUnauthorized(exchange, "Missing or malformed Authorization header");
        }

        String token = authHeader.substring(7);

        return jwtTokenProvider.validateToken(token, issuer, audience)
                .flatMap(isValid -> {
                    if (Boolean.FALSE.equals(isValid)) {
                        return rejectUnauthorized(exchange, "Token inválido o expirado");
                    }
                    return jwtTokenProvider.extractUserId(token)
                            .zipWith(jwtTokenProvider.extractRoles(token))
                            .flatMap(tuple -> {
                                String userId = tuple.getT1();
                                List<String> roles = tuple.getT2();

                                ServerHttpRequest mutatedRequest = request.mutate()
                                        .header("X-User-Id", userId)
                                        .header("X-Roles", String.join(",", roles))
                                        .headers(h -> h.remove(HttpHeaders.AUTHORIZATION))
                                        .build();

                                return chain.filter(exchange.mutate().request(mutatedRequest).build());
                            });
                });
    }

    private boolean isPublicPath(String path) {
        return Arrays.stream(publicPaths)
                .anyMatch(pattern -> PATH_MATCHER.match(pattern.trim(), path));
    }

    private Mono<Void> rejectUnauthorized(ServerWebExchange exchange, String reason) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(HttpStatus.UNAUTHORIZED);
        response.getHeaders().setContentType(MediaType.APPLICATION_JSON);

        String json;
        try {
            json = objectMapper.writeValueAsString(Map.of("error", "Token inválido", "reason", reason));
        } catch (JsonProcessingException e) {
            json = "{\"error\":\"Token inv\\u00e1lido\",\"reason\":\"Error interno\"}";
        }

        DataBuffer buffer = response.bufferFactory().wrap(json.getBytes(StandardCharsets.UTF_8));
        return response.writeWith(Mono.just(buffer));
    }
}
