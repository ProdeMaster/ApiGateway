package com.ProdeMaster.ApiGateWay;

import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Component
public class ApiGatewayFilter implements GlobalFilter {
    private static final Logger LOGGER = LoggerFactory.getLogger(ApiGatewayFilter.class);

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();
        String requestUri = request.getURI().toString();

        LOGGER.info("Método: {}, URI: {}", request.getMethod(), requestUri);

        return chain.filter(exchange);
    }
}
