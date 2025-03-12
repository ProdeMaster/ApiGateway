package com.ProdeMaster.ApiGateWay;

import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
//import org.springframework.http.HttpHeaders;
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

        LOGGER.info("Nueva solicitud al API Gateway");
        LOGGER.info("Método: {}", request.getMethod());
        LOGGER.info("URI: {}", requestUri);
        LOGGER.info("Headers: {}", request.getHeaders());

        return chain.filter(exchange);
        //HttpHeaders headers = exchange.getRequest().getHeaders();
        //if (!headers.containsKey("Authorization")) {
        //    exchange.getResponse().setStatusCode(org.springframework.http.HttpStatus.UNAUTHORIZED);
        //    return exchange.getResponse().setComplete();
        //}
        //return chain.filter(exchange);
    }
}
