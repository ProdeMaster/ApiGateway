package com.ProdeMaster.ApiGateWay;

import brave.Tracer;
import com.netflix.discovery.converters.Auto;
import org.springframework.beans.factory.annotation.Autowired;
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
    @Autowired
    private Tracer tracer;
    private static final Logger LOGGER = LoggerFactory.getLogger(ApiGatewayFilter.class);

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();
        String requestUri = request.getURI().toString();

        LOGGER.info("Método: {}, URI: {}", request.getMethod(), requestUri);
        LOGGER.info("Span actual: {}", tracer.currentSpan() != null ? tracer.currentSpan().context().traceIdString() : "Ninguna traza activa");


        return chain.filter(exchange);
    }
}
