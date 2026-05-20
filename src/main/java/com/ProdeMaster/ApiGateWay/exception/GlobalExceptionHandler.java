package com.ProdeMaster.ApiGateWay.exception;

import com.ProdeMaster.ApiGateWay.dto.ErrorCode;
import com.ProdeMaster.ApiGateWay.dto.ErrorResponse;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.security.SignatureException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.annotation.Order;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebExceptionHandler;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

/**
 * Global exception handler for unhandled exceptions in the reactive gateway pipeline.
 * Runs at order -2 (before Spring Boot's DefaultErrorWebExceptionHandler at -1).
 * JWT exceptions handled by JwtAuthenticationFilter's onErrorResume won't reach here.
 */
@Component
@Order(-2)
public class GlobalExceptionHandler implements WebExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    private final ObjectMapper objectMapper;

    public GlobalExceptionHandler(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    @Override
    public Mono<Void> handle(ServerWebExchange exchange, Throwable ex) {
        String path = exchange.getRequest().getPath().value();
        String traceId = Optional.ofNullable(org.slf4j.MDC.get("traceId"))
                .filter(s -> !s.isBlank())
                .orElse(UUID.randomUUID().toString());

        HttpStatus status;
        ErrorCode errorCode;
        String message;

        if (ex instanceof ExpiredJwtException) {
            status = HttpStatus.UNAUTHORIZED;
            errorCode = ErrorCode.EXPIRED_TOKEN;
            message = "Token expired";
        } else if (ex instanceof SignatureException) {
            status = HttpStatus.UNAUTHORIZED;
            errorCode = ErrorCode.INVALID_SIGNATURE;
            message = "Token signature is invalid";
        } else if (ex instanceof UnsupportedJwtException) {
            status = HttpStatus.UNAUTHORIZED;
            errorCode = ErrorCode.ALGORITHM_MISMATCH;
            message = "JWT algorithm not permitted";
        } else if (ex instanceof MalformedJwtException) {
            status = HttpStatus.UNAUTHORIZED;
            errorCode = ErrorCode.INVALID_TOKEN;
            message = "Token is malformed or corrupted";
        } else if (ex instanceof JwtAuthenticationException jae) {
            status = HttpStatus.UNAUTHORIZED;
            errorCode = jae.getErrorCode();
            message = jae.getMessage();
        } else if (ex instanceof JwtException) {
            status = HttpStatus.UNAUTHORIZED;
            errorCode = ErrorCode.INVALID_TOKEN;
            message = "Token validation failed";
        } else if (ex instanceof AccessDeniedException) {
            status = HttpStatus.FORBIDDEN;
            errorCode = ErrorCode.INSUFFICIENT_PERMISSIONS;
            message = "Access denied";
        } else {
            status = HttpStatus.INTERNAL_SERVER_ERROR;
            errorCode = ErrorCode.INTERNAL_ERROR;
            message = "An internal error occurred";
            log.error("Unhandled exception path={} traceId={}: {}", path, traceId, ex.getMessage(), ex);
        }

        log.warn("GlobalExceptionHandler status={} error={} path={} traceId={}",
                status.value(), errorCode, path, traceId);

        return writeError(exchange, status, errorCode, message, traceId, path);
    }

    private Mono<Void> writeError(ServerWebExchange exchange, HttpStatus status, ErrorCode errorCode,
                                   String message, String traceId, String path) {
        ServerHttpResponse response = exchange.getResponse();
        if (response.isCommitted()) {
            return Mono.error(new IllegalStateException("Response already committed"));
        }
        response.setStatusCode(status);
        response.getHeaders().setContentType(MediaType.APPLICATION_JSON);

        ErrorResponse body = ErrorResponse.builder()
                .error(errorCode.name())
                .message(message)
                .traceId(traceId)
                .timestamp(Instant.now().toString())
                .path(path)
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
}
