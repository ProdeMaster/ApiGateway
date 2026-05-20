package com.ProdeMaster.ApiGateWay.exception;

import com.ProdeMaster.ApiGateWay.dto.ErrorCode;
import io.jsonwebtoken.JwtException;

public class JwtAuthenticationException extends JwtException {

    private final ErrorCode errorCode;

    public JwtAuthenticationException(String message, ErrorCode errorCode) {
        super(message);
        this.errorCode = errorCode;
    }

    public JwtAuthenticationException(String message, ErrorCode errorCode, Throwable cause) {
        super(message, cause);
        this.errorCode = errorCode;
    }

    public ErrorCode getErrorCode() { return errorCode; }
}
