package com.ProdeMaster.ApiGateWay.dto;

import com.fasterxml.jackson.annotation.JsonInclude;

@JsonInclude(JsonInclude.Include.NON_NULL)
public class ErrorResponse {

    private String error;
    private String message;
    private String traceId;
    private String timestamp;
    private String path;

    private ErrorResponse() {}

    public String getError() { return error; }
    public String getMessage() { return message; }
    public String getTraceId() { return traceId; }
    public String getTimestamp() { return timestamp; }
    public String getPath() { return path; }

    public static Builder builder() { return new Builder(); }

    public static class Builder {
        private final ErrorResponse instance = new ErrorResponse();

        public Builder error(String error) { instance.error = error; return this; }
        public Builder message(String message) { instance.message = message; return this; }
        public Builder traceId(String traceId) { instance.traceId = traceId; return this; }
        public Builder timestamp(String timestamp) { instance.timestamp = timestamp; return this; }
        public Builder path(String path) { instance.path = path; return this; }
        public ErrorResponse build() { return instance; }
    }
}
