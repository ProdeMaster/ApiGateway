package com.ProdeMaster.ApiGateWay.Config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * Centralized JWT configuration properties (prefix: jwt.*).
 * Replaces scattered @Value injections across security classes.
 */
@Component
@ConfigurationProperties(prefix = "jwt")
public class JwtProperties {

    private String publicKeyPath = "classpath:certs/public.pem";
    private String issuer;
    private String audience;
    private long clockSkewSeconds = 30;
    private boolean loggingVerbose = false;
    private long validationTimeoutMs = 500;
    private List<String> publicPaths = List.of("/actuator/health", "/actuator/health/**");
    private List<String> algorithmWhitelist = List.of("RS256", "RS384", "RS512");

    public String getPublicKeyPath() { return publicKeyPath; }
    public void setPublicKeyPath(String publicKeyPath) { this.publicKeyPath = publicKeyPath; }

    public String getIssuer() { return issuer; }
    public void setIssuer(String issuer) { this.issuer = issuer; }

    public String getAudience() { return audience; }
    public void setAudience(String audience) { this.audience = audience; }

    public long getClockSkewSeconds() { return clockSkewSeconds; }
    public void setClockSkewSeconds(long clockSkewSeconds) { this.clockSkewSeconds = clockSkewSeconds; }

    public boolean isLoggingVerbose() { return loggingVerbose; }
    public void setLoggingVerbose(boolean loggingVerbose) { this.loggingVerbose = loggingVerbose; }

    public long getValidationTimeoutMs() { return validationTimeoutMs; }
    public void setValidationTimeoutMs(long validationTimeoutMs) { this.validationTimeoutMs = validationTimeoutMs; }

    public List<String> getPublicPaths() { return publicPaths; }
    public void setPublicPaths(List<String> publicPaths) { this.publicPaths = publicPaths; }

    public List<String> getAlgorithmWhitelist() { return algorithmWhitelist; }
    public void setAlgorithmWhitelist(List<String> algorithmWhitelist) { this.algorithmWhitelist = algorithmWhitelist; }
}
