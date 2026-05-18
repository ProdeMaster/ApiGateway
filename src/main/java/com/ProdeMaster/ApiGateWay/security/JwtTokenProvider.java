package com.ProdeMaster.ApiGateWay.security;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.SignatureException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import jakarta.annotation.PostConstruct;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.List;

@Component
public class JwtTokenProvider {

    private static final Logger log = LoggerFactory.getLogger(JwtTokenProvider.class);

    @Value("${jwt.public-key-path}")
    private String publicKeyPath;

    @Value("${jwt.clock-skew-seconds:30}")
    private long clockSkewSeconds;

    @Value("${jwt.logging.verbose:false}")
    private boolean verboseLogging;

    private final ResourceLoader resourceLoader;
    private PublicKey publicKey;

    public JwtTokenProvider(ResourceLoader resourceLoader) {
        this.resourceLoader = resourceLoader;
    }

    @PostConstruct
    public void init() {
        try {
            Resource resource = resourceLoader.getResource(publicKeyPath);
            try (InputStream is = resource.getInputStream()) {
                String pem = new String(is.readAllBytes(), StandardCharsets.UTF_8);
                publicKey = parsePemPublicKey(pem);
                log.info("RSA public key loaded from: {}", publicKeyPath);
            }
        } catch (Exception e) {
            log.error(
                    "Failed to load RSA public key from '{}': {}. " +
                            "Generate a key pair with: openssl genrsa -out private.pem 2048 && " +
                            "openssl rsa -in private.pem -pubout -out public.pem. " +
                            "All protected routes will return 401 until a valid key is configured.",
                    publicKeyPath, e.getMessage());
            publicKey = null;
        }
    }

    private PublicKey parsePemPublicKey(String pem) throws Exception {
        String stripped = pem
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s+", "");
        byte[] decoded = Base64.getDecoder().decode(stripped);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(decoded);
        return KeyFactory.getInstance("RSA").generatePublic(spec);
    }

    /**
     * Validates a JWT signed with RSA. Rejects HS256 and other symmetric algorithms
     * because verifyWith(PublicKey) only accepts asymmetric keys.
     */
    public Mono<Boolean> validateToken(String token, String expectedIssuer, String expectedAudience) {
        return Mono.fromCallable(() -> {
            if (publicKey == null) {
                log.warn("JWT validation skipped: RSA public key is not loaded.");
                return false;
            }
            try {
                Jwts.parser()
                        .verifyWith(publicKey)
                        .requireIssuer(expectedIssuer)
                        .requireAudience(expectedAudience)
                        .clockSkewSeconds(clockSkewSeconds)
                        .build()
                        .parseSignedClaims(token);
                return true;
            } catch (ExpiredJwtException e) {
                if (verboseLogging)
                    log.warn("JWT expired: {}", e.getMessage());
                return false;
            } catch (MalformedJwtException e) {
                if (verboseLogging)
                    log.warn("JWT malformed: {}", e.getMessage());
                return false;
            } catch (SignatureException e) {
                if (verboseLogging)
                    log.warn("JWT signature invalid: {}", e.getMessage());
                return false;
            } catch (UnsupportedJwtException e) {
                if (verboseLogging)
                    log.warn("JWT algorithm unsupported (HS256 rejected): {}", e.getMessage());
                return false;
            } catch (JwtException e) {
                if (verboseLogging)
                    log.warn("JWT error: {}", e.getMessage());
                return false;
            }
        }).subscribeOn(Schedulers.boundedElastic());
    }

    public Mono<Claims> extractClaims(String token) {
        return Mono.fromCallable(() -> Jwts.parser()
                .verifyWith(publicKey)
                .clockSkewSeconds(clockSkewSeconds)
                .build()
                .parseSignedClaims(token)
                .getPayload()).subscribeOn(Schedulers.boundedElastic());
    }

    public Mono<String> extractUserId(String token) {
        return extractClaims(token).map(Claims::getSubject);
    }

    @SuppressWarnings("unchecked")
    public Mono<List<String>> extractRoles(String token) {
        return extractClaims(token).map(claims -> {
            Object roles = claims.get("roles");
            if (roles instanceof List<?> list) {
                return (List<String>) list;
            }
            return List.of();
        });
    }
}
