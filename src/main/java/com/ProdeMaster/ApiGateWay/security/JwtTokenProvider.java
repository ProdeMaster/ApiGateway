package com.ProdeMaster.ApiGateWay.security;

import com.ProdeMaster.ApiGateWay.Config.JwtProperties;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
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
import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;

@Component
public class JwtTokenProvider {

    private static final Logger log = LoggerFactory.getLogger(JwtTokenProvider.class);

    private final ResourceLoader resourceLoader;
    private final JwtProperties jwtProperties;
    private final ObjectMapper objectMapper;
    private PublicKey publicKey;

    public JwtTokenProvider(ResourceLoader resourceLoader,
            JwtProperties jwtProperties,
            ObjectMapper objectMapper) {
        this.resourceLoader = resourceLoader;
        this.jwtProperties = jwtProperties;
        this.objectMapper = objectMapper;
    }

    @PostConstruct
    public void init() {
        try {
            Resource resource = resourceLoader.getResource(jwtProperties.getPublicKeyPath());
            try (InputStream is = resource.getInputStream()) {
                String pem = new String(is.readAllBytes(), StandardCharsets.UTF_8);
                publicKey = parsePemPublicKey(pem);
                log.info("RSA public key loaded from: {}", jwtProperties.getPublicKeyPath());
            }
        } catch (Exception e) {
            log.error(
                    "Failed to load RSA public key from '{}': {}. " +
                            "Generate with: openssl genrsa -out private.pem 2048 && " +
                            "openssl rsa -in private.pem -pubout -out public.pem. " +
                            "All protected routes will return 401 until a valid key is configured.",
                    jwtProperties.getPublicKeyPath(), e.getMessage());
            publicKey = null;
        }
    }

    private PublicKey parsePemPublicKey(String pem) throws Exception {
        // Filter comment lines (# ...) before stripping PEM markers
        String stripped = pem.lines()
                .filter(line -> !line.strip().startsWith("#"))
                .collect(Collectors.joining("\n"))
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s+", "");
        byte[] decoded = Base64.getDecoder().decode(stripped);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(decoded);
        return KeyFactory.getInstance("RSA").generatePublic(spec);
    }

    /**
     * Full validation pipeline: algorithm check → signature/claims verify →
     * mandatory claims.
     * Returns Claims on success; signals specific JwtException subtypes on failure
     * so callers can use onErrorResume for typed error handling.
     *
     * Item 2.2 + 2.3: validateMandatoryClaims + validateAlgorithmHeader integrated
     * here.
     */
    public Mono<Claims> validateAndExtract(String token) {
        return Mono.fromCallable(() -> {
            if (publicKey == null) {
                throw new JwtException("RSA public key not loaded. Check startup logs for details.");
            }
            // Item 2.3: algorithm whitelist check (before JJWT parsing)
            validateAlgorithmHeader(token);

            // JJWT verifies signature, exp, iss, aud
            Jws<Claims> jws = Jwts.parser()
                    .verifyWith(publicKey)
                    .requireIssuer(jwtProperties.getIssuer())
                    .requireAudience(jwtProperties.getAudience())
                    .clockSkewSeconds(jwtProperties.getClockSkewSeconds())
                    .build()
                    .parseSignedClaims(token);

            // Item 2.2: mandatory claims validation (post-parse)
            validateMandatoryClaims(jws);
            return jws.getPayload();

        }).subscribeOn(Schedulers.boundedElastic());
    }

    /**
     * Item 2.3: Validates algorithm from JWT header against whitelist.
     * Prevents algorithm confusion attacks (e.g., HS256 with a public key).
     */
    private void validateAlgorithmHeader(String token) {
        try {
            String[] parts = token.split("\\.");
            if (parts.length < 2) {
                throw new MalformedJwtException("Invalid JWT structure: missing header or payload");
            }
            byte[] headerBytes = Base64.getUrlDecoder().decode(addBase64Padding(parts[0]));
            JsonNode header = objectMapper.readTree(headerBytes);
            String alg = header.path("alg").asText();

            if (alg.isBlank()) {
                throw new MalformedJwtException("JWT header missing 'alg' field");
            }
            List<String> whitelist = jwtProperties.getAlgorithmWhitelist();
            if (!whitelist.contains(alg)) {
                log.warn("JWT_SECURITY algorithm_rejected alg={} permitted={}", alg, whitelist);
                throw new UnsupportedJwtException(String.format(
                        "Algorithm '%s' rejected. Only permitted: %s. Possible algorithm confusion attack.",
                        alg, whitelist));
            }
        } catch (UnsupportedJwtException | MalformedJwtException e) {
            throw e;
        } catch (Exception e) {
            throw new MalformedJwtException("JWT header could not be parsed: " + e.getMessage());
        }
    }

    /**
     * Item 2.2: Validates mandatory claims present and non-empty after signature
     * verification.
     */
    private void validateMandatoryClaims(Jws<Claims> jws) {
        Claims claims = jws.getPayload();

        // sub: must be present and non-empty
        String subject = claims.getSubject();
        if (subject == null || subject.isBlank()) {
            log.warn("JWT_VALIDATION claim_missing claim=sub");
            throw new JwtException("Subject (sub) claim is missing or empty");
        }

        // roles: must be present and non-empty list
        Object roles = claims.get("roles");
        if (roles == null) {
            log.warn("JWT_VALIDATION claim_missing claim=roles subject={}", subject);
            throw new JwtException("Roles claim is missing");
        }
        if (roles instanceof List<?> rolesList && rolesList.isEmpty()) {
            log.warn("JWT_VALIDATION claim_empty claim=roles subject={}", subject);
            throw new JwtException("Roles claim is empty. At least one role is required.");
        }

        // iat: must be present and not in the future (skew tolerance not applied here)
        Date issuedAt = claims.getIssuedAt();
        if (issuedAt == null) {
            log.warn("JWT_VALIDATION claim_missing claim=iat subject={}", subject);
            throw new JwtException("IssuedAt (iat) claim is missing");
        }
        if (issuedAt.after(new Date(System.currentTimeMillis() + 60_000L))) {
            // Allow 60s future tolerance for minor clock differences
            log.warn("JWT_VALIDATION token_from_future subject={} iat={}", subject, issuedAt.toInstant());
            throw new JwtException("Token issued in the future. Possible clock skew or replay attack.");
        }

        // exp: validated automatically by JJWT (clockSkewSeconds applied)
    }

    private String addBase64Padding(String base64) {
        return switch (base64.length() % 4) {
            case 2 -> base64 + "==";
            case 3 -> base64 + "=";
            default -> base64;
        };
    }

    // --- Utility extraction methods (used externally if needed) ---

    public Mono<Claims> extractClaims(String token) {
        return Mono.fromCallable(() -> Jwts.parser()
                .verifyWith(publicKey)
                .clockSkewSeconds(jwtProperties.getClockSkewSeconds())
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
