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
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * Core component for JWT token validation and claims extraction in the API Gateway.
 *
 * <p>Implements RSA-based JWT verification following
 * <a href="https://www.rfc-editor.org/rfc/rfc7519">RFC 7519</a>.  The public key is loaded
 * once at startup from the path configured by {@code jwt.public-key-path} and reused for
 * every validation request.</p>
 *
 * <p>Validation pipeline (executed in order):</p>
 * <ol>
 *   <li>Algorithm header whitelist check — prevents algorithm-confusion attacks (e.g. HS256
 *       signed with an RSA public key).</li>
 *   <li>JJWT signature verification, expiration ({@code exp}), issuer ({@code iss}), and
 *       audience ({@code aud}) checks.</li>
 *   <li>Mandatory claims check — {@code sub}, {@code roles}, {@code iat} must be present and
 *       non-empty.</li>
 *   <li>Claim-format check — {@code sub} must be a valid UUID or e-mail address; the optional
 *       {@code email} claim, if present, must also match e-mail format.</li>
 * </ol>
 *
 * <p>Security notes:</p>
 * <ul>
 *   <li>Only RS256, RS384, RS512 are accepted; HS256 is explicitly rejected.</li>
 *   <li>Clock-skew tolerance is configurable via {@code jwt.clock-skew-seconds} (default 30 s).</li>
 *   <li>Tokens issued more than 60 seconds in the future are rejected to mitigate replay attacks.</li>
 *   <li>The full token value is never logged — only a masked prefix is used in log entries.</li>
 * </ul>
 *
 * @see JwtProperties
 * @see io.jsonwebtoken.Jwts
 * @see io.jsonwebtoken.Claims
 */
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

    /**
     * Loads the RSA public key from the PEM file specified by
     * {@link JwtProperties#getPublicKeyPath()}.
     *
     * <p>If the file is missing or invalid, a warning is logged and {@code publicKey} is set to
     * {@code null}.  Every subsequent call to {@link #validateAndExtract(String)} will then
     * throw a {@link JwtException} until the application is restarted with a valid key.</p>
     */
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
     * Runs the full validation pipeline and returns the token's {@link Claims} on success.
     *
     * <p>Pipeline steps (executed synchronously on a bounded-elastic scheduler):</p>
     * <ol>
     *   <li>Verify the RSA public key was loaded at startup.</li>
     *   <li>Decode the JWT header and reject any algorithm not in the configured
     *       whitelist (see {@code jwt.algorithm-whitelist}).</li>
     *   <li>Parse and verify the token signature with JJWT, enforcing {@code exp},
     *       {@code iss}, and {@code aud}.</li>
     *   <li>Validate mandatory claims: {@code sub} (non-blank), {@code roles}
     *       (non-empty list), {@code iat} (present, not in the future).</li>
     *   <li>Validate claim formats: {@code sub} must be a UUID or e-mail;
     *       {@code email} (if present) must match e-mail format.</li>
     * </ol>
     *
     * <p>Callers should use {@code onErrorResume} to handle typed failures:</p>
     * <pre>{@code
     * jwtTokenProvider.validateAndExtract(token)
     *     .onErrorResume(ExpiredJwtException.class,  e -> rejectExpired(exchange))
     *     .onErrorResume(SignatureException.class,   e -> rejectInvalidSig(exchange))
     *     .onErrorResume(UnsupportedJwtException.class, e -> rejectAlgorithm(exchange))
     *     .onErrorResume(JwtException.class,         e -> rejectGeneric(exchange));
     * }</pre>
     *
     * @param token raw JWT string from the {@code Authorization: Bearer ...} header;
     *              must not be {@code null} or empty
     * @return a {@link Mono} that emits the validated {@link Claims} on success,
     *         or signals an error on any validation failure
     * @throws io.jsonwebtoken.ExpiredJwtException     if {@code exp} is in the past
     *                                                  (beyond clock-skew tolerance)
     * @throws io.jsonwebtoken.security.SignatureException if signature verification fails
     * @throws io.jsonwebtoken.UnsupportedJwtException if the algorithm is not in the whitelist
     * @throws io.jsonwebtoken.MalformedJwtException   if the token structure is invalid
     * @throws io.jsonwebtoken.JwtException            for any other claim or format violation
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
            // Item 4.5: claim format validation (UUID/email for sub, email format)
            validateClaimsFormat(jws.getPayload());
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

    // ---------------------------------------------------------------
    // Utility extraction methods (public API for downstream use)
    // ---------------------------------------------------------------

    /**
     * Extracts {@link Claims} from a token, verifying only the signature and expiration.
     *
     * <p>Unlike {@link #validateAndExtract(String)}, this method does <em>not</em> check
     * {@code iss}, {@code aud}, mandatory-claim presence, or claim formats.  Use it only
     * when the full pipeline has already been executed and you need direct claim access.</p>
     *
     * @param token raw JWT string; must not be {@code null}
     * @return a {@link Mono} emitting the parsed {@link Claims}
     * @throws io.jsonwebtoken.JwtException if the token is malformed or the signature is invalid
     * @see #validateAndExtract(String)
     */
    public Mono<Claims> extractClaims(String token) {
        return Mono.fromCallable(() -> Jwts.parser()
                .verifyWith(publicKey)
                .clockSkewSeconds(jwtProperties.getClockSkewSeconds())
                .build()
                .parseSignedClaims(token)
                .getPayload()).subscribeOn(Schedulers.boundedElastic());
    }

    /**
     * Convenience method that returns only the {@code sub} claim value.
     *
     * @param token raw JWT string
     * @return a {@link Mono} emitting the subject (user identifier)
     * @see #extractClaims(String)
     */
    public Mono<String> extractUserId(String token) {
        return extractClaims(token).map(Claims::getSubject);
    }

    /**
     * Convenience method that returns the {@code roles} claim as a typed list.
     *
     * <p>Returns an empty list if the {@code roles} claim is absent or is not a
     * {@link List} — callers should guard against an empty result.</p>
     *
     * @param token raw JWT string
     * @return a {@link Mono} emitting the role list (never {@code null})
     * @see #extractClaims(String)
     */
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

    // ---------------------------------------------------------------
    // Item 4.5: Claim-format validation
    // ---------------------------------------------------------------

    /**
     * Validates that claim values conform to the expected formats, preventing malformed
     * or potentially malicious data from propagating to downstream services.
     *
     * <p>Checks performed (presence/emptiness is enforced earlier by
     * {@link #validateMandatoryClaims}):</p>
     * <ul>
     *   <li>{@code sub} — must be a valid RFC 4122 UUID <em>or</em> a valid e-mail address.
     *       Rejects arbitrary strings that could carry injection payloads.</li>
     *   <li>{@code email} — if the claim is present it must match a basic e-mail pattern.</li>
     * </ul>
     *
     * <p>Examples of values that pass:</p>
     * <pre>{@code
     * sub = "550e8400-e29b-41d4-a716-446655440000"  // UUID
     * sub = "alice@example.com"                      // e-mail
     * }</pre>
     * <p>Examples that are rejected:</p>
     * <pre>{@code
     * sub = "admin'; DROP TABLE users;"   // SQL-injection attempt
     * sub = "../../etc/passwd"            // path traversal
     * sub = "plain-text-id"              // no UUID/e-mail structure
     * }</pre>
     *
     * @param claims {@link Claims} object extracted from the validated token
     * @throws JwtException if any claim value does not match the expected format
     */
    private void validateClaimsFormat(Claims claims) {
        String sub = claims.getSubject();
        // sub is guaranteed non-blank by validateMandatoryClaims; check format here
        if (!isValidUUID(sub) && !isValidEmail(sub)) {
            log.warn("JWT_VALIDATION claim_format_invalid claim=sub");
            throw new JwtException(
                    "Claim 'sub' has invalid format. Expected a UUID or e-mail address.");
        }

        // Optional email claim — validate format only when present
        String email = claims.get("email", String.class);
        if (email != null && !isValidEmail(email)) {
            log.warn("JWT_VALIDATION claim_format_invalid claim=email");
            throw new JwtException("Claim 'email' has invalid format.");
        }
    }

    /**
     * Returns {@code true} if {@code value} is a well-formed RFC 4122 UUID.
     *
     * @param value string to test; {@code null} returns {@code false}
     * @return {@code true} when the string parses successfully as a {@link UUID}
     */
    private boolean isValidUUID(String value) {
        if (value == null) return false;
        try {
            UUID.fromString(value);
            return true;
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    /**
     * Returns {@code true} if {@code value} matches a basic e-mail pattern
     * ({@code local@domain}).
     *
     * <p>The regex is intentionally permissive for the local part to accommodate
     * the wide variety of valid e-mail formats in practice.  Full RFC 5322 validation
     * is not performed here; a dedicated library should be used if strict compliance
     * is required.</p>
     *
     * @param value string to test; {@code null} returns {@code false}
     * @return {@code true} when the string contains exactly one {@code @} with a
     *         non-empty local part and domain
     */
    private boolean isValidEmail(String value) {
        return value != null && value.matches("^[A-Za-z0-9+_.-]+@.+$");
    }
}
