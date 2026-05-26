package com.ProdeMaster.ApiGateWay.fixtures;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.*;

/**
 * Generates a single RSA key pair per test session and provides helpers for building
 * JWT fixtures (valid, expired, malformed, etc.) that match the test public key.
 *
 * Keys are test-only — they have no production significance.
 */
public final class TestTokenFactory {

    public static final String ISSUER   = "https://auth.prodemaster.com";
    public static final String AUDIENCE  = "https://api.prodemaster.com";
    public static final String SUBJECT   = "550e8400-e29b-41d4-a716-446655440000";
    public static final List<String> ROLES = List.of("ADMIN", "USER");

    private static final KeyPair KEY_PAIR;

    static {
        try {
            KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
            gen.initialize(2048);
            KEY_PAIR = gen.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new ExceptionInInitializerError(e);
        }
    }

    private TestTokenFactory() {}

    // ---- Key accessors ----

    public static PublicKey getPublicKey() {
        return KEY_PAIR.getPublic();
    }

    /** Returns a PEM-encoded RSA public key suitable for configuring JwtTokenProvider. */
    public static String getPublicKeyPem() {
        byte[] encoded = KEY_PAIR.getPublic().getEncoded();
        String b64 = Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.UTF_8))
                           .encodeToString(encoded);
        return "-----BEGIN PUBLIC KEY-----\n" + b64 + "\n-----END PUBLIC KEY-----\n";
    }

    // ---- Token generators ----

    /** Standard valid RS256 token with SUBJECT, ROLES, ISSUER, AUDIENCE and 1-hour TTL. */
    public static String generateValidToken() {
        return buildRsaToken(SUBJECT, ISSUER, AUDIENCE, ROLES, 3_600, null);
    }

    /** Valid token with a specific jti (used for blacklist tests). */
    public static String generateTokenWithJti(String jti) {
        return buildRsaToken(SUBJECT, ISSUER, AUDIENCE, ROLES, 3_600, jti);
    }

    /** Token that was issued 2 h ago and expired 1 h ago — well outside the 30 s clock-skew window. */
    public static String generateExpiredToken() {
        long now = System.currentTimeMillis();
        return Jwts.builder()
                .subject(SUBJECT)
                .issuer(ISSUER)
                .audience().add(AUDIENCE).and()
                .claim("roles", ROLES)
                .issuedAt(new Date(now - 7_200_000L))
                .expiration(new Date(now - 3_600_000L))
                .signWith(KEY_PAIR.getPrivate())
                .compact();
    }

    /**
     * Token signed with an HMAC-SHA256 key (HS256).
     * Used to verify algorithm-confusion attack prevention.
     */
    public static String generateHS256Token() {
        byte[] secret = new byte[32];
        new SecureRandom().nextBytes(secret);
        SecretKey hmacKey = Keys.hmacShaKeyFor(secret);
        long now = System.currentTimeMillis();
        return Jwts.builder()
                .subject(SUBJECT)
                .issuer(ISSUER)
                .claim("roles", ROLES)
                .issuedAt(new Date(now))
                .expiration(new Date(now + 3_600_000L))
                .signWith(hmacKey)
                .compact();
    }

    /** Structurally invalid string — not Base64URL-encoded JWT parts. */
    public static String generateMalformedToken() {
        return "not-a-jwt-token";
    }

    /** Valid structure and algorithm but the signature bytes are random garbage. */
    public static String generateInvalidSignatureToken() {
        String valid  = generateValidToken();
        String[] parts = valid.split("\\.");
        byte[] fakeBytes = new byte[256];
        new SecureRandom().nextBytes(fakeBytes);
        return parts[0] + "." + parts[1] + "."
                + Base64.getUrlEncoder().withoutPadding().encodeToString(fakeBytes);
    }

    /** Valid token but iss = "https://wrong-issuer.com". */
    public static String generateWrongIssuerToken() {
        return buildRsaToken(SUBJECT, "https://wrong-issuer.com", AUDIENCE, ROLES, 3_600, null);
    }

    /** Valid token but aud = "https://wrong-audience.com". */
    public static String generateWrongAudienceToken() {
        return buildRsaToken(SUBJECT, ISSUER, "https://wrong-audience.com", ROLES, 3_600, null);
    }

    /** Token with no `sub` claim. */
    public static String generateNoSubjectToken() {
        long now = System.currentTimeMillis();
        return Jwts.builder()
                .issuer(ISSUER)
                .audience().add(AUDIENCE).and()
                .claim("roles", ROLES)
                .issuedAt(new Date(now))
                .expiration(new Date(now + 3_600_000L))
                .signWith(KEY_PAIR.getPrivate())
                .compact();
    }

    /** Token with no `roles` claim. */
    public static String generateNoRolesToken() {
        long now = System.currentTimeMillis();
        return Jwts.builder()
                .subject(SUBJECT)
                .issuer(ISSUER)
                .audience().add(AUDIENCE).and()
                .issuedAt(new Date(now))
                .expiration(new Date(now + 3_600_000L))
                .signWith(KEY_PAIR.getPrivate())
                .compact();
    }

    /** Token with an empty roles list. */
    public static String generateEmptyRolesToken() {
        long now = System.currentTimeMillis();
        return Jwts.builder()
                .subject(SUBJECT)
                .issuer(ISSUER)
                .audience().add(AUDIENCE).and()
                .claim("roles", Collections.emptyList())
                .issuedAt(new Date(now))
                .expiration(new Date(now + 3_600_000L))
                .signWith(KEY_PAIR.getPrivate())
                .compact();
    }

    /** Token with no `iat` claim. */
    public static String generateNoIatToken() {
        long now = System.currentTimeMillis();
        return Jwts.builder()
                .subject(SUBJECT)
                .issuer(ISSUER)
                .audience().add(AUDIENCE).and()
                .claim("roles", ROLES)
                .expiration(new Date(now + 3_600_000L))
                // intentionally no .issuedAt()
                .signWith(KEY_PAIR.getPrivate())
                .compact();
    }

    // ---- Private helpers ----

    private static String buildRsaToken(String subject, String issuer, String audience,
                                         List<String> roles, int validForSeconds, String jti) {
        long now = System.currentTimeMillis();
        var builder = Jwts.builder()
                .subject(subject)
                .issuer(issuer)
                .audience().add(audience).and()
                .claim("roles", roles)
                .issuedAt(new Date(now))
                .expiration(new Date(now + (long) validForSeconds * 1_000))
                .signWith(KEY_PAIR.getPrivate());
        if (jti != null) {
            builder.id(jti);
        }
        return builder.compact();
    }
}
