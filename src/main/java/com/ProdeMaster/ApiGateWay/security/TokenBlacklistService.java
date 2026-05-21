package com.ProdeMaster.ApiGateWay.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.util.Base64;

/**
 * Maintains a blacklist of revoked JWT tokens in Redis.
 * Tokens are stored by jti (or SHA-256 hash) with TTL = remaining token
 * lifetime,
 * so Redis never holds stale data after the token would have expired anyway.
 */
@Service
public class TokenBlacklistService {

    private static final Logger log = LoggerFactory.getLogger(TokenBlacklistService.class);
    private static final String PREFIX = "jwt:blacklist:";

    private final StringRedisTemplate redisTemplate;

    public TokenBlacklistService(StringRedisTemplate redisTemplate) {
        this.redisTemplate = redisTemplate;
    }

    /**
     * Adds a token identifier to the blacklist.
     *
     * @param jti                   the JWT ID claim, or a unique token fingerprint
     *                              if jti is absent
     * @param expirationTimeSeconds TTL for the Redis key — matches the token's
     *                              remaining lifetime
     */
    public Mono<Void> revokeToken(String jti, long expirationTimeSeconds) {
        return Mono.fromRunnable(() -> {
            if (expirationTimeSeconds <= 0) {
                // Token is already expired — no need to store it
                log.debug("TOKEN_BLACKLIST skip_revoke already_expired jti={}", jti);
                return;
            }
            String key = PREFIX + jti;
            redisTemplate.opsForValue().set(key, "revoked", Duration.ofSeconds(expirationTimeSeconds));
            log.info("TOKEN_BLACKLIST token_revoked jti={} ttl_s={}", jti, expirationTimeSeconds);
        }).subscribeOn(Schedulers.boundedElastic()).then();
    }

    /**
     * Checks whether a token has been revoked.
     *
     * @param jti the JWT ID claim, or a unique token fingerprint
     * @return true if the token is in the blacklist
     */
    public Mono<Boolean> isTokenBlacklisted(String jti) {
        return Mono.fromCallable(() -> {
            String key = PREFIX + jti;
            Boolean exists = redisTemplate.hasKey(key);
            boolean blacklisted = Boolean.TRUE.equals(exists);
            if (blacklisted) {
                log.debug("TOKEN_BLACKLIST hit jti={}", jti);
            }
            return blacklisted;
        }).subscribeOn(Schedulers.boundedElastic());
    }

    /**
     * Computes a stable, compact fingerprint for tokens that lack a jti claim.
     * Uses SHA-256 so the original token value is never stored.
     */
    public static String tokenFingerprint(String rawToken) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(rawToken.getBytes(StandardCharsets.UTF_8));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }
}
