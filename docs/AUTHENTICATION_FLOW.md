# Authentication Flow — API Gateway

## Overview

The API Gateway validates JWT tokens signed with RSA before forwarding requests to downstream microservices.
Valid tokens are never forwarded; instead, the gateway extracts the user identity and injects it as trusted HTTP headers.

---

## Architecture Diagram

```
Client                  API Gateway (8765)         Downstream Service
  |                           |                            |
  |  POST /users/auth/login   |                            |
  |-------------------------->| (public path, no JWT)      |
  |                           |-------(forwarded)--------->|
  |                           |<-------- JWT token --------|
  |<--- { "token": "eyJ..." } |                            |
  |                           |                            |
  |  GET /users/profile       |                            |
  |  Authorization: Bearer eyJ|                            |
  |-------------------------->|                            |
  |            1. Check public paths                       |
  |            2. Extract Bearer token                     |
  |            3. Validate RSA signature                   |
  |            4. Validate claims (sub, roles, iat, exp,   |
  |               iss, aud)                                |
  |            5. Check token blacklist (Redis)            |
  |            6. Record Prometheus metrics                |
  |            7. Check rate limit (Bucket4j)              |
  |            8. Inject X-User-Id, X-Roles headers        |
  |            9. Remove Authorization header              |
  |                           |------- GET /profile ------>|
  |                           |    X-User-Id: user-123     |
  |                           |    X-Roles: USER           |
  |                           |    X-Auth-Source: jwt      |
  |                           |<------- 200 OK ------------|
  |<---------- 200 OK --------|                            |
```

---

## Step-by-step Flow

### 1. Obtain a Token

The client authenticates against the **UserService** (not the Gateway).
UserService generates a signed JWT and returns it in the response body.

```bash
curl -X POST http://api-gateway:8765/users/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email": "user@example.com", "password": "secret"}'
```

```json
{ "token": "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyLTEyMyIs..." }
```

### 2. Call a Protected Endpoint

Include the token in the `Authorization: Bearer` header.

```bash
curl -X GET http://api-gateway:8765/users/profile \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiJ9..."
```

### 3. Gateway Validation Pipeline

For every protected request, the `JwtAuthenticationFilter` (order -100) runs:

| Step | Action | Failure response |
|------|--------|-----------------|
| 1 | Check if path matches `jwt.public-paths` | — (skip filter) |
| 2 | Verify `Authorization: Bearer` header present | `401 MISSING_TOKEN` |
| 3 | Validate RSA signature with public key | `401 INVALID_SIGNATURE` |
| 4 | Verify algorithm is RS256/RS384/RS512 | `401 ALGORITHM_MISMATCH` |
| 5 | Check `iss`, `aud`, `exp`, `iat`, `sub`, `roles` | `401 CLAIM_VALIDATION_FAILED` |
| 6 | Check token not in Redis blacklist | `401 TOKEN_REVOKED` |

### 4. Rate Limiting

After JWT validation, `RateLimitingFilter` (order -90) applies per-user limits.
Authenticated users are bucketed by `userId`; anonymous requests by client IP.

| Condition | Response |
|-----------|----------|
| Within limit | Request forwarded, `X-RateLimit-*` headers added |
| Over limit | `429 TOO_MANY_REQUESTS` + `Retry-After` header |

### 5. Header Propagation

On success, the gateway removes `Authorization` and injects:

| Header | Value | Purpose |
|--------|-------|---------|
| `X-User-Id` | JWT `sub` claim | Downstream user identity |
| `X-Roles` | JWT `roles` claim (comma-separated) | Authorization in downstream |
| `X-Token-Issued-At` | JWT `iat` as epoch ms | Audit / cache validation |
| `X-Auth-Source` | `jwt` | Indicates validated by gateway |

Downstream services **must** trust these headers and **must not** re-validate the JWT.

---

## JWT Payload Structure

```json
{
  "sub":   "user-123",
  "roles": ["USER"],
  "iss":   "https://auth.prodemaster.com",
  "aud":   "https://api.prodemaster.com",
  "iat":   1715612745,
  "exp":   1715699145,
  "jti":   "550e8400-e29b-41d4-a716-446655440000"
}
```

| Claim | Required | Description |
|-------|----------|-------------|
| `sub` | yes | User identifier (propagated as `X-User-Id`) |
| `roles` | yes | Non-empty list of role strings |
| `iss` | yes | Must match `jwt.issuer` in config |
| `aud` | yes | Must match `jwt.audience` in config |
| `iat` | yes | Issue time — rejects tokens issued >60s in the future |
| `exp` | yes | Expiry — enforced by JJWT with `jwt.clock-skew-seconds` tolerance |
| `jti` | recommended | Unique token ID used as Redis blacklist key |

---

## Error Codes Reference

All error responses follow the same JSON structure:

```json
{
  "error":     "EXPIRED_TOKEN",
  "message":   "Token expired",
  "traceId":   "abc123...",
  "timestamp": "2024-05-13T10:30:00Z",
  "path":      "/users/profile"
}
```

| Error code | HTTP | Cause |
|-----------|------|-------|
| `MISSING_TOKEN` | 401 | No `Authorization: Bearer` header |
| `INVALID_TOKEN` | 401 | Malformed / unparseable JWT |
| `EXPIRED_TOKEN` | 401 | `exp` claim is in the past |
| `INVALID_SIGNATURE` | 401 | RSA signature does not match public key |
| `ALGORITHM_MISMATCH` | 401 | Algorithm is not RS256/RS384/RS512 |
| `CLAIM_VALIDATION_FAILED` | 401 | Missing `sub`, `roles`, wrong `iss`/`aud` |
| `TOKEN_REVOKED` | 401 | Token found in Redis blacklist (logout/password change) |
| `TOO_MANY_REQUESTS` | 429 | Rate limit exceeded |

---

## Token Revocation (Blacklist)

When a user logs out or changes their password, the UserService should call:

```bash
POST http://api-gateway:8765/users/auth/logout \
  -H "Authorization: Bearer eyJ..."
```

UserService calls `TokenBlacklistService.revokeToken(jti, remainingTtlSeconds)`.
The token's `jti` is stored in Redis with TTL = remaining token lifetime.
Subsequent requests with that token receive `401 TOKEN_REVOKED`.

Redis key pattern: `jwt:blacklist:{jti}`

---

## Rate Limit Headers

Every response from a rate-limited path includes:

```
X-RateLimit-Limit:     100
X-RateLimit-Remaining: 42
X-RateLimit-Reset:     1715700123
Retry-After:           37          (only on 429 responses)
```

---

## Configuration Reference

All properties are in `src/main/resources/application.properties`.
Production overrides go in `application-prod.properties` (activate with `-Dspring.profiles.active=prod`).

```properties
# JWT validation
jwt.public-key-path=classpath:certs/public.pem
jwt.issuer=https://auth.prodemaster.com
jwt.audience=https://api.prodemaster.com
jwt.clock-skew-seconds=30
jwt.validation-timeout-ms=500
jwt.logging-verbose=true
jwt.algorithm-whitelist=RS256,RS384,RS512
jwt.public-paths=/api/public/**,/actuator/health,/actuator/health/**,\
  /users/auth/login,/users/auth/register,/users/auth/refresh

# Redis (token blacklist)
spring.data.redis.host=localhost
spring.data.redis.port=6379
spring.data.redis.timeout=2000ms

# Rate limiting
security.rate-limit.requests-per-minute=100
security.rate-limit.burst=150

# Distributed tracing
management.zipkin.tracing.endpoint=http://localhost:9411/api/v2/spans
tracing.sample.rate.admin=1.0
tracing.sample.rate.user=0.1
tracing.sample.rate.public=0.05
```

---

## Troubleshooting

**"401 EXPIRED_TOKEN" even with a fresh token**
- Verify the system clock on the machine running UserService is synced (NTP).
- Increase `jwt.clock-skew-seconds` in application.properties.

**"401 CLAIM_VALIDATION_FAILED" with a valid token**
- Check `jwt.issuer` matches the `iss` claim in the token exactly (case-sensitive).
- Check `jwt.audience` matches the `aud` claim.
- Decode the token at jwt.io to inspect actual claim values.

**"401 INVALID_SIGNATURE" after rotating keys**
- Replace `src/main/resources/certs/public.pem` with the new public key.
- Restart the gateway (public key is loaded once on startup via `@PostConstruct`).

**`X-User-Id` header missing in downstream service**
- Confirm the path is NOT in `jwt.public-paths` (public paths skip the filter).
- Check gateway logs for `JWT_VALIDATION status=SUCCESS`.

**Rate limit too strict / too loose**
- Adjust `security.rate-limit.requests-per-minute` in application.properties.
- In production, override in `application-prod.properties`.

**Metrics not appearing at `/actuator/prometheus`**
- Ensure `management.endpoints.web.exposure.include=prometheus` is set.
- Check that `micrometer-registry-prometheus` is on the classpath.
- Verify with: `curl http://localhost:8765/actuator/prometheus | grep jwt_validations`

**Redis connection refused on startup**
- Start Redis: `docker run -p 6379:6379 redis:7-alpine`
- Or point `spring.data.redis.host` to your Redis instance.

---

## Quick Validation (curl Examples)

```bash
# 1. Obtain a token from UserService
TOKEN=$(curl -s -X POST http://localhost:8765/users/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@test.com","password":"pwd123"}' | jq -r .token)

# 2. Call a protected endpoint
curl -i http://localhost:8765/users/profile \
  -H "Authorization: Bearer $TOKEN"
# Expected: 200 OK, X-RateLimit-* headers present

# 3. Missing token
curl -i http://localhost:8765/users/profile
# Expected: 401 {"error":"MISSING_TOKEN",...}

# 4. Expired token (modify exp claim manually or wait)
curl -i http://localhost:8765/users/profile \
  -H "Authorization: Bearer eyJ...OLD..."
# Expected: 401 {"error":"EXPIRED_TOKEN",...}

# 5. Check Prometheus metrics
curl -s http://localhost:8765/actuator/prometheus \
  -H "Authorization: Bearer $TOKEN" | grep jwt_validations
# Expected:
#   jwt_validations_total{result="success",...} 3.0
#   jwt_validations_duration_seconds_count ...

# 6. Trigger rate limit (run 101 requests quickly)
for i in $(seq 1 101); do
  curl -s -o /dev/null -w "%{http_code}\n" http://localhost:8765/users/profile \
    -H "Authorization: Bearer $TOKEN"
done
# Expected: first 100 → 200, request 101 → 429
```
