# Seguridad JWT — ApiGateway

## Arquitectura de Seguridad

El gateway implementa un modelo de seguridad de **dos capas**:

```
Capa 1: Spring Security (SecurityConfig.java)
  └── Permisivo: .anyExchange().permitAll()
  └── CSRF, HTTP Basic, form login, sessions deshabilitados
  └── Solo define rutas públicas a nivel framework

Capa 2: JwtAuthenticationFilter (GlobalFilter order -100)
  └── Ejecuta ANTES del routing
  └── Validación completa de JWT
  └── Blacklist check contra Redis
  └── Propagación de claims como headers internos
  └── Métricas Micrometer
```

## Flujo de Validación JWT

```
Request entrante
  ↓
JwtAuthenticationFilter.filter()
  ↓
¿Ruta en jwt.public-paths?
  ├─ Sí → chain.filter() (sin validación)
  └─ No → continúa
       ↓
¿Header Authorization: Bearer <token>?
  ├─ No → 401 MISSING_TOKEN + log WARN
  └─ Sí → extrae token
       ↓
JwtTokenProvider.validateAndExtract(token)
  ├─ 1. ¿PublicKey cargada? No → JwtException
  ├─ 2. validateAlgorithmHeader(): ¿alg en whitelist? No → UnsupportedJwtException
  ├─ 3. JJWT parser: verifyWith(publicKey).requireIssuer().requireAudience()
  │    ├── Firma inválida → SignatureException
  │    ├── Expired → ExpiredJwtException
  │    └── Malformed → MalformedJwtException
  ├─ 4. validateMandatoryClaims(): sub, roles, iat presentes y válidos
  ├─ 5. validateClaimsFormat(): sub UUID o email, email opcional con formato
  └── Ok → Claims
       ↓
TokenBlacklistService.isTokenBlacklisted(jti o fingerprint)
  ├─ Blacklisted → 401 TOKEN_REVOKED + log WARN
  └─ No blacklisted → continúa
       ↓
Injectar headers + MDC + métricas
  ├── request.mutate().header("X-User-Id", userId)
  ├── request.mutate().header("X-Roles", "ADMIN,USER")
  ├── request.mutate().header("X-Auth-Source", "jwt")
  ├── request.mutate().header("X-Token-Issued-At", epochMs)
  ├── request.mutate().removeHeader("Authorization")
  ├── MDC.put("user_role", roles)
  └── Counter "jwt.validations.total" + Timer "jwt.validations.duration_seconds"
       ↓
chain.filter(exchange mutado) → downstream
```

## Componentes de Seguridad

| Clase | Ubicación | Rol |
|-------|-----------|-----|
| `JwtTokenProvider` | `security/JwtTokenProvider.java` | Parseo, validación de firma RSA, claims, formato |
| `JwtAuthenticationFilter` | `filters/JwtAuthenticationFilter.java` | GlobalFilter que orquesta validación + blacklist + headers + métricas |
| `SecurityConfig` | `Config/SecurityConfig.java` | SecurityWebFilterChain reactivo (CSRF off, stateless, permitAll) |
| `JwtProperties` | `Config/JwtProperties.java` | Configuración externalizada (@ConfigurationProperties prefix=jwt) |
| `TokenBlacklistService` | `security/TokenBlacklistService.java` | Revocación de tokens vía Redis (TTL = tiempo de vida restante) |
| `RateLimitingFilter` | `security/RateLimitingFilter.java` | Token-bucket algorithm (Bucket4j), key por userId o IP |
| `SecurityHeadersFilter` | `security/SecurityHeadersFilter.java` | Headers OWASP en todas las respuestas |
| `GlobalExceptionHandler` | `exception/GlobalExceptionHandler.java` | WebExceptionHandler para errores no capturados |
| `ErrorResponse` / `ErrorCode` | `dto/` | DTOs para respuestas de error estandarizadas |
| `DynamicTracingSampler` | `Config/DynamicTracingSampler.java` | Sampling de trazas según rol (admin=100%, user=10%, anónimo=5%) |

## Claims Validados

### Obligatorios (item 2.2 del plan)

| Claim | Validación | Rechazo si... |
|-------|-----------|---------------|
| `sub` | No null, no blank, formato UUID o email | `JwtException("Subject (sub) claim is missing or empty")` |
| `roles` | No null, lista no vacía | `JwtException("Roles claim is missing/empty")` |
| `iat` | No null, no más de 60s en el futuro | `JwtException("IssuedAt (iat) claim is missing / Token issued in the future")` |
| `exp` | Validado por JJWT con clockSkewSeconds | `ExpiredJwtException` |

### Adicionales (item 2.3 del plan)

| Claim | Validación | Rechazo si... |
|-------|-----------|---------------|
| `iss` | `requireIssuer(jwtProperties.getIssuer())` | `JwtException` |
| `aud` | `requireAudience(jwtProperties.getAudience())` | `JwtException` |
| `alg` | Whitelist: RS256, RS384, RS512 | `UnsupportedJwtException("Algorithm 'HS256' rejected")` |

### Formato (item 4.5 del plan)

| Claim | Formato esperado |
|-------|-----------------|
| `sub` | UUID RFC 4122 o email (`local@domain`) |
| `email` (opcional) | Email básico (`local@domain`) |

## Headers Propagados a Downstream

| Header | Origen | Ejemplo |
|--------|--------|---------|
| `X-User-Id` | `claims.sub` | `550e8400-e29b-41d4-a716-446655440000` |
| `X-Roles` | `claims.roles` (join por coma) | `ADMIN,USER` |
| `X-Auth-Source` | Fijo | `jwt` |
| `X-Token-Issued-At` | `claims.iat` (epoch ms) | `1716850000000` |
| `Authorization` | **Eliminado** (no se reenvía al downstream) | — |

## Respuestas de Error Estandarizadas

### Formato JSON

```json
{
  "error": "MISSING_TOKEN",
  "message": "Token not present in Authorization header",
  "traceId": "3fa2c1d0-...",
  "timestamp": "2026-05-28T14:00:00Z",
  "path": "/users/profile"
}
```

### Códigos de Error

| Código | HTTP | Causa |
|--------|------|-------|
| `MISSING_TOKEN` | 401 | Header `Authorization` ausente o sin prefijo `Bearer` |
| `EXPIRED_TOKEN` | 401 | Token expirado (claim `exp` en el pasado) |
| `INVALID_SIGNATURE` | 401 | Firma RSA inválida |
| `ALGORITHM_MISMATCH` | 401 | Algoritmo no permitido (ej: HS256) |
| `INVALID_TOKEN` | 401 | Token malformado o corrupto |
| `CLAIM_VALIDATION_FAILED` | 401 | Claims obligatorios ausentes o formato inválido |
| `TOKEN_REVOKED` | 401 | Token en blacklist (revocado vía Redis) |
| `TOO_MANY_REQUESTS` | 429 | Rate limit excedido |
| `INSUFFICIENT_PERMISSIONS` | 403 | Acceso denegado (Spring Security) |
| `INTERNAL_ERROR` | 500 | Error interno no esperado |

## Headers de Seguridad OWASP (respuestas)

| Header | Valor | Propósito |
|--------|-------|-----------|
| `X-Content-Type-Options` | `nosniff` | Prevenir MIME-type sniffing |
| `X-Frame-Options` | `DENY` | Prevenir clickjacking |
| `X-XSS-Protection` | `1; mode=block` | Protección XSS legacy |
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains` | Forzar HTTPS |
| `Cache-Control` | `no-store, no-cache, must-revalidate, proxy-revalidate` | No cachear respuestas API |
| `Pragma` | `no-cache` | HTTP/1.0 cache compatibility |
| `Content-Security-Policy` | Configurable via `security.headers.csp` | Prevenir XSS y data injection |

## Rate Limiting

| Propiedad | Defecto | Descripción |
|-----------|---------|-------------|
| `security.rate-limit.requests-per-minute` | 100 | Requests máximos por minuto |
| `security.rate-limit.burst` | 150 | Ráfaga máxima permitida |

- Algoritmo: Token-bucket (Bucket4j)
- Key: `user:{userId}` si autenticado, `anon:{IP}` si anónimo
- Headers de respuesta: `X-RateLimit-Limit`, `X-RateLimit-Remaining`, `X-RateLimit-Reset`, `Retry-After`

## Token Blacklist (Redis)

- Almacena `jti` (JWT ID) o fingerprint SHA-256 como key en Redis
- TTL = tiempo de vida restante del token (expira automáticamente)
- Operaciones: `revokeToken(jti, ttlSeconds)`, `isTokenBlacklisted(jti)`

## Métricas Prometheus

| Métrica | Tipo | Tags |
|---------|------|------|
| `jwt_validations_total` | Counter | `result=success\|expired\|invalid\|missing\|blacklisted` |
| `jwt_validations_duration_seconds` | Timer (histogram) | Percentiles p95, p99 |

## Checklist de Verificación

- [x] Dependencias JJWT + Spring Security en `pom.xml`
- [x] `JwtTokenProvider` parsea y valida tokens RSA
- [x] `JwtAuthenticationFilter` propaga headers y chequea blacklist
- [x] `SecurityConfig` con rutas públicas definidas y CSRF deshabilitado
- [x] `public.pem` cargable desde `classpath:certs/public.pem`
- [x] Claims obligatorios validados (`sub`, `roles`, `iat`, `exp`)
- [x] Algorithm confusion prevenido (whitelist solo RSA)
- [x] Errores HTTP estandarizados (JSON con traceId)
- [x] Headers de seguridad OWASP en cada respuesta
- [x] Logging de eventos sin exponer tokens
- [x] Actuator endpoints sensibles protegidos (excepto `/health`)
- [x] `/test` deshabilitado por defecto
- [x] Tests unitarios (`JwtTokenProviderTest` — 389 líneas)
- [x] Tests de integración (`JwtGatewayIntegrationTest` — 519 líneas)
- [x] Javadoc en todas las clases de seguridad
- [x] Documentación de flujo (`docs/AUTHENTICATION_FLOW.md`)

---

**Estado**: 100% implementado según `PLAN_IMPLEMENTATION_CHECKLIST.md`  
**Referencias**: `JwtTokenProvider.java`, `JwtAuthenticationFilter.java`, `SecurityConfig.java`, `application.properties`
