# Endpoints y Rutas — ApiGateway

## Tabla de Rutas Configuradas

| # | Ruta | Destino (Eureka) | Público | Descripción |
|---|------|------------------|---------|-------------|
| 0 | `/users/**` | `lb://user-service` | Parcial | Login, register, refresh → público; profile,管理等 → protegido |
| 1 | `/matches/api/v1/**` | `lb://match-service` | No | Consulta de partidos |
| 2 | `/predictions/api/v1/**` | `lb://PREDICTION-SERVICE` | No | Gestión de predicciones |
| 3 | `/scoring/**` | `lb://SCORING-SERVICE` | No | Puntuaciones y resultados |

## Endpoints Públicos (sin JWT)

Configurados via `jwt.public-paths` en `application.properties`:

| Ruta | Método | Descripción |
|------|--------|-------------|
| `/api/public/**` | Cualquiera | Endpoints públicos genéricos |
| `/actuator/health` | GET | Health check (liveness/readiness) |
| `/actuator/health/**` | GET | Health check detallado |
| `/users/auth/login` | POST | Inicio de sesión (emite JWT) |
| `/users/auth/register` | POST | Registro de usuario |
| `/users/auth/refresh` | POST | Refrescar token |

```
POST /users/auth/login
Body: { "email": "...", "password": "..." }
Response 200: { "token": "eyJhbGc...", "userId": "...", "roles": [...] }
```

## Endpoints Protegidos (requieren JWT)

Requieren header: `Authorization: Bearer {token}`

| Ruta | Método | Servicio Downstream | Headers Inyectados |
|------|--------|---------------------|--------------------|
| `/users/profile` | GET | UserService | `X-User-Id`, `X-Roles`, `X-Auth-Source`, `X-Token-Issued-At` |
| `/users/{id}` | PUT | UserService | Ídem |
| `/matches/api/v1/**` | GET | MatchService | Ídem |
| `/predictions/api/v1/**` | GET,POST | PredictionService | Ídem |
| `/scoring/**` | GET | ScoringService | Ídem |
| `/actuator/prometheus` | GET | Interno | Ídem |
| `/actuator/metrics` | GET | Interno | Ídem |
| `/actuator/env` | GET | Interno | Ídem |
| `/actuator/loggers` | GET | Interno | Ídem |

```
GET /users/profile
Header: Authorization: Bearer eyJhbGc...
Response 200: { "id": "550e8400-...", "email": "user@example.com", "roles": ["USER"] }
```

## Flujo de Request Protegido

```
1. Cliente → POST /users/auth/login → obtiene JWT del UserService

2. Cliente → GET /users/profile
   Header: Authorization: Bearer eyJhbGc...

3. ApiGateway (puerto 8765):
   ├── SecurityHeadersFilter (order -50): prepara headers de seguridad en response
   ├── RateLimitingFilter (order -90): verifica bucket por userId o IP
   ├── JwtAuthenticationFilter (order -100):
   │   ├── ¿Ruta pública? No
   │   ├── ¿Token presente? Sí
   │   ├── ¿Token válido? Sí (firma RSA, claims, issuer, audience)
   │   ├── ¿Blacklisted? No
   │   └── Inyecta: X-User-Id, X-Roles, X-Auth-Source, X-Token-Issued-At
   ├── ApiGatewayFilter (order 0): log + traceId
   └── Routing → lb://user-service + headers enriquecidos

4. Downstream recibe request con X-User-Id y X-Roles (confía en gateway)

5. Cliente ← Response 200 OK con headers de seguridad OWASP
```

## Configuración de Rutas

```properties
# application.properties
spring.cloud.gateway.routes[0].id=user-service
spring.cloud.gateway.routes[0].uri=lb://user-service
spring.cloud.gateway.routes[0].predicates[0]=Path=/users/**
spring.cloud.gateway.routes[0].filters[0]=RewritePath=/users/(?<segment>.*), /$\{segment}

spring.cloud.gateway.routes[1].id=match-service
spring.cloud.gateway.routes[1].uri=lb://match-service
spring.cloud.gateway.routes[1].predicates[0]=Path=/matches/api/v1/**

spring.cloud.gateway.routes[2].id=prediction-service
spring.cloud.gateway.routes[2].uri=lb://PREDICTION-SERVICE
spring.cloud.gateway.routes[2].predicates[0]=Path=/predictions/api/v1/**

spring.cloud.gateway.routes[3].id=scoring-service
spring.cloud.gateway.routes[3].uri=lb://SCORING-SERVICE
spring.cloud.gateway.routes[3].predicates[0]=Path=/scoring/**
```

## Endpoint /test

Deshabilitado por defecto mediante `@ConditionalOnProperty`. Solo se activa en desarrollo con `app.endpoints.test.enabled=true`.

---

**Estado**: 4 rutas funcionales, todas protegidas por JWT (excepto whitelist explícita).  
**Referencia**: `src/main/resources/application.properties`
