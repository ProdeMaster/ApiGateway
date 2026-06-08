# ApiGateway — Resumen Ejecutivo

## Descripción General

ApiGateway es el punto de entrada único a la arquitectura de microservicios de ProdeMaster. Actúa como proxy reactivo (Spring Cloud Gateway) que enruta peticiones a los servicios downstream, valida tokens JWT con firma RSA, propaga la identidad del usuario mediante headers internos y aplica seguridad global.

## Información Técnica

| Propiedad | Valor |
|-----------|-------|
| **Spring Boot** | 3.4.3 |
| **Spring Cloud** | 2024.0.0 |
| **Patrón** | Spring Cloud Gateway reactivo (WebFlux) |
| **Puerto** | 8765 |
| **Autenticación** | JWT RSA (RS256/RS384/RS512) |
| **Librería JWT** | JJWT 0.12.6 |
| **Discovery** | Eureka Client |
| **Trazabilidad** | Micrometer Tracing + Zipkin + Brave |
| **Rate Limiting** | Bucket4j 7.6.0 |
| **Cache / Blacklist** | Redis (Spring Data Redis + Lettuce) |
| **Métricas** | Prometheus (Micrometer Registry) |

## Responsabilidades Actuales

1. ✅ Enrutar requests a microservicios (4 rutas: users, matches, predictions, scoring)
2. ✅ Descubrimiento dinámico de servicios mediante Eureka (LoadBalancer)
3. ✅ Validación de tokens JWT RSA (firma, claims, algoritmo, issuer, audience)
4. ✅ Propagación de identidad: headers `X-User-Id`, `X-Roles`, `X-Auth-Source`, `X-Token-Issued-At`
5. ✅ Blacklist de tokens revocados vía Redis
6. ✅ Rate limiting por usuario/IP con Bucket4j
7. ✅ Headers de seguridad OWASP en todas las respuestas
8. ✅ Métricas de autenticación expuestas en Prometheus
9. ✅ Sampling dinámico de trazas según rol del usuario

## Servicios Downstream

| Servicio | ID Eureka | Ruta Gateway | Protegido |
|----------|-----------|--------------|-----------|
| UserService | `user-service` | `/users/**` | Parcial (login/register público) |
| MatchService | `match-service` | `/matches/api/v1/**` | Sí |
| PredictionService | `PREDICTION-SERVICE` | `/predictions/api/v1/**` | Sí |
| ScoringService | `SCORING-SERVICE` | `/scoring/**` | Sí |

## Estado vs Plan de Implementación

| Prioridad | Items | Completados | % |
|-----------|-------|-------------|---|
| 🔴 CRÍTICO | 5 | 5 | **100%** |
| 🟠 ALTO | 10 | 10 | **100%** |
| 🟡 MEDIO | 7 | 7 | **100%** |
| 🟢 BAJO | 5 | 5 | **100%** |
| **Total** | **27** | **27** | **100%** |

## Deudas Técnicas

No se identifican deudas técnicas. Todos los items del plan (`PLAN_IMPLEMENTATION_CHECKLIST.md`) están implementados.

Observaciones menores:
- `ApiGatewayFilter.java` no fue modificado para logging de autenticación (el logging se implementó en `JwtAuthenticationFilter`, que es la ubicación correcta)
- `TestController.java` se deshabilitó por propiedad (`app.endpoints.test.enabled=false`) en lugar de eliminarse; esto permite desarrollo local sin exponerlo en producción
- La documentación de autenticación está en `docs/AUTHENTICATION_FLOW.md` en lugar de `README.md`

## Próximos Pasos Recomendados

1. Monitorear métricas de seguridad en Prometheus (`jwt_validations_total`, `jwt_validations_duration_seconds`)
2. Configurar alertas sobre tasas de rechazo de tokens
3. Ajustar sampling de trazas en producción (`application-prod.properties` ya configurado)
4. Verificar integración de blacklist con servicio de logout en UserService
5. Ejecutar suite completa de tests: `mvn clean verify`

---

**Generado**: 2026-05-28  
**Fuente**: Análisis de código vs `PLAN_IMPLEMENTATION_CHECKLIST.md`
