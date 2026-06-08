# Documentación de ApiGateway

## Descripción

Esta carpeta documenta el estado actual de **ApiGateway** (Spring Cloud Gateway con seguridad JWT RSA). El análisis se realizó contra el plan de implementación (`PLAN_IMPLEMENTATION_CHECKLIST.md`).

## Archivos

| Archivo | Lectura | Contenido |
|---------|---------|-----------|
| **01-RESUMEN_EJECUTIVO.md** | ~5 min | Visión general, métricas técnicas, estado vs plan, deudas |
| **03-ENDPOINTS_RUTAS.md** | ~10 min | Rutas configuradas, públicos vs protegidos, flujo de request |
| **09-SEGURIDAD_JWT.md** | ~15 min | Validación JWT, claims, headers, errores, checklist completo |
| **docs/AUTHENTICATION_FLOW.md** | ~15 min | Documentación detallada del flujo de autenticación |

## Lectura Recomendada

1. **01-RESUMEN_EJECUTIVO.md** → Estado general del proyecto
2. **03-ENDPOINTS_RUTAS.md** → Cómo enrutar requests
3. **09-SEGURIDAD_JWT.md** → Cómo funciona la seguridad

## Estado General

| Prioridad | Items | Completados | % |
|-----------|-------|-------------|---|
| 🔴 CRÍTICO | 5 | 5 | **100%** |
| 🟠 ALTO | 10 | 10 | **100%** |
| 🟡 MEDIO | 7 | 7 | **100%** |
| 🟢 BAJO | 5 | 5 | **100%** |
| **Total** | **27** | **27** | **100%** |

## Stack Tecnológico

- **Java 17** + **Spring Boot 3.4.3** + **Spring Cloud 2024.0.0**
- **Spring Cloud Gateway** (WebFlux reactivo)
- **JJWT 0.12.6** (JWT parsing + RSA verification)
- **Spring Security** (SecurityWebFilterChain reactivo)
- **Eureka Client** (service discovery)
- **Micrometer Tracing + Zipkin + Brave** (trazabilidad distribuida)
- **Bucket4j 7.6.0** (rate limiting)
- **Redis + Lettuce** (token blacklist)
- **Prometheus** (métricas)
- **JaCoCo** (cobertura de tests)

## Contacto

Equipo de infraestructura — ProdeMaster.

---

**Última actualización**: 2026-05-28  
**Generado por**: DeepSeek V4 Flash Free
