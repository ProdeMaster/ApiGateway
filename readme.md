# 🌐 ApiGateway Service

Este proyecto implementa un **API Gateway** utilizando **Spring Cloud Gateway**, como parte de un sistema de microservicios basado en descubrimiento de servicios con Eureka. Este componente actúa como un **único punto de entrada** para enrutar las solicitudes entrantes a los distintos servicios del backend.

---

## 🚀 ¿Qué hace este servicio?

El **ApiGateway** enruta dinámicamente las solicitudes entrantes a los microservicios registrados en el servidor Eureka. También puede aplicar filtros, autenticar usuarios y centralizar el manejo de errores, todo en un solo lugar.

---

## 🛠️ Tecnologías

- Java 17
- Spring Boot 3.4.x
- Spring Cloud Gateway
- Spring Cloud Netflix Eureka Client
- Docker & Docker Compose

---

## 📁 Estructura del proyecto

```plaintext
ApiGateway/
├── src/
│   ├── main/
│   │   ├── java/
│   │   │   └── com/ProdeMaster/ApiGateway/
│   │   │       ├─ Config
│   │   │       │  └─ TracingConfig.java
│   │   │       ├─ Controller
│   │   │       │  └─ TestController.java
│   │   │       │     
│   │   │       ├─ ApiGatewayApplication.java
│   │   │       └─ ApiGatewayFilter.java
│   │   └── resources/
│   │       └── application.properties
│   └── test/java/com/ProdeMaster/ApiGateWay/
│       └── ApiGateWayApplicationTests.java
├── Dockerfile
├── pom.xml
└── readme.md
```

## ⚙️ Configuración

El archivo `application.properties` contiene la configuración principal del ApiGateway y la conexión con el servidor Eureka. Esta es una configuración básica que garantiza un despliegue sencillo. Estas son las características principales, en el archivo  `application.properties` encontraran la configuración completa

### application.properties
```plaintext
spring.application.name=ApiGateWay
server.port=8765

#Configuracion de Eureka
eureka.client.service-url.defaultZone=http://eureka:8761/eureka/
eureka.client.fetch-registry=true
eureka.client.register-with-eureka=true

#Configuracion de Spring Cloud Gateway
spring.cloud.gateway.discovery.locator.enabled=true
spring.cloud.gateway.discovery.locator.lower-case-service-id=true

#Conectividad con zipkin para manejo de trazabilidad
spring.zipkin.base-url=http://zipkin:9411
management.zipkin.tracing.endpoint=http://zipkin:9411/api/v2/spans
management.tracing.sampling.probability=1.0
```

## 🧪 Cómo probarlo en local
### ✅ Requisitos
- JDK 17
- Maven
- Docker

#### Opción 1: sin Docker
```bash
mvn clean install
mvn spring-boot:run
```

#### Opción 2: con Docker
```bash
mvn clean package
docker image build -t api-gateway .
docker run api-gateway
```

## 📦 Docker

### Dockerfile

El servicio cuenta con un Dockerfile optimizado para producción basado en una imagen Java 17.

#### Build manual de la imagen
```bash
mvn clean package
docker image build -t eureka-service .
docker build -t eurekaservice .
```
> Es necesario empaquetar la aplicación con `mvn clean package` antes de crear la imagen de docker

## 🧩 Integración con otros servicios

El ApiGateway enruta automáticamente hacia los microservicios registrados en Eureka. Por ejemplo, una petición a:

```bash
http://localhost:8080/user-service/api/users
```
Se redirigirá al servicio llamado user-service, siempre que esté registrado en Eureka y configurado correctamente.

## 📚 Documentación adicional
* [Spring Boot](https://docs.spring.io/spring-boot/index.html)
* [Spring cloud](https://docs.spring.io/spring-cloud/docs/current/reference/html/)
* [Spring Cloud Gateway](https://docs.spring.io/spring-cloud-gateway/docs/current/reference/html/)
* [Ciclo de vida de las aplicaciones con Maven](https://keepcoding.io/blog/que-es-maven-lifecycle-y-sus-fases/)

## 🧑‍💻 Autor
> Nombre: Gastón Herrlein
>
> GitHub: @Gaston-Herrlein

## 📄 Licencia
Sin licencia