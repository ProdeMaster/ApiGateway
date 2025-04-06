FROM openjdk:17-jdk-slim

WORKDIR /app

COPY target/ApiGateWay-0.0.1-SNAPSHOT.jar ApiGateWay-0.0.1-SNAPSHOT.jar

EXPOSE 8765

LABEL version="0.1"
LABEL description="Application corresponding to the api gateway service used in the ProdeMaster project"

LABEL org.opencontainer.java.version="17"
LABEL org.opencontainer.Spring.version="3.4.*"
LABEL org.opencontainer.mvn.version="3.9.9"


ENTRYPOINT ["java", "-jar", "ApiGateWay-0.0.1-SNAPSHOT.jar"]
