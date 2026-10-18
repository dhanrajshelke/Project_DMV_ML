FROM maven:3.9-eclipse-temurin-8 AS build

WORKDIR /app

COPY server/pom.xml ./pom.xml
COPY server/src ./src

RUN mvn clean package -DskipTests

FROM eclipse-temurin:8-jre

WORKDIR /app

COPY --from=build /app/target/*.jar app.jar

EXPOSE 8085

ENTRYPOINT ["java", "-jar", "app.jar"]
