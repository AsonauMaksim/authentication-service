FROM openjdk:21-jdk

COPY target/authentication-service-*.jar app.jar

EXPOSE 8082

ENTRYPOINT ["java", "-jar", "app.jar"]