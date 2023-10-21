FROM openjdk:8
EXPOSE 8080
ADD target/auth-api.jar auth-api.jar
ENTRYPOINT ["java","-jar","/auth-api.jar"]