#stage 1
#Start with a base image containing Java runtime
FROM openjdk:17 as build

# Add Maintainer Info
LABEL maintainer="dlcndgjs12 <yy8775799@gmail.com>"

# The application's jar file
ARG JAR_FILE=build/libs/springboot3-oauth2-authorization-server-0.0.1-SNAPSHOT.jar

# Add the application's jar to the container
COPY ${JAR_FILE} app.jar

#unpackage jar file
RUN mkdir -p build/libs/dependency && (cd target/dependency; jar -xf /app.jar)

#stage 2
#Same Java runtime
FROM openjdk:17

#Add volume pointing to /tmp
VOLUME /tmp

#Copy unpackaged application to new container
ARG build
COPY --from=build ${build}/BOOT-INF/lib /app/lib
COPY --from=build ${build}/META-INF /app/META-INF
COPY --from=build ${build}/BOOT-INF/classes /app

#execute the application
ENTRYPOINT ["java","-cp","app:app/lib/*","com.optimagrowth.license.LicenseServiceApplication"]