FROM maven:3.6.1-jdk-8 as builder
WORKDIR /app
COPY . .
RUN mvn clean install -DskipTests=true
ARG JAR_FILE=target/*.jar
COPY ${JAR_FILE} application.jar
RUN mkdir -p target/dependency && (cd target/dependency; jar -xf ../*.jar)

FROM gcr.io/distroless/java:8
ARG DEPENDENCY=/app/target/dependency
COPY --from=builder ${DEPENDENCY}/BOOT-INF/lib /app/lib
COPY --from=builder ${DEPENDENCY}/META-INF /app/META-INF
COPY --from=builder ${DEPENDENCY}/BOOT-INF/classes /app
ENV _JAVA_OPTIONS "-Djava.security.egd=file:/dev/./urandom -Dfile.encoding=UTF-8"
ENTRYPOINT ["java","-cp","app:app/lib/*","dev.cuny.app.BbsApplication"]
