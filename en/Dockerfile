# syntax=docker/dockerfile:1.7

# 1. Build stage: test and package with Maven and the JDK.
FROM maven:3.9-eclipse-temurin-21 AS build

WORKDIR /workspace

# Copy pom.xml first so dependency layers are reused when only source files change.
COPY pom.xml ./

RUN --mount=type=cache,target=/root/.m2 \
    mvn -B -ntp dependency:go-offline

COPY src ./src

RUN --mount=type=cache,target=/root/.m2 \
    mvn -B -ntp clean verify

# 2. Runtime stage: include only the JRE and application JAR.
FROM eclipse-temurin:21-jre-jammy AS runtime

RUN apt-get update \
    && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

# Run the application as a dedicated non-root user.
RUN groupadd --system --gid 10001 appgroup \
    && useradd --system --uid 10001 --gid appgroup \
       --create-home --shell /usr/sbin/nologin appuser

WORKDIR /app

COPY --from=build --chown=appuser:appgroup \
    /workspace/target/application.jar \
    /app/application.jar

USER appuser:appgroup

ENV SERVER_PORT=8000
ENV JAVA_TOOL_OPTIONS="-XX:MaxRAMPercentage=75.0 -XX:+ExitOnOutOfMemoryError"

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD curl --fail --silent http://127.0.0.1:${SERVER_PORT}/ping || exit 1

ENTRYPOINT ["java", "-jar", "/app/application.jar"]
