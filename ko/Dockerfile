# syntax=docker/dockerfile:1.7

# 1. Build stage: Maven과 JDK로 테스트 및 패키징한다.
FROM maven:3.9-eclipse-temurin-21 AS build

WORKDIR /workspace

# pom.xml을 먼저 복사하면 소스만 변경됐을 때 의존성 레이어를 재사용할 수 있다.
COPY pom.xml ./

RUN --mount=type=cache,target=/root/.m2 \
    mvn -B -ntp dependency:go-offline

COPY src ./src

RUN --mount=type=cache,target=/root/.m2 \
    mvn -B -ntp clean verify

# 2. Runtime stage: 실행에 필요한 JRE와 jar만 포함한다.
FROM eclipse-temurin:21-jre-jammy AS runtime

RUN apt-get update \
    && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

# 애플리케이션을 root가 아닌 전용 사용자로 실행한다.
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
