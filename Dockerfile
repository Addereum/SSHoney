# ---------- Build stage ----------
FROM eclipse-temurin:21 AS build
WORKDIR /workspace

COPY pom.xml ./

# sourcecode
COPY src src

RUN bash -lc "mvn -q -DskipTests package"

# ---------- Runtime stage ----------
FROM eclipse-temurin:21-jre
WORKDIR /app

LABEL org.opencontainers.image.source="https://github.com/addereum/SSHoney"
LABEL org.opencontainers.image.description="Bag of Honey: Lightweight multi-protocol honeypot"
LABEL org.opencontainers.image.licenses="MIT"

RUN mkdir -p /data && chmod 700 /data

# Non-root-User anlegen
RUN useradd -r -s /bin/false honey
RUN chown honey:honey /data

USER honey

COPY --from=build /workspace/target/bagofhoney-1.0-SNAPSHOT-shaded.jar /app/app.jar

EXPOSE 2222/tcp 4000/udp 5000/tcp
ENV JAVA_OPTS=""

ENTRYPOINT ["sh","-c","exec java $JAVA_OPTS -jar /app/app.jar"]


