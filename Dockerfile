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

RUN mkdir -p /data && chmod 700 /data

# Non-root-User anlegen
RUN useradd -r -s /bin/false honey
RUN chown honey:honey /data

USER honey

COPY target/bagofhoney-1.0-SNAPSHOT.jar /app/app.jar

EXPOSE 2222/tcp 4000/udp 5000/tcp
ENV JAVA_OPTS=""

ENTRYPOINT ["sh","-c","exec java $JAVA_OPTS -jar /app/app.jar"]


