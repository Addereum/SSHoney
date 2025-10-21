# Bauzeit-Image (Maven) optional, wenn du im Container bauen willst.
FROM eclipse-temurin:21 AS build
WORKDIR /workspace
COPY pom.xml mvnw ./
COPY .mvn .mvn
# nur wenn du das Projekt inside Docker bauen willst; sonst entferne diesen Schritt.
RUN ["bash", "-lc", "mvn -q -DskipTests package"]

# Laufzeit-Image
FROM eclipse-temurin:21-jre
WORKDIR /app

# Kopiere Ergebnis des Builds (erwartet: target/bagofhoney-1.0-SNAPSHOT.jar)
COPY target/bagofhoney-1.0-SNAPSHOT.jar /app/app.jar
# falls du kein fat-jar baust, kannst du statt dessen alle dependency-jars in ein libs-Dir kopieren
# COPY target/dependency /app/libs

EXPOSE 2222/tcp 4000/udp

ENV JAVA_OPTS=""

ENTRYPOINT ["sh","-c","exec java $JAVA_OPTS -jar /app/app.jar"]
