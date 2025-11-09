FROM maven:3-jdk-11 as build
COPY . /app
WORKDIR /app
RUN mvn clean package

# FROM openjdk:11-buster
# COPY flag.txt /flag.txt
# COPY --from=build /app/target/accessing-data-rest-0.0.1-SNAPSHOT.jar /opt/app/
# CMD ["java", "-jar", "/opt/app/accessing-data-rest-0.0.1-SNAPSHOT.jar"]

FROM openjdk:11-buster

# Create a non-root user
RUN useradd -m -u 1000 appuser

# Copy flag as root and set permissions so appuser can read but not write/delete
COPY flag.txt /flag.txt
RUN chown root:root /flag.txt && chmod 444 /flag.txt

# Copy application
COPY --from=build /app/target/accessing-data-rest-0.0.1-SNAPSHOT.jar /opt/app/
RUN chown root:root /opt/app/accessing-data-rest-0.0.1-SNAPSHOT.jar && chmod 555 /opt/app/accessing-data-rest-0.0.1-SNAPSHOT.jar

# Create a minimal writable temp directory for the app
RUN mkdir -p /tmp/app && chown appuser:appuser /tmp/app && chmod 700 /tmp/app

# Make filesystem mostly read-only
RUN chmod -R a-w /etc /usr /lib /lib64 /bin /sbin /opt 2>/dev/null || true

# Switch to non-root user
USER appuser
WORKDIR /tmp/app

ENV SERVER_PORT=4001

CMD ["java", "-Djava.io.tmpdir=/tmp/app", "-jar", "/opt/app/accessing-data-rest-0.0.1-SNAPSHOT.jar"]
