FROM eclipse-temurin:11-jdk as build
COPY . /app
WORKDIR /app
RUN ./gradlew build

FROM postgres:13
COPY rootfs/ /
COPY --from=build /app/build/libs/heap-dump-1.0-SNAPSHOT.jar /opt/app/
RUN (sh -e /setup.sh && rm /setup.sh)
CMD ["supervisord", "-n", "-c", "/etc/supervisor/supervisord.conf"]
