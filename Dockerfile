FROM eclipse-temurin:17-jre

WORKDIR /

COPY [ "./target/docker/dgcg.jar", "/dgcg.jar" ]

ENV JAVA_OPTS="$JAVA_OPTS -Xms256M -Xmx1G"

EXPOSE 8090

RUN mkdir /logs
RUN chown 65534:65534 /logs

USER 65534:65534

ENTRYPOINT [ "sh", "-c", "java $JAVA_OPTS -Dspring.profiles.active=dev -Djava.security.egd=file:/dev/./urandom -jar /dgcg.jar" ]
