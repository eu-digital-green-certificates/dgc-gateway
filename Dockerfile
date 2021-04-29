FROM adoptopenjdk:11-jre-hotspot

WORKDIR /

COPY [ "./target/docker/dgcg.jar", "/dgcg.jar" ]

ENV JAVA_OPTS="$JAVA_OPTS -Xms256M -Xmx1G"

EXPOSE 8080

ENTRYPOINT [ "sh", "-c", "java $JAVA_OPTS -Djava.security.egd=file:/dev/./urandom -jar /dgcg.jar" ]
