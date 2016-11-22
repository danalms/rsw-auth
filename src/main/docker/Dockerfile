FROM openjdk:8
VOLUME /tmp
ADD auth-server-0.0.1.jar app.jar
RUN sh -c 'touch /app.jar'
ENV JAVA_OPTS="-Xms256m -Xmx1024m"
ENTRYPOINT [ "sh", "-c", "java $JAVA_OPTS -Dspring.profiles.active=cloud -Djava.security.egd=file:/dev/./urandom -jar /app.jar" ]
MAINTAINER Dan Alms "dan@rosssoftwareworks.com"