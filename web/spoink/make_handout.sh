tar --owner="arx" --group="arx" \
    --transform 's|challenge|spoink|' \
    -czvf handout.tar.gz challenge/Dockerfile challenge/docker-compose.yml challenge/spoink/public challenge/spoink/templates challenge/spoink/target/spoink-0.0.1-SNAPSHOT-spring-boot.jar
