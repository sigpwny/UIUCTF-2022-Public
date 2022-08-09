tar --owner="arx" --group="arx" \
    --exclude challenge/Dockerfile \
    --transform 's|Dockerfile.handout|Dockerfile|' \
    --transform 's|challenge|woeby|' \
    -czvf handout.tar.gz challenge

