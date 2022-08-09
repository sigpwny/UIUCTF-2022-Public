# To build to ../challenge
# DOCKER_BUILDKIT=1 docker build . --target release --output type=local,dest=../challenge

FROM --platform=linux/amd64 ubuntu:20.04 AS build

RUN apt-get -y update && apt-get -y install build-essential
RUN apt-get -y install libgmp-dev

WORKDIR /root
COPY vast_cornfields.c ./

RUN gcc -O0 -lgmp vast_cornfields.c -o vast_cornfields

FROM scratch AS release

COPY --from=build /root/vast_cornfields /
