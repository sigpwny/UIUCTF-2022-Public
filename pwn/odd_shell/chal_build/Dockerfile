# To build:
# DOCKER_BUILDKIT=1 docker build . --target release --output type=local,dest=../challenge

FROM --platform=linux/amd64 ubuntu:20.04 AS build

RUN apt-get -y update && apt-get -y install build-essential

WORKDIR /root
COPY Makefile ./
COPY chal.c ./

RUN make

FROM scratch AS release

COPY --from=build /root/chal /
