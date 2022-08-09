# To build:
# DOCKER_BUILDKIT=1 docker build . --target release --output type=local,dest=../challenge

FROM --platform=linux/amd64 ubuntu:20.04 AS build

RUN apt-get -y update && apt-get -y install build-essential
RUN apt-get -y install libgmp-dev

WORKDIR /root
COPY Makefile ./
COPY main.c ./
COPY babel.c ./
COPY babel.h ./

RUN make

FROM scratch AS release

COPY --from=build /root/library_of_babel /
