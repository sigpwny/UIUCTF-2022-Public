# To build to ../challenge
# DOCKER_BUILDKIT=1 docker build . --target release --output type=local,dest=../challenge

FROM ocaml/opam:debian-ocaml-4.02 AS cpc

RUN opam install ocamlfind
# we need bash for ocaml profile script
SHELL ["/bin/bash", "-c"]

# download cpc source
WORKDIR /home/opam/
# use forked version of cpc for ocaml 4.02
RUN git clone https://github.com/vbmithr/cpc /home/opam/cpc
WORKDIR /home/opam/cpc
RUN git checkout 0e3362319b76dd1b177eaa81bd55941ac1859d49

# build cpc
RUN source /home/opam/.profile \
    && ./configure \
    && make

WORKDIR /home/opam/
COPY chal.cpc ./

# build challenge binary
RUN ./cpc/bin/cpc -I ./cpc/include -L./cpc/runtime -lm -pthread -lcpc -DNDEBUG -O3 chal.cpc -o cpsc && strip cpsc

FROM scratch AS release

COPY --from=cpc /home/opam/cpsc /
COPY Dockerfile /
