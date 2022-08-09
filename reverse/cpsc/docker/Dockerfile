FROM ocaml/opam:debian-ocaml-4.02

RUN opam install ocamlfind
SHELL ["/bin/bash", "-c"]

# download cpc source
WORKDIR /home/opam/
RUN git clone https://github.com/vbmithr/cpc /home/opam/cpc
WORKDIR /home/opam/cpc
RUN git checkout 0e3362319b76dd1b177eaa81bd55941ac1859d49

# build cpc
WORKDIR /home/opam/cpc
RUN source /home/opam/.profile \
    && ./configure \
    && make

# export built files
WORKDIR /home/opam/cpc
RUN tar czf /home/opam/export.tar.gz bin include lib runtime
