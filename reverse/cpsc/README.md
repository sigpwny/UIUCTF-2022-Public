# CPSC

Continuation passing style C is a challenge that uses
[CPC](https://github.com/kerneis/cpc) to create C programs with strange control
flow.

## Building CPC

To build the challenge files, first build CPC, a special source-to-source
compiler and its runtime libraries. Use the included Dockerfile to build these
assets.  Note that it only creates executables for Debian systems.

First, build the dockerfile with:
```sh
docker build -t cpc docker/
```

Then, build the compiler and runtime files and copy them out of the docker:
```sh
docker run --rm cpc cat /home/opam/export.tar.gz > export.tar.gz
mkdir export
tar xvf export.tar.gz -C export
```

## Building challenge files

Run `make` to build. Resulting binary will be in `src/chal`. The source is
in `src/chal.cpc`.

For more options, such as saving intermediate files, use the `./build` script.
See `./build -h` for help.

## Building challenge binaries

To build official challenge binaries, use the dockerfile in this directory. See
the instructions at the top of the file.

## Author

This challenge was made by Richard Liu.
