# Copyright 2020-2022 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

FROM ubuntu:20.04 as exploit-build

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y build-essential xxd

COPY solution.S /tmp

RUN gcc -static -nostartfiles /tmp/solution.S -o /tmp/solution.o
RUN objcopy -j .text -O binary /tmp/solution.o /tmp/solution
RUN xxd -p /tmp/solution > /tmp/solution.txt

FROM gcr.io/kctf-docker/healthcheck@sha256:abe5bc78f1eed01a050bc9efccde279aef560888598c0a04547b383a1429c6d4

COPY healthcheck_loop.sh healthcheck.py healthz_webserver.py /home/user/
COPY --from=exploit-build /tmp/solution.txt /home/user/solution.txt

CMD kctf_drop_privs /home/user/healthcheck_loop.sh & /home/user/healthz_webserver.py
