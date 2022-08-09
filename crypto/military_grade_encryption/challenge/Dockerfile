FROM gcr.io/kctf-docker/challenge@sha256:d884e54146b71baf91603d5b73e563eaffc5a42d494b1e32341a5f76363060fb

RUN mkdir /usr/src/app
WORKDIR /usr/src/app

# pip
COPY ./requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

RUN pip install --no-cache-dir uwsgi

# chal files
RUN mkdir static templates
COPY app.py cipher.py flag.enc ./
COPY templates/ ./templates/

CMD umount /kctf/pow/ /kctf/pow-bypass && \
    kctf_drop_privs \
    /usr/local/bin/uwsgi --http 0.0.0.0:1337 --master -p 4 -w app:app
