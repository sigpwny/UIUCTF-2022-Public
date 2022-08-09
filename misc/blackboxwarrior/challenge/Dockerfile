FROM gcr.io/kctf-docker/challenge@sha256:d884e54146b71baf91603d5b73e563eaffc5a42d494b1e32341a5f76363060fb

RUN mkdir /usr/src/app
WORKDIR /usr/src/app

# pip
COPY ./site/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

RUN mkdir -p /usr/src/app/static/images
RUN wget https://www.cs.toronto.edu/~kriz/cifar-10-python.tar.gz -O /usr/src/app/static/images/cifar-10-python.tar.gz
RUN tar -C /usr/src/app/static/images -xf /usr/src/app/static/images/cifar-10-python.tar.gz

RUN mkdir -p /home/user/.cache/torch/hub/checkpoints/
RUN wget https://download.pytorch.org/models/efficientnet_b0_rwightman-3dd342df.pth -O /home/user/.cache/torch/hub/checkpoints/efficientnet_b0_rwightman-3dd342df.pth

ENV FLAG=uiuctf{oh_n0_my_b4nksy}

COPY site .
COPY models /usr/src/models

CMD umount /kctf/pow/ /kctf/pow-bypass && \
    kctf_drop_privs \
    env FLAG="$FLAG" python3 app.py
