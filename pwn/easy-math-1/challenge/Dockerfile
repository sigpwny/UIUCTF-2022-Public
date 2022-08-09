FROM ubuntu:18.04 as chroot

# convenience tools, after all, we want them to work in the container
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get -y install vim nano gdb git python3-dev gcc build-essential && \
    rm -rf /var/lib/apt/lists/*

# ctf should have same password in case they somehow manage to su ctf
RUN adduser --disabled-password --gecos '' --uid 1000 ctf
RUN adduser --disabled-password --gecos '' --uid 1001 admin
RUN echo "ctf:ctf" | chpasswd

COPY README easy-math.c flag /home/ctf/

WORKDIR /home/ctf
RUN gcc easy-math.c -o easy-math
RUN chown -R ctf:ctf .
RUN chmod 644 *
RUN chown admin:admin flag easy-math
RUN chmod 400 flag
RUN chmod 4555 easy-math

FROM gcr.io/kctf-docker/challenge@sha256:d884e54146b71baf91603d5b73e563eaffc5a42d494b1e32341a5f76363060fb

# sudo so that we can become root after sshd forks, so that we can kctf_drop_privs...
# this is highly questionable but it should be okay, they never get any actual execution here
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y openssh-server sudo && rm -rf /var/lib/apt/lists/*

COPY --from=chroot / /chroot

# fake dev (we just need urandom, everything else is for fun)
RUN bash -c "cp -a /dev/{fd,full,null,ptmx,pts,random,shm,stderr,stdin,stdout,tty,urandom,zero} /chroot/dev/"

# second flag, mounted in by nsjail2.cfg
COPY flag2 /
RUN chmod 400 /flag2
RUN chown 1001:1001 /flag2

# second flag, mounted in by nsjail3.cfg
COPY flag3 /
RUN chmod 400 /flag3
RUN chown 1001:1001 /flag3

# ha, get it, ns jail shell, jail cell... lol
COPY nsjail-shell.sh nsjail-shell2.sh nsjail-shell3.sh /
RUN chmod +x /nsjail-shell.sh /nsjail-shell2.sh /nsjail-shell3.sh

# continue sudo setup
RUN adduser --disabled-password --gecos '' --shell /nsjail-shell.sh ctf
RUN adduser --disabled-password --gecos '' --shell /nsjail-shell2.sh ctf-part-2
RUN adduser --disabled-password --gecos '' --shell /nsjail-shell3.sh ctf-part-3
RUN echo "ctf ALL=(ALL) NOPASSWD: /nsjail-shell.sh" >> /etc/sudoers
RUN echo "ctf-part-2 ALL=(ALL) NOPASSWD: /nsjail-shell2.sh" >> /etc/sudoers
RUN echo "ctf-part-3 ALL=(ALL) NOPASSWD: /nsjail-shell3.sh" >> /etc/sudoers
RUN echo "ctf:ctf" | chpasswd
RUN echo "ctf-part-2:ctf" | chpasswd
RUN echo "ctf-part-3:6d49a6fb" | chpasswd

# use the same ssh host key so if we redeploy, people aren't like ssh host key changed
COPY ssh* /etc/ssh/
RUN chmod 600 /etc/ssh/ssh_*_key
RUN chmod 644 /etc/ssh/ssh_*_key.pub
RUN mkdir -p /run/sshd

# nsjail config
COPY nsjail.cfg nsjail2.cfg nsjail3.cfg /home/user/

# nsjail needs some more caps for count: 2
COPY exceptionally-hacky-kctf-drop-privs-replacement.sh /usr/bin/kctf_drop_privs

CMD kctf_setup && \
    mount -t tmpfs tmpfs /tmp && \
    /usr/sbin/sshd -D -e
