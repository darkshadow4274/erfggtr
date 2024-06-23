FROM ubuntu:latest

RUN apt-get update
RUN apt-get install socat -y

EXPOSE 2568

RUN useradd ctf

WORKDIR /chal
COPY flag.txt /chal
COPY bakait /chal

USER ctf

CMD ["socat", "tcp-l:2568,reuseaddr,fork", "EXEC:./bakait"]
