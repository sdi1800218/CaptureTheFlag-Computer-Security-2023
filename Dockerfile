# Use a pentest OS as base
FROM debian:latest

# install packages
RUN apt update
# install pwntools and pray for rain
RUN apt install -y python3 python3-pip python3-pwntools netcat-openbsd curl

# copy scripts inside container
COPY docker-run.sh /root/
COPY ./pown/exploit.py /root/
COPY ./pown/padding_oracles.py /root/

# Required for pwn
COPY ./pown/libc.so.6 /
RUN cd /root/

# run when container starts
CMD ["bash", "/root/docker-run.sh"]
