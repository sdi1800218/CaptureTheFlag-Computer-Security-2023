# Use a pentest OS as base
FROM parrotsec/security:latest

# install packages
RUN apt update
RUN apt install -y python3 python3-pip

# copy scripts inside container
COPY docker-run.sh /root/
COPY ./pown/exploit.py /root/

# Required for pwn
COPY ./pown/libc.so.6 /

# install pwntools and pray for rain
RUN apt install -y python3-pwntools netcat-openbsd curl

# run when container starts
CMD ["bash", "/root/docker-run.sh"]
