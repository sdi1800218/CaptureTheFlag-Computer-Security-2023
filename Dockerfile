FROM debian:latest

# install packages
RUN apt update
RUN apt install -y python3 python3-pip

# copy scripts inside container
COPY docker-run.sh /root/
COPY exploit.py /root/

# Required for pwn
COPY libc.so.6 /root/

# install pwntools and pray for rain
RUN pip3 install pwn 

# run when container starts
CMD ["bash", "/root/docker-run.sh"]