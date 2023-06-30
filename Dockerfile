FROM debian:latest

# install packages
RUN apt update
RUN apt install -y python3

# copy script inside container
COPY docker-run.sh /root/

# run when container starts
CMD ["bash", "/root/docker-run.sh"]