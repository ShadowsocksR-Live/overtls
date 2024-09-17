FROM rust AS build
LABEL overtls by source

WORKDIR /app

# apt
RUN apt-get update && \
    apt-get install -y openssl curl && \
    apt-get install -y git


RUN git clone https://github.com/shadowsocksr-live/overtls.git && \
    cd overtls && \
    cargo build --release




ENV CONFIG=/app/config.json


CMD bash /app/overtls-bin -r server -c ${CONFIG}



