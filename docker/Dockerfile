FROM visense/debain11_slim:v1


ENV TUNNEL_PATH=/secret-tunnel-path/
ENV OVERTLS_LOG_LEVEL=debug


ARG HTTP_PORT=80
ARG HTTPS_PORT=443

ARG OVERTLS_HOST=127.0.0.1
ARG OVERTLS_PORT=10000


COPY run.sh utils.sh index.html security.conf 50x.html /

RUN echo 'export HTTP_PORT='"$HTTP_PORT" > /etc/envinit.sh && \
    echo 'export HTTPS_PORT='"$HTTPS_PORT" >> /etc/envinit.sh && \
    echo 'export HTTP_PORT='"$HTTP_PORT" >> /etc/envinit.sh && \
    echo 'export OVERTLS_HOST='"$OVERTLS_HOST" >> /etc/envinit.sh && \
    echo 'export OVERTLS_PORT='"$OVERTLS_PORT" >> /etc/envinit.sh && \
    sed -i 's/deb.debian.org/mirrors.aliyun.com/g' /etc/apt/sources.list && \
    \cp /utils.sh /etc/utils.sh && \
    apt-get update && apt-get install -y wget nginx vim && chmod +x /run.sh && mkdir -p /default/ && cd /default && \
    wget -O overtls.zip https://github.com/shadowsocksr-live/overtls/releases/latest/download/overtls-x86_64-unknown-linux-musl.zip && \
    unzip overtls.zip && rm -rf overtls.zip && \
    rm -rf /var/lib/apt/lists/* && \
    mkdir /web && \
    mkdir /cert && \
    cd /default && \
    rm -rf /etc/nginx/sites-enabled/* && \
    \cp /security.conf /etc/nginx/conf.d/ && \
    chown -R www-data:www-data /web && \
    chmod -R 777 /web
    
    



VOLUME ["/web"]
VOLUME ["/cert"]

USER root


EXPOSE $HTTP_PORT
EXPOSE $HTTPS_PORT

   
ENTRYPOINT ["/bin/bash", "run.sh"]
