FROM alpine:3.17


ENV TUNNEL_PATH=/secret-tunnel-path/
ENV OVERTLS_LOG_LEVEL=debug


ARG HTTP_PORT=80
ARG HTTPS_PORT=443

ARG OVERTLS_HOST=127.0.0.1
ARG OVERTLS_PORT=10000
ARG SSL_KEY=privkey.pem
ARG SSL_PUBLIC=fullchain.pem

COPY run.sh utils.sh index.html 50x.html /

RUN echo 'export HTTP_PORT='"$HTTP_PORT" > /etc/envinit.sh && \
    echo 'export HTTPS_PORT='"$HTTPS_PORT" >> /etc/envinit.sh && \
    echo 'export HTTP_PORT='"$HTTP_PORT" >> /etc/envinit.sh && \
    echo 'export OVERTLS_HOST='"$OVERTLS_HOST" >> /etc/envinit.sh && \
    echo 'export OVERTLS_PORT='"$OVERTLS_PORT" >> /etc/envinit.sh && \
    echo 'export SSL_KEY='"$SSL_KEY" >> /etc/envinit.sh && \
    echo 'export SSL_PUBLIC='"$SSL_PUBLIC" >> /etc/envinit.sh && \
    sed -i 's/dl-cdn.alpinelinux.org/mirrors.aliyun.com/g' /etc/apk/repositories && \ 
    echo "https://nginx.org/packages/mainline/alpine/v3.17/main" >> /etc/apk/repositories && \
    \cp /utils.sh /etc/utils.sh && \
    apk add --update --allow-untrusted --no-cache bash unzip wget fontconfig nginx nginx-mod-stream nginx-mod-http-headers-more nginx-mod-http-lua vim && \ 
    chmod +x /run.sh && mkdir -p /default/ && cd /default && \
    wget -O overtls.zip https://github.com/shadowsocksr-live/overtls/releases/latest/download/overtls-x86_64-unknown-linux-musl.zip && \
    unzip overtls.zip && rm -rf overtls.zip && \
    fc-cache -f -v && \
    rm -rf /var/cache/apk/* /tmp/* && \
    mkdir /web && \
    mkdir /cert && \
    rm -rf /etc/nginx/sites-enabled/* && \
    rm -rf /etc/nginx/http.d/* && \
    rm -rf /etc/nginx/conf.d/*

    
    



VOLUME ["/web"]
VOLUME ["/cert"]

USER root


EXPOSE $HTTP_PORT
EXPOSE $HTTPS_PORT/tcp
EXPOSE $HTTPS_PORT/udp
   
ENTRYPOINT ["/bin/bash", "run.sh"]
