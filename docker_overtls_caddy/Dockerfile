FROM alpine:3.17


ENV TUNNEL_PATH=/secret-tunnel-path/ \
    OVERTLS_LOG_LEVEL=debug \
    HTTPS_PORT=443 \
    OVERTLS_HOST=127.0.0.1 \
    OVERTLS_PORT=10000 \
    CADDY_VERSION=2.7.6 \
    BASE_PATH="/etc/s6-overlay/s6-rc.d" \
    DOMAIN_NAME="" \
    S6_OVERLAY_VERSION="3.2.0.2"

COPY --chmod=755 ./rootfs /

RUN apk update && apk add --no-cache unzip wget && \
    wget -O /tmp/s6-overlay-noarch.tar.xz https://github.com/just-containers/s6-overlay/releases/download/v${S6_OVERLAY_VERSION}/s6-overlay-noarch.tar.xz && \
    tar -C / -Jxf /tmp/s6-overlay-noarch.tar.xz && \
    rm -f /tmp/s6-overlay-noarch.tar.xz && \
    wget -O /tmp/s6-overlay-x86_64.tar.xz https://github.com/just-containers/s6-overlay/releases/download/v${S6_OVERLAY_VERSION}/s6-overlay-x86_64.tar.xz && \
    tar -C / -Jxf /tmp/s6-overlay-x86_64.tar.xz && \
    rm -f /tmp/s6-overlay-x86_64.tar.xz && \
    wget -O /tmp/caddy.tar.gz https://github.com/caddyserver/caddy/releases/download/v${CADDY_VERSION}/caddy_${CADDY_VERSION}_linux_amd64.tar.gz && \
    tar -xzvf /tmp/caddy.tar.gz -C ${BASE_PATH}/caddy && \
    wget -O /tmp/overtls.zip https://github.com/shadowsocksr-live/overtls/releases/latest/download/overtls-x86_64-unknown-linux-musl.zip && \
    unzip /tmp/overtls.zip -d ${BASE_PATH}/overtls -x "config.json" && \
    rm -rf /var/cache/apk/* /tmp/*

    
    
EXPOSE $HTTPS_PORT/tcp \
       $HTTPS_PORT/udp


VOLUME ["/web"]
HEALTHCHECK --interval=10s --timeout=5s CMD /healthcheck.sh

ENTRYPOINT ["/init"]