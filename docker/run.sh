#!/bin/bash
source /etc/envinit.sh
source /etc/utils.sh

checkssl(){
  local file="/cert/$SSL_PUBLIC"
  if [ ! -f "$file" ]; then
    echoerr "找不到证书公钥文件： $file, 请检查配置"
    exit 1
  fi
  file="/cert/$SSL_KEY"
  if [ ! -f "$file" ]; then
    echoerr "找不到证书私钥文件： $file, 请检查配置"
    exit 1
  fi
}

checkindex(){
  isindex=0
  local dir="/web"
    if [ ! -d "$dir" ]; then
      mkdir "$dir"
    fi
  cd $dir
   file_list=("index.php" "index.html" "index.htm" "index.nginx-debian.html")
   for file in "${file_list[@]}"; do
    if [ -f "$file" ]; then
      echolog "存在默认首页: $file"
      isindex=1
      break
    fi
  done
  local xfile="50x.html"
  is50x=0
   if [ -f "$xfile" ]; then
      echolog "存在默认50x错误页: $xfile"
      is50x=1
    fi
}

initIndex(){
    checkindex
    if [ $isindex -eq 0 ]; then
      echolog "不存在首页, 则使用默认首页"
      \cp /index.html /web/index.html
    fi
    if [ $is50x -eq 0 ]; then
      echolog "不存在50x错误页, 则使用默认50x错误页"
      \cp /50x.html /web/50x.html
    fi
}

initConfig(){
  rm -rf /etc/nginx/conf.d/overtls.conf
  cat > /etc/nginx/conf.d/overtls.conf <<EOF
  server {
        listen $HTTP_PORT default_server;
        listen [::]:$HTTP_PORT default_server;
        server_name localhost;
        index index.php index.html index.htm index.nginx-debian.html;
        root  /web;
  }
  server {
        listen $HTTPS_PORT ssl default_server;
        listen $HTTPS_PORT quic reuseport default_server;
        listen [::]:$HTTPS_PORT ssl default_server;
        listen [::]:$HTTPS_PORT quic reuseport default_server;
        http2 on;
        ssl_certificate       /cert/$SSL_PUBLIC;
        ssl_certificate_key   /cert/$SSL_KEY;
        ssl_protocols         TLSv1.3;
        add_header Alt-Svc 'h3=":$HTTPS_PORT"; ma=86400';
        server_name           localhost;
        index index.php index.html index.htm index.nginx-debian.html;
        root  /web;
        error_page 400 403 502 = /index.html;

        location ~ \\.php$ {
            
        }
        
        location = /index.html {
          root  /web;
        }
EOF
     TUNNEL_PATH_STRING="$TUNNEL_PATH"
     OLD_IFS="$IFS"
     IFS=','
     for path in $TUNNEL_PATH; do
          path="${path#"${path%%[![:space:]]*}"}"
          path="${path%"${path##*[![:space:]]}"}"
          cat >> /etc/nginx/conf.d/overtls.conf <<EOF
            location $path {
                proxy_redirect off;
                proxy_pass http://$OVERTLS_HOST:$OVERTLS_PORT;
                proxy_http_version 1.1;
                proxy_set_header Upgrade \$http_upgrade;
                proxy_set_header Connection "upgrade";
                proxy_set_header Host \$http_host;
            }
EOF
    done
    IFS="$OLD_IFS"

          cat >> /etc/nginx/conf.d/overtls.conf <<EOF
  }
EOF

    local identity=$(random_string_gen 4)
    rm -rf /default/config.json
    cat > /default/config.json <<EOF
{
    "remarks": "${identity}",
    "tunnel_path": $(get_tunnel_path),

    "server_settings": {
        "forward_addr": "http://127.0.0.1:$HTTP_PORT",
        "listen_host": "$OVERTLS_HOST",
        "listen_port": $OVERTLS_PORT
    }
}
EOF

}

echolog "开始启动-----------------------------"
echolog "使用的tunnel_path=$TUNNEL_PATH-------"
checkssl && initIndex && initConfig && nginx && \
cd /default && chmod +x ./overtls && ./overtls -v $OVERTLS_LOG_LEVEL -r server -c config.json
