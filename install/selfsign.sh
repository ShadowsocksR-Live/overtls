#!/bin/bash

# 自簽名證書的生成和用法
# 1. 下載本腳本
#    wget https://raw.githubusercontent.com/shadowsocksr-live/overtls/master/install/selfsign.sh
# 2. 添加可執行權限
#    chmod +x selfsign.sh
# 3. 執行腳本, 這裡的 9 個參數依次是: 國家, 省份, 城市, 組織, CA的通用名, 服務器的通用名, 你電郵地址, 胡謅的網址, 你VPS的IP
#    ./selfsign.sh CN JiangSu ChangZhou MyGreatOrg Root_CA Server1 email@example.com example.com 123.45.67.89
# 4. 現在你將得到以下文件:
#    ca.crt  ca.key  server.crt  server.csr  server.key  serverca.txt
# 5. 將 server.crt 和 server.key 用於 overtls 服務器, 並在配置文件中使用它們。
#    server.crt: 服務器證書
#    server.key: 服務器私鑰
# 6. 將 ca.crt 文件用於客戶端, 用它的全路徑 填寫配置文件中的 cafile 參數的值。
#    ca.crt: 根證書
# 7. 注意：
#    - 這時候 overtls 不用 nginx 幫忙了，客戶端直接連接 overtls 服務端的監聽端口。
#      當然你最好還是裝一個 nginx 監聽在 80 端口，當 GFW 的探測流量到達時，overtls 能作出體面的回應。
#    - 由於自簽名證書不被公認，所以 GFW 可能會在一段時間後封了你的服務器，請謹慎使用。
#    - 客戶端的配置文件中的 cafile 參數的值，應該是 ca.crt 的全路徑， 例如 /etc/over-tls/ca.crt。
#    - 客戶端的配置文件中的 cafile 參數的值，也可以是證書的內容，當然它非常的長，因此不推薦這麼用，
#      它形如這樣 “-----BEGIN CERTIFICATE-----\nMIIFfTCC...\n-----END CERTIFICATE-----”。
#    - 這種自簽名證書翻牆的方式，只是讓你在沒有 `域名` 時的臨時解決方案，不要長期使用，否則說不定哪天就被 GFW 封了。
#

# 關鍵信息
COUNTRY=$1
STATE=$2
LOCALITY=$3
ORGANIZATION=$4
ORGANIZATIONAL_UNIT=$4
COMMON_NAME_CA=$5
COMMON_NAME_SERVER=$6
EMAIL_ADDRESS=$7
DNS_1=$8
IP_1=${9}

# 有效期 10 年, self-signed certificate will expire in 10 years
DAYS=3650

# 生成根證書的私鑰
openssl genrsa -out ca.key 4096

# 生成根證書
openssl req -outform PEM -new -x509 -sha256 -key ca.key -extensions v3_ca -out ca.crt -subj "/C=$COUNTRY/ST=$STATE/L=$LOCALITY/O=$ORGANIZATION/OU=$ORGANIZATIONAL_UNIT/CN=$COMMON_NAME_CA/emailAddress=$EMAIL_ADDRESS" -days ${DAYS}

# 生成自簽名證書的私鑰
openssl genrsa -out server.key 4096

# 生成自簽名證書的 CSR
openssl req -new -sha256 -key server.key -out server.csr -subj "/C=$COUNTRY/ST=$STATE/L=$LOCALITY/O=$ORGANIZATION/OU=$ORGANIZATIONAL_UNIT/CN=$COMMON_NAME_SERVER/emailAddress=$EMAIL_ADDRESS"

# 生成 serverca.txt 文件
cat << EOF > serverca.txt
subjectAltName = @${ORGANIZATION}
extendedKeyUsage = serverAuth

[${ORGANIZATION}]
DNS.1 = $DNS_1
IP.1 = $IP_1
EOF

# 生成自簽名證書
openssl x509 -req -CA ca.crt -CAkey ca.key -in server.csr -out server.crt -extfile serverca.txt -sha256 -set_serial 0x1111 -days ${DAYS}

# 查看文件
ls
