# overtls_caddy
docker run -itd  --restart always --name overtls -p 443:443 -e DOMAIN_NAME=域名 -e TUNNEL_PATH=/admin/,/log/  -v /web:/web chengxudong2020/overtls_caddy:latest

# 參數說​​明
-v /web 可選建議設定web靜態檔案所在目錄其中必須為包含index.php index.html index.htm index.nginx-debian.html 任何一個為預設首頁請自己從網上下載之後放入目錄重啟容器或者新建容器提前放好，映射之後的容器的目錄必須是/web
-e TUNNEL_PATH 可選 預設為 /secret-tunnel-path/ 請務必自行修改成複雜字串, 否則造成迅速被 GFW 封鎖之後果自負
-e DOMAIN_NAME 必須配置否則無法啟動 域名，需要配置解析