# overtls
docker run --restart always -p 80:80 -p 443:443  --name overtls -e TUNNEL_PATH=/secret-tunnel-path/ -v /cert:/cert -v /web:/web -itd registry.cn-hangzhou.aliyuncs.com/dubux/overtls:latest

# 参数说明
- -v 证书所在目录 一定要映射到/cert容器目录 证书要目录中必须存在私钥privkey.pem 公钥fullchain.pem 名字不对请该名
- -v web静态文件所在目录 其中必须为包含index.php index.html index.htm index.nginx-debian.html 
  任何一个为默认首页 请自己从网上下载之后放入目录重启容器或者新建容器提前放好，映射之后的容器的目录必须是 /web
- -e TUNNEL_PATH 默认为 /secret-tunnel-path/ 请修改 否则出现任何后果自负
