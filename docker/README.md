# overtls
```bash
docker run --restart always -p 80:80 -p 443:443/tcp -p 443:443/udp --name overtls -e TUNNEL_PATH=/secret-tunnel-path/ -v /cert:/cert -v /web:/web -itd chengxudong2020/overtls
```

# 参数说明
- `-p` 当端口映射到宿主机443 tcp和udp端口的情况下支持http3
- `-v 证书所在目录` 一定要映射到 /cert容器目录 证书目录中必须存在私钥 `privkey.pem` 公钥 `fullchain.pem` 若名字不对请改名
- `-v web静态文件所在目录` 其中必须为包含 `index.php`, `index.html`, `index.htm`, `index.nginx-debian.html`
  中任何一个为默认首页, 请自行从网上下载之后放入目录重启容器或者新建容器提前備好，映射之后的容器的目录必须是 `/web`
- `-e TUNNEL_PATH` 默认格式为 `/secret-tunnel-path/` 或者 `/secret-tunnel-path/,/secret-tunnel-path2/,/secret-tunnel-path2/`.
  请務必自行修改成复杂字符串, 否则造成迅速被 `GFW` 封鎖之后果自负
