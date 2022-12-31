# viatls

一千行代碼實現的 TLS 代理，大家看看配置文件就知道怎麼回事，用法非常簡單。

`certfile` 和 `keyfile` 爲可選，配正確後 自身就變身 https 服務端，非翻牆流量直接轉發到 `forward_addr` 指向的目標。
若 `certfile` 和 `keyfile` 兩項配錯或乾脆不存在，則需要前置的 `反向代理` 如 `nginx` 協助。

注意 `tunnel_path` 配置項，請務必改成你自己獨有的複雜字符串，否則 `GFW` 立馬拿你祭旗。

```
{
    "tunnel_path": "/secret-tunnel-path/",

    "server_settings": {
        "certfile": "/etc/mysite_cert/fullchain.pem",
        "keyfile": "/etc/mysite_cert/privkey.pem",
        "forward_addr": "127.0.0.1:80",
        "listen_host": "0.0.0.0",
        "listen_port": 443
    },

    "client_settings": {
        "server_host": "123.45.67.89",
        "server_port": 443,
        "server_domain": "example.com",
        "listen_host": "127.0.0.1",
        "listen_port": 1080
    }
}
```

本文件是最少條目的配置文件，完整的配置文件可以參考 [config.json](config.json)。

配置文件是 服務端 和 客戶端 通用的， 當程序以 服務端 身份運行時， `server_settings` 部分是有效的，`client_settings` 是被忽略的；反之，當程序以 客戶端 身份運行時，`client_settings` 部分是有效的，`server_settings` 部分是被忽略的。
