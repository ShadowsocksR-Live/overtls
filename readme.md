# overtls

overtls 代理軟件，通過 TLS 實現代理，支持 TCP 和 UDP 流量轉發。

功能齊備且代碼精簡，總共也就 1200 行代碼。

## 原理

爲了能有效騙過 [GFW](https://en.wikipedia.org/wiki/Great_Firewall)，直接使用 [TLS](https://en.wikipedia.org/wiki/Transport_Layer_Security) 作爲代理協議是最簡單的方法。
TLS 協議是一種加密協議，它的加密方式是對稱加密，即客戶端和服務端使用相同的密鑰進行加密解密。

我們可以利用這個特性，將客戶端和服務端的加密解密過程封裝成一個代理服務，這樣就可以在 GFW 的監視下，進行加密的 TCP 和 UDP 代理。

overtls 客戶端首先與 overtls 服務端建立 TLS 連接，然後 overtls 客戶端和 overtls 服務端之間的數據交換都是加密的。

我們只要約定 overtls 客戶端訪問某一特定資源 uri，就認爲是要進行代理，服務端會將含有這個 uri 的數據包轉發到指定的目標地址。

我們的代理就這樣達成了。

因此，overtls 服務端和 overtls 客戶端之間的數據交換是加密的，而 overtls 服務端和目標服務器之間的數據交換是明文的。

綜上所述，我們需要準備的東西有：
- 一個帶公網 IP 的 VPS 主機，必須自行購買，
- 一個域名，可以購買或申請免費的，並將該域名解析到 VPS 主機的 IP 上，
- 一對 https 證書/私鑰，證書可以自行購買，也可以在 [Let's Encrypt](https://letsencrypt.org/) 申請免費的，
- 一個 http 服務端軟件（如 [nginx](https://www.nginx.com/) ），並提供用於僞裝用途的站點資源或者充當前置的 `反向代理`，

## 安裝

可直接從源代碼編譯，也可以從 [發布頁面](https://github.com/ssrlive/overtls/releases) 下載預編譯的二進制文件。

## 用法

### 服務端

```bash
$ overtls server -c config.json
```

### 客戶端

```bash
$ overtls client -c config.json
```

### 配置文件

```json
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
配置文件非常簡單。是 `服務端` 和 `客戶端` 通用的， 
- 當程序以 `服務端` 身份運行時，`server_settings` 部分是有效的，而 `client_settings` 部分是被忽略的；
- 當程序以 `客戶端` 身份運行時，`client_settings` 部分是有效的，而 `server_settings` 部分是被忽略的。

`certfile` 和 `keyfile` 爲可選項，配正確後 軟件就變身 https 協議服務端，非翻牆流量直接轉發到 `forward_addr` 指向的目標。
若 `certfile` 和 `keyfile` 兩項配錯或乾脆不存在，則需要前置的 `反向代理` 如 `nginx` 協助方可工作。

注意 `tunnel_path` 配置項，請務必改成你自己獨有的複雜字符串，否則 `GFW` 立馬拿你祭旗。

> 爲方便測試，提供了 `disable_tls` 選項以停用 `TLS` 的能力；就是說，若該項存在且爲 `true` 時，本軟件將 `明文(plain text)` 傳輸流量；出於安全考慮，正式場合請勿使用。

本示例展示的是最少條目的配置文件，完整的配置文件可以參考 [config.json](config.json)。
