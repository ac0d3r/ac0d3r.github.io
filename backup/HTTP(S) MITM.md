# HTTP(S) MITM

> [https://en.wikipedia.org/wiki/Man-in-the-middle_attack](https://en.wikipedia.org/wiki/Man-in-the-middle_attack)

<img width="300" src="https://github.com/user-attachments/assets/412125a9-c5ce-4c4f-a652-8785720e1c44" />

中间人攻击（Man-in-the-middle attack，缩写：MITM）是指攻击者与通讯的两端分别创建独立的联系，并交换其所收到的数据，使通讯的两端认为他们正在通过一个私密的连接与对方直接对话，但事实上整个会话都被攻击者完全控制。

# **HTTP(S)中间人代理**

## HTTP

<img width="300" src="https://github.com/user-attachments/assets/7af5b1fe-4494-40b3-8d0c-74d673971426" />

HTTP 是超文本传输协议，数据在客户端（比如浏览器）和服务器之间传输时是明文的。想要监听 HTTP 流量实现起来非常简单，只要充当 Proxy Server 拦截网络流量，接受并解析 HTTP 请求转发给目标服务器，把真正的服务器响应内容转发给客户端，或者伪造的响应给客户端。

下面以 [mitmproxy](https://mitmproxy.org/) 为例子：

- 启动 proxy server `mitmproxy -p 8081`
- 设置系统代理
    
    在macOS中，在 `WIFI - Proxies` 设置 Web proxy:
    
    <img width="300" src="https://github.com/user-attachments/assets/4cc18fcc-155e-4a3f-bb69-e0cdb5c51c9c" />

- 用浏览器访问一个 http 网页（⚠️使用系统代理），在 mitmproxy 中就捕获到HTTP 请求：
    
    <img width="300" src="https://github.com/user-attachments/assets/dad060bf-2551-4d67-9ca4-6260a347082a" />

## HTTPS

HTTPS 是基于 HTTP 的安全版本，加了 SSL/TLS 加密层：

<img width="300" src="https://github.com/user-attachments/assets/2e30e6da-45b0-4cd7-b0f2-e8407f5cbbd8" />

`SSL/TLS` 的功能实现主要依赖于三类基本算法，『散列函数』、『对称加密』和『非对称加密』，其利用非对称加密实现身份认证和密钥协商，对称加密算法采用协商的密钥对数据加密，基于散列函数验证信息的完整性。

<img width="300" src="https://github.com/user-attachments/assets/1d62f614-3673-4243-90ea-28c16eeac1f2" />

> (from: [https://heptaluan.github.io/2020/08/09/HTTP/09/](https://heptaluan.github.io/2020/08/09/HTTP/09/)

### HTTPS 是如何请求的

HTTPS 的请求过程比 HTTP 多了一些步骤，主要包括建立安全连接和数据传输两部分：

<img width="400" src="https://github.com/user-attachments/assets/bf9c7373-df4b-448c-9418-bcd54c5711cc" />

- **建立 TCP 连接：**客户端（比如浏览器）先通过 TCP 三次握手跟服务器（通常是 443 端口）建立连接。
- **SSL/TLS 握手：**在 TCP 连接建立后，客户端和服务器通过 TLS 握手协商加密方式，确保通信安全：
    - **客户端问候（Client Hello）**：客户端发送支持的加密算法（Cipher Suites）、TLS 版本和一个随机数。
    - **服务器回应（Server Hello）**：服务器选定一种加密算法，返回自己的证书（含公钥）和另一个随机数。
    - **验证证书**：客户端用操作系统或浏览器内置的根证书验证服务器证书的合法性，确保没被伪造。
    - **密钥交换（现代实践）**：客户端与服务器通过 ECDHE/DHE 等临时 Diffie-Hellman 协议协商出共享秘密，并据此派生会话密钥（Session Key），提供前向保密。历史上也存在“用服务器公钥直接加密会话密钥”的 RSA 密钥交换，但在 TLS 1.3 中已移除。
    - **握手完成**：双方确认加密参数，握手结束，之后的通信都用会话密钥加密。
- **发送加密的 HTTP 请求：**握手完成后，客户端用会话密钥加密 HTTP 请求，请求内容包括 URL、Header、Body 等（如 GET /index.html），发给服务器。
- **服务器响应：**服务器收到加密请求，用会话密钥解密，处理后返回加密的响应。

### **数字证书链**

补充说明：实际部署中通常由“中间 CA”签发服务器证书。客户端会构建从服务器证书到根 CA 的完整链并进行主机名校验（优先检查证书的 SAN），还可能进行 OCSP 或 CRL 状态检查以确认证书未被吊销。

数字证书链的核心是**证书中心**(certificate authority，简称CA)，合法CA的公钥是**预存**在操作系统和浏览器里的，只有通过了CA认证的服务器公钥才被浏览器客户端认为是可信的公钥。认证的原理很简单，依然是公私钥原理。CA拿自己的私钥去给需要认证的服务器公钥签名，生成一个“数字证书”。数字证书是包含了CA的签名，服务器自身公钥等等信息的集合体。浏览器拿着CA的公钥去验证该签名。只有被CA公钥验证通过的证书才是可信任的证书。

<img width="400" src="https://github.com/user-attachments/assets/2c7f8240-0e52-47a0-b9db-508c4cccab38" />

> (from [https://github.com/wuchangming/https-mitm-proxy-handbook/blob/master/doc/Chapter3.md](https://github.com/wuchangming/https-mitm-proxy-handbook/blob/master/doc/Chapter3.md)

### 伪造并信任CA证书

> 🔒安全提示：生成的根 CA 私钥仅用于本地调试，务必妥善保管并限制文件权限。不要在生产或不受控环境中安装或分发自签 CA。滥用可能带来严重安全与合规风险。

让自定义的CA证书得到了客户端的信任，就能用CA证书签发各种“伪造”的服务器证书。

使用 [github.com/google/martian](http://github.com/google/martian) 库来生成CA根证书：

```go
package cert

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"testing"
	"time"

	"github.com/google/martian/v3/mitm"
)

func TestGenCA(t *testing.T) {
	x509c, priv, err := mitm.NewAuthority("zznq.mitm", "ZZNQ MITM", 10*365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	certOut, err := os.Create("./ca.pem")
	if err != nil {
		t.Fatal(err)
	}
	defer certOut.Close()
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: x509c.Raw})

	keyOut, err := os.Create("./ca.key")
	if err != nil {
		t.Fatal(err)
	}
	defer keyOut.Close()

	pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
}

```

在对应操作系统上安装并信任证书：

<img width="300" src="https://github.com/user-attachments/assets/9dcb7df0-98fc-444a-bf8e-df95f33c72c9" />

### 如何劫持HTTPS流量

> [https://docs.mitmproxy.org/stable/concepts-howmitmproxyworks/#explicit-https](https://docs.mitmproxy.org/stable/concepts-howmitmproxyworks/#explicit-https)
> 

<img width="400" src="https://github.com/user-attachments/assets/3b29e15c-a1ed-4353-9700-77c5086fee2b" />

以 mitmproxy 为例：

1. 客户端与 mitmproxy 建立连接，并发出 HTTP CONNECT 请求。
2. Mitmproxy 以 `200 Connection Established` 进行响应，就像它已经设置了 CONNECT 管道一样。客户端认为它正在与远程服务器通信，并启动 TLS 连接。它使用 SNI 来指示它要连接到的主机名。
3. Mitmproxy 连接到服务器，并使用客户端指示的 SNI 主机名建立 TLS 连接。
4. 服务器使用匹配的证书进行响应，该证书包含生成拦截证书所需的 CN 和 SAN 值。
5. Mitmproxy 生成拦截证书，并继续在步骤 3 中暂停的客户端 TLS 握手。
6. 客户端通过已建立的 TLS 连接发送请求。
7. Mitmproxy 通过步骤 4 中启动的 TLS 连接将请求传递到服务器。

### 使用martian实现

```go
package main

import (
	"crypto/tls"
	"crypto/x509"
	"log"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/google/martian/v3"
	"github.com/google/martian/v3/mitm"
)

var defaultTimeout = 5 * time.Second

func main() {
	skipTLSVerify := true
	parentProxy := ""
	certFile := "./ca.pem"
	keyFile := "./ca.key"

	proxy := martian.NewProxy()
	proxy.SetRoundTripper(&http.Transport{
		MaxIdleConns:          100,
		TLSHandshakeTimeout:   defaultTimeout,
		ExpectContinueTimeout: defaultTimeout,
		ResponseHeaderTimeout: defaultTimeout,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: skipTLSVerify,
		},
	})

	if parentProxy != "" {
		proxyURL, err := url.Parse(parentProxy)
		if err != nil {
			log.Fatal(err)
		}
		proxy.SetDownstreamProxy(proxyURL)
	}

	// config mitm cert file
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		log.Fatal(err)
	}
	x509c, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		log.Fatal(err)
	}
	tlscnf, err := mitm.NewConfig(x509c, cert.PrivateKey)
	if err != nil {
		log.Fatal(err)
	}
	tlscnf.SkipTLSVerify(skipTLSVerify)
	proxy.SetMITM(tlscnf)

	// set request, response modifier
	proxy.SetRequestModifier(martian.RequestModifierFunc(
		func(req *http.Request) error {
			log.Printf("[mitm] modify request - method: %s url: %s", req.Method, req.URL.String())
			return nil
		}))
	proxy.SetResponseModifier(martian.ResponseModifierFunc(
		func(res *http.Response) error {
			log.Printf("[mitm] modify response - method: %s url: %s status: %d", res.Request.Method, res.Request.URL.String(), res.StatusCode)
			return nil
		}))

	// start proxy server
	listener, err := net.Listen("tcp", ":8081")
	if err != nil {
		log.Fatalf("listen error: %v", err)
	}
	defer listener.Close()

	log.Printf("proxy server listen on %s", listener.Addr().String())
	if err := proxy.Serve(listener); err != nil {
		log.Fatalf("proxy serve error: %v", err)
	}
}

```

运行测试HTTPS中间人代理:

> ⚠️该示例将上游 TLS 校验设置为 InsecureSkipVerify=true，仅用于本地调试。生产环境请关闭此选项，或配置受信任的上游 CA 与证书校验，以防止上游被劫持。

<img width="400" src="https://github.com/user-attachments/assets/a364d6c9-8e96-475b-b1c1-9577b8057018" />

# 透明代理

透明代理（Transparent Proxy）是一种网络代理方式，其特点是客户端无需手动配置代理设置，网络流量就会被自动拦截并通过代理服务器处理。

## 透明 HTTP(S)

> [https://docs.mitmproxy.org/stable/concepts-howmitmproxyworks/#transparent-https](https://docs.mitmproxy.org/stable/concepts-howmitmproxyworks/#transparent-https)

<img width="400" src="https://github.com/user-attachments/assets/40236ce3-8f12-4770-a14e-b86a7196f889" />

使用透明代理时，连接将重定向到网络层的代理，而无需任何客户端配置。

通过路由（routing）的机制将原始目标端口为80，443等连接重定向到Proxy server，然后按照显式 HTTPS 连接来建立 CN 和 SAN，并处理 SNI。

## 流量重定向

> [https://docs.mitmproxy.org/stable/howto-transparent/](https://docs.mitmproxy.org/stable/howto-transparent/)

- 在 Linux 下可以使用 `iptables` 工具来实现
    
    ```bash
    sudo sysctl -w net.ipv4.ip_forward=1
    sudo sysctl -w net.ipv6.conf.all.forwarding=1
    sudo iptables -t nat -A PREROUTING -i eth1 -p tcp --dport 80 -j REDIRECT --to-port 8081
    sudo iptables -t nat -A PREROUTING -i eth1 -p tcp --dport 443 -j REDIRECT --to-port 8081
    ```
    
- macOS 下可以使用 [pf](https://docs.mitmproxy.org/stable/howto-transparent/#macos)
    
    ```bash
    sudo sysctl -w net.inet.ip.forwarding=1
    ## in pf.conf
    rdr pass on en0 inet proto tcp to any port {80, 443} -> 127.0.0.1 port 8081
    ## pf.conf EOF
    sudo pfctl -f pf.conf
    sudo pfctl -e
    ```
    

### Local capture

> [https://github.com/mitmproxy/mitmproxy_rs](https://github.com/mitmproxy/mitmproxy_rs)

- macOS
    
    在macOS 下使用的 network-extension(App Proxy Provider)，它处在传输层只拦截和处理 TCP/UDP 流量，通过 `NEAppProxyTCPFlow` 和 `NEAppProxyUDPFlow` 等类操作基于流的连接。
    
- Linux
    
    用 eBPF 在内核处拦截流量(Layer 3)和用户空间网络栈对TCP重组(Layer 4) 再转发。
    

### WireGuard

> [https://www.wireguard.com/](https://www.wireguard.com/)

WireGuard 是一种现代 VPN 协议，运行在网络层（Layer 3），通过用户空间或内核实现高效的 IP 数据包隧道传输。mitmproxy 的 WireGuard 模式利用 WireGuard 的隧道功能，将客户端的网络流量路由到 mitmproxy，然后由 mitmproxy 进行代理处理（如解密 HTTPS、记录流量等），最后转发到目标服务器。

适合对其它设备（Android, iOS）流量进行代理，如果 WireGuard 和 mitmproxy 运行在同一设备上，会导致数据包会循环路由。

## 如何基于TUN自己实现透明代理

### TUN

TUN/TAP 是操作系统内核中的虚拟网络设备，由软件进行实现，向操作系统和应用程序提供与硬件网络设备完全相同的功能。其中 TAP 是以太网设备(二层设备)，操作和封装以太网数据帧，TUN 则是网络层设备(Layer 3)，操作和封装网络层数据帧。

在操作系统中，TUN 设备允许用户空间程序（如 VPN 客户端）读写网络数据包，通常以 IP 数据包的形式（区别于 TAP 设备，TAP 工作在更低的以太网帧级别）。

<img width="300" src="https://github.com/user-attachments/assets/0f83d1cf-4fc6-4d42-b8d3-07a34eb07820" />

> (from [https://paper.seebug.org/1648/](https://paper.seebug.org/1648/)

### 什么是VPN?

VPN 全称为虚拟私人网络(Virtual Private Network)，常用于连接中、大型企业或团体间私人网络的通讯方法，利用隧道协议（Tunneling Protocol）来达到发送端认证、消息保密与准确性等功能。

<img width="300" src="https://github.com/user-attachments/assets/3abe17c6-cec6-4223-a6c9-b19071093f51" />

> (from [https://paper.seebug.org/1648/](https://paper.seebug.org/1648/)

VPN的核心工作原理就依赖于TUN设备，通过 TUN 你数据(Layer 3)打包（封装、加密）后通过公共网络发送到VPN服务器，再由服务器解包并转发到目标地址。

### 设计思路

<img width="400" src="https://github.com/user-attachments/assets/07b4d280-5e44-404c-97fa-918951af97f0" />

这里要非常小心数据包循环路由，就是通过 Proxy 发出的流量又根据路由表规则再次经过 TUN 重新回到了Proxy段。

- 一般防止环路的方法：[https://zu1k.com/posts/coding/tun-mode/#防止环路](https://zu1k.com/posts/coding/tun-mode/#%E9%98%B2%E6%AD%A2%E7%8E%AF%E8%B7%AF)
- 还有一种类似软路由思路，区分入口网卡和出口网卡，这样也不会出现环路： 
    <img width="400" src="https://github.com/user-attachments/assets/0fc7469a-e9d8-4fa9-af70-4006a0855391" />

使用 [wireguard-go](https://git.zx2c4.com/wireguard-go/tree/tun) 创建 tun 设备，基于 [gvisor](https://github.com/google/gvisor/tree/master/pkg/tcpip) 的 TCP/IP 协议栈处理IP层流量，还是使用 [martian](http://github.com/google/martian) 实现HTTPS中间人。区别呢就是不需要再去 Listen 一个端口，去实现一个满足 `func (p *Proxy) Serve(l net.Listener)` 入参的  `net.Listener` 接口就行。

# 引用资源

- https://github.com/google/martian
- https://github.com/wuchangming/https-mitm-proxy-handbook
- [https://mitmproxy.org/](https://mitmproxy.org/)
- [https://www.wireguard.com/](https://www.wireguard.com/)
- [https://stack.chaitin.com/techblog/detail/40](https://stack.chaitin.com/techblog/detail/40)
- [https://paper.seebug.org/1648/](https://paper.seebug.org/1648/)
- [https://zu1k.com/posts/coding/tun-mode/](https://zu1k.com/posts/coding/tun-mode/)