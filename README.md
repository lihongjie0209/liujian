# 流鉴（liujian）

Go 命令行抓包工具，支持手机只修改 DNS 后抓取常见 HTTP/HTTPS 流量，也支持智能端口上的显式 HTTP 和 SOCKS5 代理。终端中可查看实时会话、历史请求和 WebSocket 文本/二进制消息，并导出 HAR 1.2。

## 下载与运行

从 [Releases](https://github.com/lihongjie0209/liujian/releases) 下载对应系统和架构的压缩包，解压后直接运行。提供 Linux（amd64、arm64、armv7）、macOS（Intel、Apple Silicon）和 Windows（amd64、arm64）版本；另附 `checksums.txt` 供 SHA-256 校验。程序面向 IPv4 局域网。

Linux 示例：

```sh
sudo setcap cap_net_bind_service=+ep ./liujian
./liujian run --upstream-dns 1.1.1.1:53
```

macOS 上监听 53/80/443 需要 `sudo ./liujian run --upstream-dns 1.1.1.1:53`。Windows 在 PowerShell 中运行 `./liujian.exe run --upstream-dns 1.1.1.1:53`，并允许系统防火墙的入站连接。运行 `liujian --help` 查看命令和参数。

从源码构建需要 Go 1.25 或更新版本：

```sh
git clone https://github.com/lihongjie0209/liujian.git
cd liujian
go build -o liujian ./cmd/liujian
```


默认在所有 IPv4 网卡（`0.0.0.0`）监听 DNS UDP/TCP 53、HTTP 80、HTTPS 443 和 HTTP/SOCKS5 智能代理 8080。DNS 按请求来源 IP 匹配本机接口网段，返回同网段的监听地址；重叠网段取最具体的匹配。TUI 会列出本机局域网地址；手机 DNS 需要设置为其中一个可达地址，不能填写 `0.0.0.0`。如需只监听一个地址，可显式设置 `--listen-ip 192.168.1.20`。确保本机防火墙允许手机访问这些端口。`--upstream-dns` 可省略，此时读取系统 DNS 解析配置中的上游服务器；它不能指向抓包机自身。

如果 DNS 客户端来自其他网段（例如经过路由或 DNS 转发器），需显式指定响应地址。规则按客户端 CIDR 匹配，右侧 IP 必须是抓包机本地接口上的地址，且能从该客户端网络访问。显式规则优先于自动匹配，重叠规则取最具体的一条；无法匹配时返回 SERVFAIL，不会返回 `0.0.0.0`：

```sh
./liujian run --dns-answer-rule 192.168.50.0/24=192.168.1.20 \
  --dns-answer-rule 10.8.0.0/16=10.0.0.8
```

如果目标应用使用非标准端口，可在保留默认端口的同时追加监听端口：

```sh
./liujian run \
  --http-extra-ports 8081,9000 --https-extra-ports 8443,9443 \
  --exclude '*.skip.example'
```

额外端口需要标明是 HTTP 还是 HTTPS，并且不能与 DNS、智能代理或其他监听端口重复。会话仍按请求中的原始域名和端口连接上游。要修改默认端口，可使用 `--http-port`、`--https-port`；`--dns-port` 主要用于测试或受限环境，`--proxy-port` 可调整智能代理端口。手机仅改 DNS 的实际使用仍需让其请求到对应的监听端口。

只抓指定目标时，可重复使用 `--allow-host`，填写完整域名、子域名通配符、目标 IP 或 CIDR；`--allow-client` 可限制手机等客户端的 IP 或 CIDR。两类条件同时设置时必须同时命中。未命中的 DNS 查询会交给上游，显式代理请求则直接转发且不保存会话。未设置白名单时仍抓取所有可处理的目标。

```sh
./liujian run --allow-host api.example.com --allow-host '*.example.net' \
  --allow-host 203.0.113.0/24 --allow-client 192.168.1.50
```

按目标 IP 筛选域名时，程序先查询上游 DNS 的 A 记录再决定是否重写；目标没有匹配的 A 记录时不抓取。`*.example.net` 匹配子域名，不匹配 `example.net` 本身。`ca-proxy.test` 的证书下载入口始终可访问。

在同一 Wi-Fi 下，将手机的 DNS 服务器改为抓包机地址。然后在手机浏览器访问 `http://ca-proxy.test/ca.crt` 获取当前 CA 证书。iOS 安装后还需在“证书信任设置”启用完全信任。Android 新版应用默认可能不信任用户安装的 CA，证书绑定的应用也可能拒绝抓包证书。也可以手动导出证书并传到手机：

```sh
./liujian ca export ./ca.crt
```

程序内置八组公开测试用 eMudhra CA，默认使用 `EM-DV-TLS-CA-G3C`。它们的私钥已公开泄露，证书已吊销，**仅可用于隔离测试**；现代客户端可能直接拒绝它们签发的证书。两组 `CS` CA 仅有代码签名用途，不适合 TLS 流量。可列出内置名称，并在运行或导出时显式选择：

内置 TLS CA 签发的站点证书会附带 eMudhra 官方的 `emSign Root TLS CA - G3` 交叉签名证书，以便客户端将证书链连接到已有的 `emSign ECC Root CA - G3` 信任锚。完整证书链也无法消除客户端对已泄露或已撤销 CA 的主动阻止。

```sh
./liujian ca profiles
./liujian --ca-profile EM-OV-TLS-CA-G3B run
./liujian --ca-profile EM-OV-TLS-CA-G3B ca export ./ca.crt
```

已有自己的 CA 可导入 PEM 证书与匹配的未加密私钥；导入时会校验 CA 用途、有效期及密钥匹配。导入后重启抓包进程：

```sh
./liujian ca import ./my-ca.crt ./my-ca.key
```

导入的 CA 默认保存在 `~/.local/share/ca-proxy/ca.pem`（沿用旧版数据目录，以保留已有证书和会话），并优先于内置默认 CA；显式传入 `--ca-profile` 时则使用指定的内置 CA。要清除本地 CA 覆盖，可移走该 `ca.pem`。会话默认保存在同一数据目录；可用 `--data-dir` 更改。上游 HTTPS 证书会正常校验。

也可以生成一组新的本地 CA，再将导出的证书安装到测试设备。`ca create` 遇到现有 `ca.pem` 会拒绝覆盖；生成后重启抓包进程。`ca diagnose` 显示当前 CA、为目标签发的证书，以及目标上游的证书链与系统信任结果；它无法判断客户端的证书绑定或吊销检查。

```sh
./liujian ca create
./liujian ca export ./ca.crt
./liujian ca diagnose api.example.com
./liujian ca diagnose api.example.com --connect-to 192.0.2.10:443
```

## 智能代理端口

`--proxy-port` 默认是 `8080`，同一端口会自动识别 HTTP 代理与 SOCKS5，无须分别配置。可直接把浏览器或系统代理设置为 `抓包机IP:8080`，协议选择 HTTP 或 SOCKS5；SOCKS5 使用免认证模式，并允许局域网或本机客户端连接。当前支持 SOCKS5 TCP CONNECT；BIND 与 UDP ASSOCIATE 返回不支持。

SOCKS5 的 HTTP、HTTPS 请求沿用 CA 动态证书、白名单、脚本、TUI 和存储流程；其他 TCP 协议只转发，不解析正文。浏览器使用 SOCKS5 时建议启用由代理端解析域名，以保留域名供证书签发和会话展示。客户端如果使用证书绑定或拒绝测试 CA，HTTPS 仍可能无法解密。

```sh
./liujian run --proxy-port 8080
curl --proxy http://127.0.0.1:8080 http://example.com/
curl --proxy socks5h://127.0.0.1:8080 http://example.com/
```

## 查看和导出

实时 TUI 顶部显示当前 DNS、HTTP、HTTPS、HTTP/SOCKS5 智能代理监听端口，以及手机 DNS 和 CA 证书安装指引。默认监听所有 IPv4 网卡时，顶部会列出可供手机使用的局域网地址及 DNS 响应规则。启动时会检查防火墙状态，此后每 15 秒刷新一次；Windows 下检查当前程序的入站允许或阻止规则，未找到允许规则时提示手机访问尚未验证。此检查不能代替从手机实际连接测试。TLS 握手失败会显示为列表中的失败记录，Enter 可查看 SNI、客户端地址、错误原因和合并次数；同一错误每 10 秒最多新增一行，顶部也有总次数，不会逐条刷屏。其他服务错误写入数据目录下的 `ca-proxy.log`。手机常规 DNS 设置使用 53 端口；如果启动参数为其他 DNS 端口，TUI 会提示改为 `--dns-port 53`。监听地址为本机回环地址时，也会提示改用局域网 IPv4 地址。

列表按 Chrome Network 风格展示 Name、Status、Type、Initiator、Size、Time、Waterfall；状态码按成功、跳转、失败着色。左右方向键切换 All、Fetch/XHR、Doc、CSS、JS、Img、Media、Font、WS、SSE、Manifest、Wasm、TLS、Other 类型，`0` 返回 All。上下方向键选择请求，Enter 打开详情。详情中用 Tab 切换 Headers、Payload、Preview、Response、Cookies、Timing；SSE/WS 请求还有 Messages 标签，可以选中消息并按 Enter 查看正文；执行过脚本的会话还有 Scripts 标签，显示每个脚本的格式化输出、控制台日志与错误。JSON/HTML 会格式化并高亮。Esc 返回上一级；列表中按 `/` 输入筛选条件，多项条件用空格连接，例如 `url:/api proto:https method:GET status:200 client:192.168.1.50 resp:token`。多个条件默认是 AND，也支持 `&`、`|`、`!`、括号及引号，例如 `(method:POST | status:5xx) & !url:/health`。`req:` 和 `resp:` 分别搜索请求和响应的 URL/状态、头、正文；普通文本搜索这些内容及错误。gzip 压缩正文也会解压后索引；其他未知压缩格式和加密正文需要脚本先转换成可读文本。`proto:` 支持 `http`、`https`、`ws`、`wss`、`websocket`、`sse`、`h2`、`http1`。在详情按 `r` 重放当前 HTTP 请求，按 `c` 使用 OSC 52 复制 cURL 命令（取决于终端剪贴板支持）。PageUp/PageDown 滚动详情，`q` 退出。退出后可重新打开历史或导出：

```sh
./liujian sessions
./liujian sessions export ./capture.har
./liujian sessions export ./errors.har --filter 'status:5xx | error:tls'
./liujian sessions replay 123
./liujian sessions curl 123
```

重放会直连目标上游，保留原方法、头和已保存的请求正文，并把新响应存成一条会话；不会自动跟随重定向。请求正文已截断或 WebSocket 握手会话不能重放。导出的 cURL 命令适用于 POSIX shell；含正文时使用 `xxd` 传递二进制数据。

通过 `--mock-config` 可按顺序匹配并替换响应：使用已保存的会话响应，或从本地文件读取正文。匹配不到的请求正常发往上游。配置在启动时读取，改动后需要重启；文件路径相对配置文件定位。模拟响应也会写入会话。示例配置见 [examples/mocks.json](examples/mocks.json)。

```sh
./liujian run --mock-config ./examples/mocks.json
```

无头模式可输出方便脚本和 AI 逐行读取的 JSON Lines；每个 HTTP/TLS 会话以及每条 WebSocket/SSE 消息各占一行。诊断信息写入 stderr，标准输出只包含数据。`--no-tui` 是 `--headless` 的兼容别名：

```sh
./liujian run --headless --output jsonl > capture.jsonl
./liujian run --headless --output console
./liujian run --headless --output jsonl --inline-body-bytes 1024 --body-dir ./capture-bodies
./liujian run --capture-log ./capture.jsonl  # 同时显示 TUI 并记录 JSONL
./liujian run --headless --output jsonl --filter '(method:POST | status:5xx) & !url:/health'
```

正文超过 `--inline-body-bytes`（默认 4096 字节）时，输出中用绝对 `path` 指向单独的 `.body` 文件；较小的文本正文直接写入 `text`，二进制正文用 `base64`。正文文件仅当前用户可读。每个请求/响应正文默认最多保存 10 MiB，每条 WebSocket 或 SSE 消息默认最多保存 1 MiB，可用 `--body-mb` 和 `--frame-mb` 调整；超过上限的内容会标记为 `truncated`。SSE 和 WebSocket 消息在连接保持打开时也会持续输出。默认保留约 1 GiB 的 SQLite 会话数据，可用 `--disk-mb` 调整；单独导出的正文文件不计入此限制，需要自行清理。HAR 中 WebSocket 消息和 SSE 事件分别位于自定义 `_webSocketMessages`、`_sseEvents` 字段；总耗时有记录，阶段耗时为近似值。

## 请求和响应脚本

通过 `--script-config` 加载多个 JavaScript 脚本，按配置顺序处理 HTTP 请求和响应；每个脚本接收一个对象并返回新的对象。正文 `body` 是 `Uint8Array`，可处理 JSON、HTML、加密数据或任意二进制格式。可修改请求的 `method`、`url` 的路径及查询参数、`headers`、`body`；可修改响应的 `status`、`headers`、`body`。为避免绕过抓包白名单，请求 URL 的协议和主机不能改变。`display` 是只用于详情展示的文本，不会传给上游或客户端；`console.log()` 输出和报错也会记录到会话。`utf8Decode(bytes)` 和 `utf8Encode(text)` 可用于文本转换。

```sh
./liujian run --script-config ./examples/scripts.json
```

配置示例见 [examples/scripts.json](examples/scripts.json)，脚本示例见 [examples/format-api.js](examples/format-api.js)。配置中的 `file` 相对配置文件定位；`phases` 可选，取值为 `request`、`response`，省略时执行脚本实现的阶段函数。脚本定义 `onRequest(request)` 和/或 `onResponse(response)`，返回包含修改后字段的对象。脚本默认最多执行 2 秒，`timeout_ms` 可调整到 1–60000。脚本失败时保留原对象并继续执行后续脚本，错误在 Scripts 标签、JSONL 的 `scripts` 字段和 HAR 的 `_scripts` 字段中可见。超过 `--body-mb` 的正文不会交给脚本处理；SSE 持续响应和 WebSocket 消息目前不执行响应正文脚本。

每个脚本都可使用 `ca` 工具对象；除文字编码和格式化外，二进制方法均接收或返回 `Uint8Array`：

| 能力 | 方法 |
| --- | --- |
| UTF-8 | `ca.text.encode(text)`、`ca.text.decode(bytes)`；兼容旧的 `utf8Encode`、`utf8Decode` |
| Base64 | `ca.base64.encode(bytes)`、`decode(text)`、`urlEncode(bytes)`、`urlDecode(text)` |
| Hex | `ca.hex.encode(bytes)`、`ca.hex.decode(text)` |
| gzip | `ca.gzip.compress(bytes)`、`ca.gzip.decompress(bytes)` |
| JSON | `ca.json.pretty(bytes)` 返回格式化文本；解析仍可用 JS 的 `JSON.parse` |
| URL 查询值 | `ca.url.encode(text)`、`ca.url.decode(text)` |
| 摘要与签名 | `ca.crypto.sha256(bytes)`、`ca.crypto.hmacSHA256(key, bytes)` |
| 加解密 | `ca.crypto.aesGCMEncrypt(key, nonce, bytes, aad?)`、`aesGCMDecrypt(...)` |
| 随机数 | `ca.crypto.randomBytes(count)` |
| 国密摘要 | `ca.gm.sm3(bytes)`、`ca.gm.hmacSM3(key, bytes)` |
| SM4 | `ca.gm.sm4GCMEncrypt/Decrypt(key, nonce, bytes, aad?)`；`ca.gm.sm4CBCEncrypt/Decrypt(key, iv, bytes)` |
| SM2 | `ca.gm.sm2Encrypt(publicKey, bytes, format?)`、`ca.gm.sm2Decrypt(privateKey, bytes, format?)` |

AES-GCM 使用 16/24/32 字节密钥和 12 字节 nonce；密文包含末尾的认证标签，同一密钥下每次加密应使用不同 nonce。工具出错时会抛出可由 JS `try/catch` 捕获的异常；解压结果及工具返回的二进制内容受 `--body-mb` 上限约束。`console.log`、`console.warn`、`console.error` 会显示在 Scripts 标签。脚本运行时不提供 Node.js 的 `require`、文件或网络 API。

国密实现使用 [emmansun/gmsm](https://github.com/emmansun/gmsm)。SM4 使用 16 字节密钥；GCM 使用 12 字节 nonce，CBC 使用 16 字节 IV 和 PKCS#7 填充。SM2 公钥输入为 65 字节未压缩点，私钥输入为 32 字节原始标量；`format` 可取 `"c1c3c2"`（默认）、`"c1c2c3"`、`"asn1"`。可先用 `ca.hex.decode` 或 `ca.base64.decode` 将已有密钥和密文转为字节，再传入国密方法。例如：

```js
var plaintext = ca.gm.sm2Decrypt(
  ca.hex.decode(privateKeyHex),
  ca.base64.decode(responseText),
  "c1c3c2"
);
response.display = ca.text.decode(plaintext);
```

其中 `privateKeyHex` 和 `responseText` 应由脚本从已知测试数据中取得。`display` 只显示解密结果；若要修改实际响应，还需设置 `response.body = plaintext` 并同步调整相关响应头。

## 发布

推送 `v*` 标签后，GitHub Actions 会运行测试，并使用 GoReleaser 构建各平台压缩包及 SHA-256 校验文件。常规推送和 Pull Request 也会运行单元测试与 `go vet`。发布配置见 [.goreleaser.yaml](.goreleaser.yaml) 和 [.github/workflows/release.yml](.github/workflows/release.yml)。

## 测试

交互逻辑使用快速的模型测试，终端测试单独运行：

```sh
go test ./...
go test -tags integration ./cmd/liujian -run TestCLIProxyTUIAndHAR
```

## 抓包范围

DNS 模式默认把域名解析到抓包机，仅对配置的 HTTP/HTTPS 端口提供服务。其他端口的连接可能失败，可用 `--exclude` 将域名交回上游 DNS。直连 IP、应用内 DoH/DoT、HTTP/3/QUIC、证书绑定及不信任用户 CA 的应用无法保证解密。当前不提供网关或 VPN 模式。

协议实现参考了 [go-mitmproxy](https://github.com/lqqyt2423/go-mitmproxy) 的设计；本项目代码按自己的 CLI、DNS、代理、证书、存储和 TUI 模块组织，没有直接复制其源码。

内置测试 CA 的背景见 [Mozilla eMudhra 事件记录](https://bugzilla.mozilla.org/show_bug.cgi?id=2083449)。

参考 [mitmproxy 12.3 发布说明](https://www.mitmproxy.org/posts/releases/mitmproxy-12.3/)，本工具在连接上游 HTTPS/WSS 时仍按系统或显式配置的根证书验证，并额外拒绝证书链中使用已公开 eMudhra 签名密钥的证书。该检查不会影响本地测试客户端所用的内置 CA。

## 许可证与测试 CA

源代码按 [MIT 许可证](LICENSE) 发布。内置的第三方测试证书及私钥不属于该许可证授权范围；这些密钥已公开泄露且相关证书已吊销，不应在生产环境使用。抓取的流量可能包含敏感数据，请仅在有权测试的设备和网络中运行。
