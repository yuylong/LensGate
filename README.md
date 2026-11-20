# Lensgate：AI 安全网关 Demo（PC 端 AI 流量观察）

一个用 Go 实现的单机 Demo：通过显式正向代理截获 HTTP/HTTPS 流量，按“协议指纹”识别 OpenAI 兼容调用，解析请求/响应与 SSE 流，命中检测规则后产生告警和日志，其余流量透明放行。

对应规划文档：`PC端AI流量安全分析Demo规划（正向代理与OpenAI）.md`

## 1. 已实现能力

- **显式 HTTP/HTTPS 正向代理**：`CONNECT` 后本地 MITM，按 SNI 动态签发证书。
- **协议识别而非域名识别**：路径形态 + JSON Schema + 认证头/SDK 头 + 响应 `object`/SSE 事件，输出四级置信度：
  - `confirmed`：路径、报文结构、认证特征/已知域名同时匹配。
  - `compatible`：路径与报文结构匹配，但缺少认证或域名佐证。
  - `suspected`：只有路径或只有报文结构。
  - `not_ai`：未发现 OpenAI 特征，直接放行且不落盘正文。
- **支持多种变体**：
  - `/v1/chat/completions`、`/v1/responses`、`/v1/embeddings`
  - Azure：`/openai/deployments/{id}/chat/completions`
  - OpenRouter：`/api/v1/chat/completions`
  - vLLM / Ollama / LiteLLM / OneAPI 等兼容服务
- **流式聚合**：增量解析 SSE，聚合文本、工具调用、Token 用量与结束原因。
- **流式 Token 统计（usage 注入）**：真实上游的流式响应默认不返回 `usage`（Token 列为空的根因）；网关对 `stream=true` 的 chat completions 请求在转发前自动注入 `stream_options.include_usage=true`，使上游在流末尾附带 usage chunk。客户端已显式设置 `stream_options` 或请求体截断时跳过；存储的请求正文仍保留客户端原始报文，控制台 ParseStatus 标记 `stream_usage_injected`。该字段为 OpenAI 官方参数，Azure、vLLM、LiteLLM 等主流兼容服务均支持，兼容性风险极低。
- **检测规则**：
  - `DLP-001` 凭据泄露（OpenAI/AWS/GitHub Key、私钥、Bearer、明文口令）
  - `DLP-002` 个人敏感信息（手机号、身份证、邮箱、银行卡）
  - `PI-001` 提示词注入/越狱
  - `TOOL-001` 危险工具调用（命令执行、文件读写、数据库、外发）
  - `DISC-001` 未知域名 AI 调用（影子 AI / 自建代理）
- **客户端指纹识别**：依据 `Sec-Fetch-*`、`x-stainless-*`、框架特征头与 `User-Agent` 推断流量来自哪类客户端（浏览器直接访问 / 浏览器页面 JS / OpenAI Python·Node SDK / LangChain / LlamaIndex / OpenRouter / curl / Postman / Python HTTP / Go / Node / PowerShell / Hertz），在控制台以“客户端”列展示。已知非浏览器客户端的 UA 自声明（`hertz`、`curl` 等）优先于 `Sec-Fetch-*`：Electron 应用（如 Trae）的内嵌 Chromium 网络层会自动附加 `Sec-Fetch-*`，但其转发层 UA 是框架名，此时 UA 信息量更大。属**自声明指纹推断**：UA 可伪造，且只能识别到 SDK/工具层，无法穿透到上层 Agent 产品名。
- **实时控制台**：总览、流量列表、告警、规则说明，SSE 实时推送；点击任意流量行从右侧滑出详情抽屉，按分区展示请求头/正文、解析出的 messages/tools/tool_calls、响应体或 SSE 事件、Token 用量、命中规则与原始报文（`GET /api/flows/{id}` 按需拉取，列表接口保持轻量）。
- **可移植接入层**：核心管线只依赖 HTTP 请求/响应；显式代理与透明代理适配器共用同一个 `ingress.Handler`。
- **零第三方依赖**：仅使用 Go 标准库，`go build` 即可得到单二进制。

## 2. 快速开始

要求 Go 1.21+。

```powershell
cd <仓库目录>

# 终端 1：启动 mock OpenAI（HTTP 18080 / HTTPS 18443）
go run ./cmd/mock-openai

# 终端 2：启动网关（代理 8080 / 控制台 8081）
go run ./cmd/lensgate -insecure-upstream

# 浏览器打开控制台
start http://127.0.0.1:8081

# 终端 3：跑全部演示场景
go run ./cmd/demo-client -scenario all
```

`-insecure-upstream` 仅用于本地自签名 mock。接入真实服务时应去掉，并保持 `upstream_insecure_skip_verify=false`。

### 让真实应用走代理

把应用的 HTTP/HTTPS 代理设置为 `127.0.0.1:8080`。根证书在 Windows 上默认自动导入：

- 启动时执行 `certutil -user -addstore Root .\data\ca\ca.pem`，写入**当前用户**受信任根存储，不需要管理员权限，重复启动不会重复添加。
- 只对本机当前用户生效，Chrome/Edge/curl.exe 会直接信任；Firefox 使用独立存储，仍需手动导入。
- 参数：`-ca-store user`（默认）、`-ca-store machine`（写入本机存储，需管理员）、`-ca-store none`（关闭自动导入）。
- 也可以从控制台右上角「下载根证书」或 `http://127.0.0.1:8081/api/ca.pem` 手动导入。

命令行验证：

```powershell
$env:HTTPS_PROXY = "http://127.0.0.1:8080"
curl.exe --ssl-no-revoke https://api.openai.com/v1/models `
  -H "Authorization: Bearer <your-key>"
```

> Windows 自带的 `curl.exe` 走 Schannel，会强制校验证书吊销状态，而本地自签叶证书没有 CRL/OCSP，因此需要 `--ssl-no-revoke`（或 `-k` 跳过校验）。Chrome/Edge 使用系统信任库并会对本地根证书软失败，一般无需额外参数。

> 根私钥保存在 `data/ca/ca-key.pem`，仅用于本机 Demo，不要分发或用于生产。

## 3. 演示场景与预期告警

| 场景 | 请求 | 预期 |
| --- | --- | --- |
| `clean` | `/v1/chat/completions` 普通问答 | `confirmed`，仅 `DISC-001`（本地 mock 域名未登记） |
| `stream` | 同上，`stream=true` | SSE 聚合，文本/用量入库 |
| `pii` | 手机号、邮箱、身份证 | `DLP-002` |
| `leak` | `sk-...`、`AKIA...`、`api_key=` | `DLP-001`（请求与响应回显均命中） |
| `inject` | “忽略以上所有指令…” | `PI-001` |
| `tooldef` | 声明 `shell_exec` 工具 | `TOOL-001` |
| `toolcall` | 模型返回 `shell_exec` + `rm -rf` 参数 | `TOOL-001`（响应侧） |
| `responses` / `responses-stream` | `/v1/responses` | 识别为 `responses` 变体 |
| `embedding` | `/v1/embeddings` | 识别为 `embeddings` 变体并提取用量 |
| `azure` | `/openai/deployments/.../chat/completions` | Azure 变体，`api-key` 认证 |
| `unknown` | `localhost` 上的 `/api/v1/chat/completions` | `confirmed` + `DISC-001` |
| `curl` | 携带 `User-Agent: curl/8.7.1` | 客户端识别为 `curl` |
| `browser` | 携带 `Sec-Fetch-Mode: cors` + `Origin` | 客户端识别为 `browser-fetch` |

演示客户端的各场景刻意携带不同的客户端指纹头（stainless 头、`X-Langchain-Id`、Go/Node/curl/浏览器 UA 等），控制台“客户端”列可据此观察推断差异。注意这些指纹可被伪造，仅用于来源分类与影子 AI 排查，不能作为身份认证依据。

`127.0.0.1` 不在 `known_ai_hosts` 中，所以本地 mock 每次都会触发 `DISC-001`——这正好演示“未知域名上的 OpenAI 协议”识别。真实部署时把企业允许的 AI 服务域名加入配置即可。

## 4. 配置

复制 `config.example.json` 为 `config.json` 后按需修改；不存在时使用内置默认值。

```json
{
  "proxy_addr": "127.0.0.1:8080",
  "api_addr": "127.0.0.1:8081",
  "data_dir": "./data",
  "max_inspect_body": 4194304,
  "max_request_bytes": 33554432,
  "upstream_insecure_skip_verify": false,
  "known_ai_hosts": ["api.openai.com", "chatgpt.com"],
  "rules": [
    {
      "id": "CUSTOM-001",
      "name": "内部项目代号",
      "level": "high",
      "direction": "both",
      "keywords": ["Project Falcon"],
      "regexps": ["FALCON-\\d{4}"],
      "explanation": "检测内部敏感项目代号外发"
    }
  ]
}
```

数据文件：

- `data/flows.jsonl`：识别到的 AI 流量（非 AI 流量不写入）。
- `data/flow-details.jsonl`：单条流量的完整明细（请求/响应头、脱敏后的正文、SSE 事件），只在打开控制台详情抽屉时按需读取。
- `data/alerts.jsonl`：告警。
- `data/ca/ca.pem`、`data/ca/ca-key.pem`：本地根证书与私钥。

隐私处理：

- `Authorization`、Cookie、API Key 等敏感头在详情中整体打码（仅保留 `Bearer` 之类认证方案）。
- 证据片段、请求/响应摘要统一脱敏（保留少量首尾字符）。
- 详情中的正文按 JSON 字符串值逐项脱敏后落盘，仍受 `max_inspect_body` 截断约束，控制台会提示“已截断”。
- `not_ai` 流量不落盘、不保留正文；即使命中规则也只记录 Flow 摘要。

## 5. 架构与可移植性

```
[应用/浏览器]
      │  显式代理 CONNECT / 透明重定向
      ▼
internal/ingress
  ├── explicit    显式代理：CONNECT + MITM
  └── transparent 透明模拟：固定目标 + SNI 证书
      │  ingress.Handler(ctx, ConnMeta, http.ResponseWriter, *http.Request)
      ▼
internal/pipeline
  ├── 读取/转发请求（流式回写、SSE 聚合）
  ├── internal/proto/openai  协议识别与解析
  ├── internal/detect        规则检测与脱敏
  └── internal/store         JSONL + 内存环形缓冲 + 实时订阅
      ▼
internal/api + internal/web  控制台 / REST / SSE
```

关键约束：`internal/pipeline` 不 import 任何 `internal/ingress/*` 子包。接入层只负责把字节流还原成 HTTP 请求，并填充 `model.ConnMeta`：

```go
type ConnMeta struct {
    Ingress     string
    Src         netip.AddrPort
    Dst         netip.AddrPort
    DstHost     string
    DstPort     uint16
    OriginalDst netip.AddrPort
    SNI         string
    ALPN        []string
    IsTLS       bool
}
```

因此迁移到网关设备时，只需新增一个 `ingress` 实现（WFP / iptables / nftables / TProxy），业务逻辑无需改动。透明模拟器的元数据一致性由 `TestIngressParity` 覆盖：

```powershell
go test ./internal/ingress -run TestIngressParity -v
```

手动体验透明模拟：

```powershell
# 终端 1
go run ./cmd/mock-openai

# 终端 2：8082 模拟“被重定向的透明流量”，固定目标 127.0.0.1:18443
go run ./cmd/lensgate -insecure-upstream -transparent-target 127.0.0.1:18443 -transparent-listen 127.0.0.1:8082

# 终端 3：连接 8082，但 Host/目标仍是 18443
curl.exe -k --connect-to 127.0.0.1:18443:127.0.0.1:8082 https://127.0.0.1:18443/v1/chat/completions `
  -H "Content-Type: application/json" `
  -H "Authorization: Bearer sk-demo" `
  -d '{\"model\":\"gpt-4o-mini\",\"messages\":[{\"role\":\"user\",\"content\":\"hello\"}]}'
```

## 6. 目录结构

```
cmd/
  lensgate/         网关入口：配置、CA、Store、管线、API、Ingress
  mock-openai/      本地 OpenAI 模拟服务（HTTP + 自签名 HTTPS）
  demo-client/      14 个演示场景客户端
internal/
  api/              REST / SSE / 内嵌控制台
  config/           JSON 配置
  detect/           规则引擎与脱敏
  ingress/          接入层抽象 + HTTP-over-conn 服务
  ingress/explicit/ 显式正向代理（MITM）
  ingress/transparent/ 透明代理模拟适配器
  mockopenai/       mock 服务实现
  model/            Flow / Alert / ConnMeta / Session
  pipeline/         请求转发、响应流式聚合、编排
  proto/openai/     协议识别、客户端指纹、请求/响应解析、SSE 解析
  store/            JSONL 持久化 + 内存环形缓冲 + 订阅
  tlsmitm/          本地 CA 与按 SNI 签发证书
```

## 7. 与规划文档的差异

| 规划 | 当前实现 | 原因 |
| --- | --- | --- |
| YAML 配置 | JSON | 避免第三方依赖，保持单二进制 |
| SQLite 存储 | JSONL + 内存环形缓冲 | 同上；接口已隔离，后续可替换 |
| WebSocket 推送 | SSE | 标准库直接支持，满足单向实时推送 |
| 下游 HTTP/2 MITM | 下游仅 HTTP/1.1，上游支持 h2 | 首版降低复杂度；h2 适配器可后续补充 |
| 操作系统级透明代理 | 透明模拟适配器 | PC Demo 不做 WFP/iptables 驱动；用于验证上层逻辑复用 |

## 8. 已知限制

- 为简化实现，请求体会先缓冲再转发；超大文件上传类请求不适合作为首批场景。
- 所有 HTTPS 都被 MITM；对不信任本地 CA 的客户端会表现为证书错误。
- 下游强制 HTTP/1.1（ALPN 只声明 `http/1.1`），现代客户端会自动降级。
- 告警目前只记录不阻断；阻断/重写可作为后续策略引擎能力。
- 客户端来源是**请求头指纹推断**：UA 可被改写，只能识别到 SDK/工具层，不能作为身份认证或合规审计的唯一依据。
- JSONL 不做轮转，长期运行需要按天切分或替换为 SQLite。

## 9. 测试

```powershell
gofmt -w .
go vet ./...
go test ./...
go build ./...
```

覆盖点：协议四级置信度、客户端指纹推断与优先级、Azure/OpenRouter 路径、SSE 增量聚合、工具调用聚合、五类检测规则、证据脱敏、存储环形缓冲与重启加载、显式/透明接入元数据一致性。
