# Lensgate 项目指南（AGENTS.md）

AI 安全网关 Demo：通过显式正向代理截获 HTTP/HTTPS 流量，按"协议指纹"识别 OpenAI 兼容调用，解析请求/响应与 SSE 流，命中检测规则后产生告警和日志。详见 [README.md](README.md)。

## 构建与测试

要求 Go 1.21+，**零第三方依赖**（仅标准库），不要引入外部包。

```powershell
go build ./...        # 编译
go vet ./...          # 静态检查，提交前必须通过
go test ./...         # 单元测试
```

本地运行（两个终端）：

```powershell
go run ./cmd/mock-openai                    # mock OpenAI（HTTP 18080 / HTTPS 18443）
go run ./cmd/lensgate -insecure-upstream    # 网关（代理 8080 / 控制台 8081）
go run ./cmd/demo-client -scenario all      # 演示场景
```

控制台：`http://127.0.0.1:8081`。`-insecure-upstream` 仅用于本地自签名 mock，接入真实服务时必须去掉。

## 架构

```
cmd/
  lensgate/        # 网关主程序入口
  mock-openai/     # 本地 mock OpenAI 服务
  demo-client/     # 演示场景客户端
internal/
  ingress/         # 接入层适配器：explicit（显式代理）/ transparent（透明代理）
  pipeline/        # 核心管线
  proto/openai/    # 协议识别：classifier（四级置信度）、parser、sse（流式聚合）
  detect/          # 检测规则（DLP-001/002、PI-001、TOOL-001、DISC-001）
  api/             # 控制台与 API 服务（SSE 实时推送）
  store/           # 告警与流量存储
  tlsmitm/         # CA 签发与证书信任（trust_windows.go 等含平台构建标签）
  config/          # 配置加载
  model/           # 数据模型
  mockopenai/      # mock 服务实现
```

核心设计：**可移植接入层**——`pipeline` 只依赖 HTTP 请求/响应，显式代理与透明代理适配器共用同一个 `ingress.Handler`。新增接入方式时实现 `ingress.Handler` 即可，不要让核心管线感知代理细节。

## 关键约定

- **协议识别而非域名识别**：按路径形态 + JSON Schema + 认证头/SDK 头 + 响应 `object`/SSE 事件判断，输出四级置信度 `confirmed` / `compatible` / `suspected` / `not_ai`。修改 classifier 时保持这四级语义，`not_ai` 流量直接放行且**不落盘正文**。
- **支持多种 OpenAI 变体**：`/v1/chat/completions`、`/v1/responses`、`/v1/embeddings`、Azure、OpenRouter、vLLM/Ollama/LiteLLM 等兼容服务。新增变体时同步更新 classifier 与 parser 的测试。
- **检测规则**在 `internal/detect/rules.go`，规则 ID（如 `DLP-001`）是控制台展示与日志检索的稳定标识，不要改动已有 ID。
- **平台相关代码**：证书信任逻辑按平台拆分（`trust_windows.go`、`trust_other.go`），使用构建标签，修改时注意同步所有平台文件。
- **证书安全**：根私钥在 `data/ca/ca-key.pem`，仅限本机 Demo，任何情况下不要提交到仓库或对外分发。
- 提交前运行 `go vet ./...` 和 `go test ./...`，新增功能需附带表驱动测试（参考 `internal/detect/detect_test.go` 的风格）。
