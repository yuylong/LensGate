package detect

import (
	"regexp"

	"lensgate/internal/config"
)

// 内置规则 ID，告警和测试都依赖这些稳定标识。
const (
	RuleDLPCredential = "DLP-001"
	RuleDLPPII        = "DLP-002"
	RulePromptInject  = "PI-001"
	RuleDangerTool    = "TOOL-001"
	RuleShadowAI      = "DISC-001"
)

type RuleInfo struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Level       string `json:"level"`
	Direction   string `json:"direction"`
	Explanation string `json:"explanation"`
}

var builtinRules = []RuleInfo{
	{
		ID:          RuleDLPCredential,
		Name:        "凭据泄露",
		Level:       "high",
		Direction:   "both",
		Explanation: "请求或响应中出现 API Key、访问令牌、私钥或明文口令。",
	},
	{
		ID:          RuleDLPPII,
		Name:        "个人敏感信息",
		Level:       "medium",
		Direction:   "both",
		Explanation: "请求或响应中出现手机号、身份证号、邮箱、银行卡号等个人信息。",
	},
	{
		ID:          RulePromptInject,
		Name:        "提示词注入/越狱",
		Level:       "high",
		Direction:   "request",
		Explanation: "用户输入试图覆盖系统指令、泄露提示词或进入无限制模式。",
	},
	{
		ID:          RuleDangerTool,
		Name:        "危险工具调用",
		Level:       "high",
		Direction:   "both",
		Explanation: "模型请求调用命令执行、文件读写、数据库或外发类高风险工具。",
	},
	{
		ID:          RuleShadowAI,
		Name:        "未知域名 AI 调用",
		Level:       "medium",
		Direction:   "request",
		Explanation: "在未登记域名上识别到 OpenAI 兼容协议，可能是影子 AI 或自建代理。",
	},
}

type compiledExtra struct {
	info  RuleInfo
	words []string
	res   []*regexp.Regexp
}

func compileExtra(rules []config.RuleConfig) []compiledExtra {
	out := make([]compiledExtra, 0, len(rules))
	for _, r := range rules {
		if r.ID == "" || r.Name == "" {
			continue
		}
		ce := compiledExtra{
			info: RuleInfo{
				ID:          r.ID,
				Name:        r.Name,
				Level:       orDefault(r.Level, "medium"),
				Direction:   orDefault(r.Direction, "both"),
				Explanation: orDefault(r.Explanation, "自定义敏感内容规则"),
			},
			words: r.Keywords,
		}
		for _, expr := range r.Regexps {
			if re, err := regexp.Compile(expr); err == nil {
				ce.res = append(ce.res, re)
			}
		}
		out = append(out, ce)
	}
	return out
}

func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}
