package detect

import (
	"fmt"
	"regexp"
	"strings"
	"unicode/utf8"

	"lensgate/internal/config"
	"lensgate/internal/model"
)

type TextSpan struct {
	Field string
	Value string
}

type ToolSpan struct {
	Field     string
	Name      string
	Arguments string
}

// Input 是检测器需要的全部可读内容，由管线从解析结果中抽取。
type Input struct {
	RequestTexts  []TextSpan
	RequestTools  []ToolSpan
	ResponseTexts []TextSpan
	ResponseCalls []ToolSpan
	Host          string
	Confidence    string
	KnownHost     bool
}

type Detector struct {
	extra []compiledExtra
}

func New(extraRules []config.RuleConfig) *Detector {
	return &Detector{extra: compileExtra(extraRules)}
}

func (d *Detector) Rules() []RuleInfo {
	out := make([]RuleInfo, 0, len(builtinRules)+len(d.extra))
	out = append(out, builtinRules...)
	for _, e := range d.extra {
		out = append(out, e.info)
	}
	return out
}

var credentialPatterns = []struct {
	name string
	re   *regexp.Regexp
}{
	{"openai_key", regexp.MustCompile(`sk-[A-Za-z0-9_\-]{20,}`)},
	{"anthropic_key", regexp.MustCompile(`sk-ant-[A-Za-z0-9_\-]{20,}`)},
	{"aws_access_key", regexp.MustCompile(`AKIA[0-9A-Z]{16}`)},
	{"github_token", regexp.MustCompile(`gh[pousr]_[A-Za-z0-9]{20,}`)},
	{"private_key", regexp.MustCompile(`-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----`)},
	{"bearer_token", regexp.MustCompile(`(?i)bearer\s+[A-Za-z0-9\-._~+/]{20,}`)},
	{"secret_assign", regexp.MustCompile(`(?i)(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?token)\s*[:=]\s*["']?[^\s"',}]{6,}`)},
}

var piiPatterns = []struct {
	name string
	re   *regexp.Regexp
}{
	{"email", regexp.MustCompile(`[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}`)},
	{"cn_mobile", regexp.MustCompile(`(?:\+?86[- ]?)?1[3-9]\d{9}`)},
	{"cn_idcard", regexp.MustCompile(`[1-9]\d{5}(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx]`)},
	{"bank_card", regexp.MustCompile(`\b(?:\d[ -]?){15,18}\d\b`)},
}

var injectionPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)ignore\s+(all\s+)?(the\s+)?(previous|prior|above)\s+(instructions?|prompts?|rules?)`),
	regexp.MustCompile(`(?i)disregard\s+(all\s+)?(the\s+)?(previous|prior|above)`),
	regexp.MustCompile(`(?i)(reveal|show|print)\s+(your\s+)?(system\s+)?(prompt|instructions?)`),
	regexp.MustCompile(`(?i)(jailbreak|do\s+anything\s+now|dan\s+mode|developer\s+mode|god\s+mode)`),
	regexp.MustCompile(`忽略(之前|以上|前面|先前|全部)的?(所有)?(指令|提示|规则|要求)`),
	regexp.MustCompile(`(无视|绕过|突破)(之前|以上|安全|内容|系统)?(的)?(限制|规则|指令|提示词)`),
	regexp.MustCompile(`(输出|打印|告诉我|展示)(你的)?(系统)?(提示词|system\s*prompt|初始指令)`),
	regexp.MustCompile(`(你现在是|从现在起你是|扮演)(一个)?(不受限制|没有限制|越狱)`),
	regexp.MustCompile(`开发者模式|越狱模式`),
}

var toolNamePattern = regexp.MustCompile(`(?i)(^|[_\-.])(exec|execute|shell|bash|sh|cmd|powershell|eval|system|popen|spawn|subprocess|terminal|delete|remove|unlink|drop|truncate|write|writefile|write_file|readfile|read_file|upload|download|curl|wget|http_request|sql|query|send_email|sendmail|smtp|ssh|scp|browser|chrome)([_\-.]|$)`)

var toolArgPattern = regexp.MustCompile(`(?i)(rm\s+-rf|curl\s+https?://|wget\s+https?://|powershell(\.exe)?\s|cmd(\.exe)?\s+/c|/bin/(ba)?sh|base64\s+-d|chmod\s+777|drop\s+table|delete\s+from|truncate\s+table|nc\s+-[el])`)

type collector struct {
	findings []model.Finding
	seen     map[string]bool
	perRule  map[string]int
}

func (c *collector) add(f model.Finding) {
	const maxPerRule = 5
	key := f.RuleID + "|" + f.FieldPath + "|" + f.Evidence
	if c.seen[key] {
		return
	}
	if c.perRule[f.RuleID] >= maxPerRule {
		return
	}
	c.seen[key] = true
	c.perRule[f.RuleID]++
	c.findings = append(c.findings, f)
}

func (d *Detector) Inspect(in Input) []model.Finding {
	c := &collector{seen: map[string]bool{}, perRule: map[string]int{}}

	for _, span := range in.RequestTexts {
		d.scanSecrets(c, "request", span)
		d.scanPII(c, "request", span)
		d.scanInjection(c, span)
	}
	for _, span := range in.ResponseTexts {
		d.scanSecrets(c, "response", span)
		d.scanPII(c, "response", span)
	}
	for _, tool := range in.RequestTools {
		d.scanTool(c, "request", tool)
	}
	for _, call := range in.ResponseCalls {
		d.scanTool(c, "response", call)
	}
	if in.Confidence == "confirmed" || in.Confidence == "compatible" {
		if !in.KnownHost {
			c.add(model.Finding{
				RuleID:      RuleShadowAI,
				RuleName:    "未知域名 AI 调用",
				Level:       "medium",
				Direction:   "request",
				FieldPath:   "flow.host",
				Evidence:    in.Host,
				Explanation: "该域名不在已知 AI 服务清单中，但识别到 OpenAI 兼容协议，可能是影子 AI、自建代理或中转服务。",
			})
		}
	}

	d.scanExtra(c, in)
	return c.findings
}

func (d *Detector) scanSecrets(c *collector, direction string, span TextSpan) {
	for _, p := range credentialPatterns {
		loc := p.re.FindStringIndex(span.Value)
		if loc == nil {
			continue
		}
		hit := span.Value[loc[0]:loc[1]]
		c.add(model.Finding{
			RuleID:      RuleDLPCredential,
			RuleName:    "凭据泄露",
			Level:       "high",
			Direction:   direction,
			FieldPath:   span.Field,
			Evidence:    mask(hit),
			Explanation: fmt.Sprintf("检测到疑似 %s，已脱敏展示。", p.name),
		})
	}
}

func (d *Detector) scanPII(c *collector, direction string, span TextSpan) {
	for _, p := range piiPatterns {
		loc := p.re.FindStringIndex(span.Value)
		if loc == nil {
			continue
		}
		hit := span.Value[loc[0]:loc[1]]
		c.add(model.Finding{
			RuleID:      RuleDLPPII,
			RuleName:    "个人敏感信息",
			Level:       "medium",
			Direction:   direction,
			FieldPath:   span.Field,
			Evidence:    mask(hit),
			Explanation: fmt.Sprintf("检测到疑似 %s，已脱敏展示。", p.name),
		})
	}
}

func (d *Detector) scanInjection(c *collector, span TextSpan) {
	for _, re := range injectionPatterns {
		loc := re.FindStringIndex(span.Value)
		if loc == nil {
			continue
		}
		c.add(model.Finding{
			RuleID:      RulePromptInject,
			RuleName:    "提示词注入/越狱",
			Level:       "high",
			Direction:   "request",
			FieldPath:   span.Field,
			Evidence:    snippet(span.Value[loc[0]:loc[1]], 80),
			Explanation: "输入包含覆盖系统指令、套取提示词或进入越狱模式的表达。",
		})
		return
	}
}

func (d *Detector) scanTool(c *collector, direction string, tool ToolSpan) {
	if tool.Name != "" && toolNamePattern.MatchString(tool.Name) {
		c.add(model.Finding{
			RuleID:      RuleDangerTool,
			RuleName:    "危险工具调用",
			Level:       "high",
			Direction:   direction,
			FieldPath:   tool.Field + ".name",
			Evidence:    snippet(tool.Name, 60),
			Explanation: "工具名称指向命令执行、文件操作、数据库或外发能力。",
		})
		return
	}
	if tool.Arguments != "" && toolArgPattern.MatchString(tool.Arguments) {
		loc := toolArgPattern.FindStringIndex(tool.Arguments)
		hit := tool.Arguments[loc[0]:loc[1]]
		c.add(model.Finding{
			RuleID:      RuleDangerTool,
			RuleName:    "危险工具调用",
			Level:       "high",
			Direction:   direction,
			FieldPath:   tool.Field + ".arguments",
			Evidence:    snippet(hit, 80),
			Explanation: "工具参数包含破坏性命令、外联下载或数据库删除语句。",
		})
	}
}

func (d *Detector) scanExtra(c *collector, in Input) {
	for _, e := range d.extra {
		if e.info.Direction == "request" || e.info.Direction == "both" {
			d.scanExtraSpans(c, e, "request", in.RequestTexts)
		}
		if e.info.Direction == "response" || e.info.Direction == "both" {
			d.scanExtraSpans(c, e, "response", in.ResponseTexts)
		}
	}
}

func (d *Detector) scanExtraSpans(c *collector, e compiledExtra, direction string, spans []TextSpan) {
	for _, span := range spans {
		hit := ""
		for _, w := range e.words {
			if w != "" && strings.Contains(span.Value, w) {
				hit = w
				break
			}
		}
		if hit == "" {
			for _, re := range e.res {
				if loc := re.FindStringIndex(span.Value); loc != nil {
					hit = span.Value[loc[0]:loc[1]]
					break
				}
			}
		}
		if hit == "" {
			continue
		}
		c.add(model.Finding{
			RuleID:      e.info.ID,
			RuleName:    e.info.Name,
			Level:       e.info.Level,
			Direction:   direction,
			FieldPath:   span.Field,
			Evidence:    mask(hit),
			Explanation: e.info.Explanation,
		})
	}
}

// mask 保留少量首尾字符，既能让用户判断类型，又避免完整泄露。
func mask(s string) string {
	r := []rune(strings.TrimSpace(s))
	switch {
	case len(r) == 0:
		return ""
	case len(r) <= 6:
		return "***"
	case len(r) <= 12:
		return string(r[:2]) + "***" + string(r[len(r)-2:])
	default:
		return string(r[:4]) + "***" + string(r[len(r)-4:])
	}
}

func snippet(s string, max int) string {
	s = strings.TrimSpace(s)
	if utf8.RuneCountInString(s) <= max {
		return s
	}
	r := []rune(s)
	return string(r[:max]) + "..."
}

// Redact 在写入日志摘要前替换凭据与个人信息，避免正文片段二次泄露。
func Redact(s string) string {
	if s == "" {
		return ""
	}
	for _, p := range credentialPatterns {
		s = p.re.ReplaceAllStringFunc(s, mask)
	}
	for _, p := range piiPatterns {
		s = p.re.ReplaceAllStringFunc(s, mask)
	}
	return s
}
