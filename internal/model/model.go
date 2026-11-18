package model

import (
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"time"
)

// ConnMeta 是接入层与核心管线之间唯一的传输上下文。
// 显式代理、透明代理、TUN/WFP 的差异都应在这里被归一化。
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

// Conn 把原始连接和归一化元数据绑定在一起，仅接入层使用。
type Conn struct {
	net.Conn
	Meta ConnMeta
}

func (m ConnMeta) SrcString() string {
	if !m.Src.IsValid() {
		return ""
	}
	return m.Src.String()
}

func (m ConnMeta) DstString() string {
	if m.DstHost != "" {
		if m.DstPort > 0 {
			return net.JoinHostPort(m.DstHost, strconv.Itoa(int(m.DstPort)))
		}
		return m.DstHost
	}
	if !m.Dst.IsValid() {
		return ""
	}
	return m.Dst.String()
}

func (m ConnMeta) OriginalDstString() string {
	if !m.OriginalDst.IsValid() {
		return ""
	}
	return m.OriginalDst.String()
}

type RequestInfo struct {
	Method        string
	Host          string
	Path          string
	Query         string
	Headers       http.Header
	ContentType   string
	Body          []byte
	BodyTruncated bool
}

type ResponseInfo struct {
	Status        int
	Headers       http.Header
	ContentType   string
	Body          []byte
	BodyTruncated bool
	SSE           []SSEEvent
	Chunks        int
	Completed     bool
	Error         string
}

type SSEEvent struct {
	Event string
	Data  string
}

type Usage struct {
	Input  int `json:"input"`
	Output int `json:"output"`
	Total  int `json:"total"`
}

type Finding struct {
	RuleID      string `json:"rule_id"`
	RuleName    string `json:"rule_name"`
	Level       string `json:"level"`
	Direction   string `json:"direction"`
	FieldPath   string `json:"field_path"`
	Evidence    string `json:"evidence"`
	Explanation string `json:"explanation"`
}

type Classification struct {
	ProtocolFamily string
	APIVariant     string
	Confidence     string
	Evidence       []string
	Reason         string
}

// Session 是一次请求在核心管线中的完整状态，不直接对外输出。
type Session struct {
	ID              string
	Meta            ConnMeta
	Request         RequestInfo
	Response        ResponseInfo
	Classification  Classification
	Model           string
	Stream          bool
	Usage           *Usage
	Findings        []Finding
	RequestSummary  string
	ResponseSummary string
	ParseStatus     []string
	StartedAt       time.Time
	EndedAt         time.Time
}

// Flow 是日志、API 与控制台展示的稳定结构。
type Flow struct {
	ID              string    `json:"id"`
	Ingress         string    `json:"ingress"`
	Src             string    `json:"src"`
	Dst             string    `json:"dst"`
	OriginalDst     string    `json:"original_dst"`
	SNI             string    `json:"sni"`
	Method          string    `json:"method"`
	Host            string    `json:"host"`
	Path            string    `json:"path"`
	Status          int       `json:"status"`
	ProtocolFamily  string    `json:"protocol_family"`
	APIVariant      string    `json:"api_variant"`
	Confidence      string    `json:"confidence"`
	Evidence        []string  `json:"evidence"`
	Model           string    `json:"model"`
	Stream          bool      `json:"stream"`
	Usage           *Usage    `json:"usage,omitempty"`
	RequestSummary  string    `json:"request_summary"`
	ResponseSummary string    `json:"response_summary"`
	ParseStatus     []string  `json:"parse_status"`
	Findings        []Finding `json:"findings"`
	StartedAt       time.Time `json:"started_at"`
	EndedAt         time.Time `json:"ended_at"`
	DurationMS      int64     `json:"duration_ms"`
}

type Alert struct {
	ID          string    `json:"id"`
	FlowID      string    `json:"flow_id"`
	RuleID      string    `json:"rule_id"`
	RuleName    string    `json:"rule_name"`
	Level       string    `json:"level"`
	Direction   string    `json:"direction"`
	FieldPath   string    `json:"field_path"`
	Evidence    string    `json:"evidence"`
	Explanation string    `json:"explanation"`
	Host        string    `json:"host"`
	Path        string    `json:"path"`
	CreatedAt   time.Time `json:"created_at"`
}

type Stats struct {
	TotalFlows   int            `json:"total_flows"`
	TotalAlerts  int            `json:"total_alerts"`
	ByProtocol   map[string]int `json:"by_protocol"`
	ByConfidence map[string]int `json:"by_confidence"`
	ByModel      map[string]int `json:"by_model"`
	ByRule       map[string]int `json:"by_rule"`
}
