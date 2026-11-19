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

	// ClientKind 是基于请求头的客户端指纹推断（Agent/SDK/浏览器/curl 等）。
	// 仅作参考，UA 可伪造，不代表强认证。
	ClientKind   string
	ClientDetail string
	ClientReason string
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
	ClientKind      string    `json:"client_kind"`
	ClientDetail    string    `json:"client_detail"`
	ClientReason    string    `json:"client_reason"`
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

// Header 是脱敏后的单个请求/响应头；用切片而不是 map 保证展示顺序稳定。
type Header struct {
	Name   string   `json:"name"`
	Values []string `json:"values"`
}

type ToolCallDetail struct {
	ID        string `json:"id,omitempty"`
	Name      string `json:"name"`
	Arguments string `json:"arguments"`
}

type MessageDetail struct {
	Role      string           `json:"role"`
	Content   string           `json:"content"`
	ToolCalls []ToolCallDetail `json:"tool_calls,omitempty"`
}

type ToolDetail struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

// RequestDetail 是请求侧的全部可展示信息，正文已脱敏并可能被截断。
type RequestDetail struct {
	Method        string          `json:"method"`
	Host          string          `json:"host"`
	Path          string          `json:"path"`
	Query         string          `json:"query"`
	Headers       []Header        `json:"headers"`
	ContentType   string          `json:"content_type"`
	Body          string          `json:"body"`
	BodyTruncated bool            `json:"body_truncated"`
	Model         string          `json:"model"`
	Stream        bool            `json:"stream"`
	Messages      []MessageDetail `json:"messages"`
	Instructions  string          `json:"instructions"`
	Input         string          `json:"input"`
	Tools         []ToolDetail    `json:"tools"`
}

type SSEDetail struct {
	Event string `json:"event"`
	Data  string `json:"data"`
}

// ResponseDetail 是响应侧的全部可展示信息，SSE 流同时保留事件列表与聚合结果。
type ResponseDetail struct {
	Status        int              `json:"status"`
	Headers       []Header         `json:"headers"`
	ContentType   string           `json:"content_type"`
	Body          string           `json:"body"`
	BodyTruncated bool             `json:"body_truncated"`
	SSE           []SSEDetail      `json:"sse"`
	Text          string           `json:"text"`
	FinishReason  string           `json:"finish_reason"`
	ToolCalls     []ToolCallDetail `json:"tool_calls"`
	Object        string           `json:"object"`
	Chunks        int              `json:"chunks"`
	Completed     bool             `json:"completed"`
	Error         string           `json:"error,omitempty"`
}

// FlowDetail 是单条流量的完整明细，只在 /api/flows/{id} 按需返回。
// 列表接口 /api/flows 保持轻量，不含正文。
type FlowDetail struct {
	Flow     Flow           `json:"flow"`
	ALPN     []string       `json:"alpn"`
	IsTLS    bool           `json:"is_tls"`
	Request  RequestDetail  `json:"request"`
	Response ResponseDetail `json:"response"`
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
	ByClient     map[string]int `json:"by_client"`
	ByRule       map[string]int `json:"by_rule"`
}
