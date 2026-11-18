package config

import (
	"encoding/json"
	"os"
	"strings"
)

type RuleConfig struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Level       string   `json:"level"`
	Direction   string   `json:"direction"`
	Keywords    []string `json:"keywords"`
	Regexps     []string `json:"regexps"`
	Explanation string   `json:"explanation"`
}

type Config struct {
	ProxyAddr                  string       `json:"proxy_addr"`
	APIAddr                    string       `json:"api_addr"`
	DataDir                    string       `json:"data_dir"`
	MaxInspectBody             int          `json:"max_inspect_body"`
	MaxRequestBytes            int64        `json:"max_request_bytes"`
	UpstreamInsecureSkipVerify bool         `json:"upstream_insecure_skip_verify"`
	KnownAIHosts               []string     `json:"known_ai_hosts"`
	Rules                      []RuleConfig `json:"rules,omitempty"`
}

func Default() Config {
	return Config{
		ProxyAddr:       "127.0.0.1:8080",
		APIAddr:         "127.0.0.1:8081",
		DataDir:         "./data",
		MaxInspectBody:  4 << 20,
		MaxRequestBytes: 32 << 20,
		KnownAIHosts: []string{
			"api.openai.com",
			"chatgpt.com",
			"openai.azure.com",
			"api.anthropic.com",
			"generativelanguage.googleapis.com",
			"api.deepseek.com",
		},
	}
}

// Load 读取 JSON 配置；文件不存在时返回默认配置。
// MVP 使用 JSON 而不是 YAML，避免引入额外依赖。
func Load(path string) (Config, error) {
	cfg := Default()
	if path == "" {
		return cfg, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil
		}
		return cfg, err
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return cfg, err
	}
	if cfg.MaxInspectBody <= 0 {
		cfg.MaxInspectBody = 4 << 20
	}
	if cfg.MaxRequestBytes <= 0 {
		cfg.MaxRequestBytes = 32 << 20
	}
	return cfg, nil
}

func (c Config) IsKnownHost(host string) bool {
	h := strings.ToLower(strings.TrimSpace(host))
	if i := strings.LastIndex(h, ":"); i > 0 {
		h = h[:i]
	}
	for _, known := range c.KnownAIHosts {
		k := strings.ToLower(strings.TrimSpace(known))
		if k == "" {
			continue
		}
		if h == k || (strings.HasPrefix(k, ".") && strings.HasSuffix(h, k)) {
			return true
		}
		if strings.HasPrefix(k, "*.") && strings.HasSuffix(h, k[1:]) {
			return true
		}
	}
	return false
}
