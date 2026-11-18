//go:build !windows

package tlsmitm

import "fmt"

// EnsureTrusted 在非 Windows 平台只给出提示，由用户按发行版方式手动信任。
func EnsureTrusted(certPath, scope string) TrustResult {
	return TrustResult{
		Supported: false,
		Detail:    fmt.Sprintf("当前系统不支持自动导入，请手动信任根证书 %s", certPath),
	}
}
