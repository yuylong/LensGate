//go:build windows

package tlsmitm

import (
	"crypto/sha1"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
)

// EnsureTrusted 把根证书导入 Windows 证书存储。
// scope=user 写入 CurrentUser\Root，不需要管理员权限；
// scope=machine 写入 LocalMachine\Root，需要管理员权限。
// 导入通过系统自带的 certutil 完成，保持零第三方依赖。
func EnsureTrusted(certPath, scope string) TrustResult {
	res := TrustResult{Supported: true, Detail: "已加入当前用户受信任根证书"}
	if scope == "" {
		scope = "user"
	}
	abs, err := filepath.Abs(certPath)
	if err != nil {
		res.Detail = fmt.Sprintf("解析证书路径失败: %v", err)
		return res
	}
	thumb, err := thumbprint(abs)
	if err != nil {
		res.Detail = fmt.Sprintf("读取根证书失败: %v", err)
		return res
	}

	storeArgs := []string{"-user", "-store", "Root", thumb}
	addArgs := []string{"-user", "-addstore", "-f", "Root", abs}
	if scope == "machine" {
		storeArgs = []string{"-store", "Root", thumb}
		addArgs = []string{"-addstore", "-f", "Root", abs}
		res.Detail = "已加入本机受信任根证书"
	}

	// 已在存储中就不重复写入；certutil 输出为本地编码，只匹配 ASCII 指纹。
	if out, err := runCertutil(storeArgs...); err == nil && strings.Contains(strings.ToUpper(string(out)), thumb) {
		res.Trusted = true
		res.Detail += "（已存在）"
		return res
	}
	if out, err := runCertutil(addArgs...); err != nil {
		res.Detail = fmt.Sprintf("导入失败: %v %s", err, compact(string(out)))
		return res
	}
	res.Trusted = true
	res.Changed = true
	return res
}

func thumbprint(certPath string) (string, error) {
	data, err := os.ReadFile(certPath)
	if err != nil {
		return "", err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return "", errors.New("不是 PEM 格式")
	}
	if _, err := x509.ParseCertificate(block.Bytes); err != nil {
		return "", err
	}
	sum := sha1.Sum(block.Bytes)
	return strings.ToUpper(hex.EncodeToString(sum[:])), nil
}

func runCertutil(args ...string) ([]byte, error) {
	exe, err := exec.LookPath("certutil.exe")
	if err != nil {
		exe = filepath.Join(os.Getenv("SystemRoot"), "System32", "certutil.exe")
	}
	cmd := exec.Command(exe, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	return cmd.CombinedOutput()
}

func compact(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if len([]rune(s)) > 160 {
		return string([]rune(s)[:160]) + "..."
	}
	return s
}
