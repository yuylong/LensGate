package tlsmitm

// TrustResult 描述根证书导入系统信任库的结果。
type TrustResult struct {
	Supported bool   // 当前系统是否支持自动导入
	Trusted   bool   // 证书现在是否已受信任
	Changed   bool   // 本次启动是否真正写入了存储
	Detail    string // 给日志看的一句话说明
}
