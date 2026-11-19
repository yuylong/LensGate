package store

import (
	"testing"
	"time"

	"lensgate/internal/model"
)

func TestStoreRingStatsAndReload(t *testing.T) {
	dir := t.TempDir()
	st, err := New(dir, 2, 2)
	if err != nil {
		t.Fatal(err)
	}

	mk := func(id, host, modelName string) model.Flow {
		return model.Flow{
			ID: id, Host: host, Model: modelName,
			ProtocolFamily: "openai", Confidence: "confirmed",
			StartedAt: time.Now(), EndedAt: time.Now(),
		}
	}
	st.AddFlow(mk("1", "a.example", "gpt-4o-mini"))
	st.AddFlow(mk("2", "b.example", "gpt-4o-mini"))
	st.AddFlow(mk("3", "c.example", "deepseek-chat"))
	st.AddAlerts([]model.Alert{
		{ID: "a1", FlowID: "3", RuleID: "PI-001", Level: "high"},
		{ID: "a2", FlowID: "3", RuleID: "DLP-001", Level: "high"},
	})

	flows := st.Flows(10)
	if len(flows) != 2 {
		t.Fatalf("ring size = %d, want 2", len(flows))
	}
	if flows[0].ID != "3" || flows[1].ID != "2" {
		t.Fatalf("unexpected order: %s,%s", flows[0].ID, flows[1].ID)
	}
	stats := st.Stats()
	if stats.TotalFlows != 3 || stats.TotalAlerts != 2 {
		t.Fatalf("stats = %+v", stats)
	}
	if stats.ByModel["gpt-4o-mini"] != 2 {
		t.Fatalf("by_model = %+v", stats.ByModel)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}

	reloaded, err := New(dir, 2, 2)
	if err != nil {
		t.Fatal(err)
	}
	defer reloaded.Close()
	if got := len(reloaded.Flows(10)); got != 2 {
		t.Fatalf("reloaded ring = %d, want 2", got)
	}
	if got := reloaded.Stats().TotalFlows; got != 3 {
		t.Fatalf("reloaded total = %d, want 3", got)
	}
	if got := len(reloaded.Alerts(10)); got != 2 {
		t.Fatalf("reloaded alerts = %d, want 2", got)
	}
}

func newDetail(id, body string) model.FlowDetail {
	return model.FlowDetail{
		Flow:    model.Flow{ID: id, Host: "api.openai.com"},
		Request: model.RequestDetail{Method: "POST", Body: body},
	}
}

func TestStoreFlowDetailPersistsAcrossReload(t *testing.T) {
	dir := t.TempDir()
	st, err := New(dir, 4, 4)
	if err != nil {
		t.Fatal(err)
	}
	st.AddFlowDetail(newDetail("f1", "body-1"))
	st.AddFlowDetail(newDetail("f2", "body-2"))

	got, ok := st.FlowDetail("f1")
	if !ok || got.Request.Body != "body-1" || got.Flow.Host != "api.openai.com" {
		t.Fatalf("detail = %+v, ok = %v", got, ok)
	}
	if _, ok := st.FlowDetail("missing"); ok {
		t.Fatal("不存在的详情不应返回")
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}

	reloaded, err := New(dir, 4, 4)
	if err != nil {
		t.Fatal(err)
	}
	defer reloaded.Close()

	if got, ok := reloaded.FlowDetail("f2"); !ok || got.Request.Body != "body-2" {
		t.Fatalf("重启后读取详情失败：%+v ok=%v", got, ok)
	}
	// 重启后继续追加，新老详情都应可读。
	reloaded.AddFlowDetail(newDetail("f3", "body-3"))
	if got, ok := reloaded.FlowDetail("f3"); !ok || got.Request.Body != "body-3" {
		t.Fatalf("追加后读取新详情失败：%+v ok=%v", got, ok)
	}
	if got, ok := reloaded.FlowDetail("f1"); !ok || got.Request.Body != "body-1" {
		t.Fatalf("追加后读取旧详情失败：%+v ok=%v", got, ok)
	}
}

func TestStoreFlowDetailEvictsWithFlowCap(t *testing.T) {
	st, err := New(t.TempDir(), 2, 2)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	st.AddFlowDetail(newDetail("a", "1"))
	st.AddFlowDetail(newDetail("b", "2"))
	st.AddFlowDetail(newDetail("c", "3"))

	if _, ok := st.FlowDetail("a"); ok {
		t.Fatal("超出 flowCap 的最旧详情应被淘汰")
	}
	if _, ok := st.FlowDetail("c"); !ok {
		t.Fatal("最新详情应可读")
	}
}

func TestStoreFlowDetailInMemoryWhenNoDir(t *testing.T) {
	st, err := New("", 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	st.AddFlowDetail(newDetail("a", "1"))
	if got, ok := st.FlowDetail("a"); !ok || got.Request.Body != "1" {
		t.Fatalf("无数据目录时应保留内存详情：%+v ok=%v", got, ok)
	}
	st.AddFlowDetail(newDetail("b", "2"))
	if _, ok := st.FlowDetail("a"); ok {
		t.Fatal("内存模式同样按 flowCap 淘汰")
	}
	if _, ok := st.FlowDetail("b"); !ok {
		t.Fatal("最新内存详情应可读")
	}
}

func TestSubscribeReceivesFlow(t *testing.T) {	st, err := New("", 10, 10)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	ch, cancel := st.Subscribe()
	defer cancel()

	st.AddFlow(model.Flow{ID: "x", Host: "h", Confidence: "confirmed"})
	select {
	case ev := <-ch:
		if ev.Type != "flow" || ev.Flow == nil || ev.Flow.ID != "x" {
			t.Fatalf("unexpected event: %+v", ev)
		}
	case <-time.After(time.Second):
		t.Fatal("no event received")
	}
}
