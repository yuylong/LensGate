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

func TestSubscribeReceivesFlow(t *testing.T) {
	st, err := New("", 10, 10)
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
