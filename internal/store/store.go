package store

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"

	"lensgate/internal/model"
)

const (
	defaultFlowCap  = 2000
	defaultAlertCap = 1000
	subBuffer       = 64
)

// Event 是推送给控制台（SSE）的实时事件。
type Event struct {
	Type  string       `json:"type"`
	Flow  *model.Flow  `json:"flow,omitempty"`
	Alert *model.Alert `json:"alert,omitempty"`
}

// Store 使用内存环形缓冲提供查询，同时把全量记录追加到 JSONL。
// MVP 不引入 SQLite，保持单二进制零依赖；数据量大时可替换为 SQLite 实现。
type Store struct {
	mu sync.Mutex

	flows      []model.Flow
	alerts     []model.Alert
	flowCap    int
	alertCap   int
	stats      model.Stats
	flowsFile  *os.File
	alertsFile *os.File

	subs   map[int]chan Event
	nextID int
}

func New(dir string, flowCap, alertCap int) (*Store, error) {
	if flowCap <= 0 {
		flowCap = defaultFlowCap
	}
	if alertCap <= 0 {
		alertCap = defaultAlertCap
	}
	s := &Store{
		flowCap:  flowCap,
		alertCap: alertCap,
		subs:     map[int]chan Event{},
		stats: model.Stats{
			ByProtocol:   map[string]int{},
			ByConfidence: map[string]int{},
			ByModel:      map[string]int{},
			ByClient:     map[string]int{},
			ByRule:       map[string]int{},
		},
	}
	if dir == "" {
		return s, nil
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	flowPath := filepath.Join(dir, "flows.jsonl")
	alertPath := filepath.Join(dir, "alerts.jsonl")

	s.loadFlows(flowPath)
	s.loadAlerts(alertPath)

	f, err := os.OpenFile(flowPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return nil, err
	}
	a, err := os.OpenFile(alertPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		f.Close()
		return nil, err
	}
	s.flowsFile = f
	s.alertsFile = a
	return s, nil
}

func (s *Store) loadFlows(path string) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 4*1024*1024)
	for sc.Scan() {
		var fl model.Flow
		if json.Unmarshal(sc.Bytes(), &fl) != nil {
			continue
		}
		s.flows = append(s.flows, fl)
		s.flowStats(fl)
		if len(s.flows) > s.flowCap {
			s.flows = s.flows[len(s.flows)-s.flowCap:]
		}
	}
}

func (s *Store) loadAlerts(path string) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 4*1024*1024)
	for sc.Scan() {
		var al model.Alert
		if json.Unmarshal(sc.Bytes(), &al) != nil {
			continue
		}
		s.alerts = append(s.alerts, al)
		s.stats.TotalAlerts++
		s.stats.ByRule[al.RuleID]++
		if len(s.alerts) > s.alertCap {
			s.alerts = s.alerts[len(s.alerts)-s.alertCap:]
		}
	}
}

func (s *Store) AddFlow(f model.Flow) {
	data, _ := json.Marshal(f)
	s.mu.Lock()
	if s.flowsFile != nil {
		if len(data) > 0 {
			s.flowsFile.Write(append(data, '\n'))
		}
	}
	s.flows = append(s.flows, f)
	if len(s.flows) > s.flowCap {
		s.flows = s.flows[len(s.flows)-s.flowCap:]
	}
	s.flowStats(f)
	subs := s.snapshotSubs()
	s.mu.Unlock()

	ev := Event{Type: "flow", Flow: &f}
	for _, ch := range subs {
		select {
		case ch <- ev:
		default:
		}
	}
}

func (s *Store) AddAlerts(alerts []model.Alert) {
	if len(alerts) == 0 {
		return
	}
	data := make([][]byte, 0, len(alerts))
	s.mu.Lock()
	for _, al := range alerts {
		b, _ := json.Marshal(al)
		data = append(data, b)
		s.alerts = append(s.alerts, al)
		s.stats.TotalAlerts++
		s.stats.ByRule[al.RuleID]++
	}
	if len(s.alerts) > s.alertCap {
		s.alerts = s.alerts[len(s.alerts)-s.alertCap:]
	}
	if s.alertsFile != nil {
		for _, b := range data {
			s.alertsFile.Write(append(b, '\n'))
		}
	}
	subs := s.snapshotSubs()
	s.mu.Unlock()

	for i := range alerts {
		al := alerts[i]
		ev := Event{Type: "alert", Alert: &al}
		for _, ch := range subs {
			select {
			case ch <- ev:
			default:
			}
		}
	}
}

func (s *Store) flowStats(f model.Flow) {
	s.stats.TotalFlows++
	if f.ProtocolFamily != "" {
		s.stats.ByProtocol[f.ProtocolFamily]++
	}
	if f.Confidence != "" {
		s.stats.ByConfidence[f.Confidence]++
	}
	if f.Model != "" {
		s.stats.ByModel[f.Model]++
	}
	if f.ClientKind != "" {
		if s.stats.ByClient == nil {
			s.stats.ByClient = map[string]int{}
		}
		s.stats.ByClient[f.ClientKind]++
	}
}

func (s *Store) Flows(limit int) []model.Flow {
	s.mu.Lock()
	defer s.mu.Unlock()
	if limit <= 0 || limit > len(s.flows) {
		limit = len(s.flows)
	}
	out := make([]model.Flow, 0, limit)
	for i := len(s.flows) - 1; i >= 0 && len(out) < limit; i-- {
		out = append(out, s.flows[i])
	}
	return out
}

// ReclassifyClients 用外部校正函数重新计算已加载历史流量的派生字段。
// 只改内存中的 Flow 与 ByClient 统计，不回写 JSONL：启动时调用即可让旧记录
// 用上新的指纹规则，避免历史数据长期停留在过期结论上。
func (s *Store) ReclassifyClients(fn func(f *model.Flow)) {
	if fn == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	byClient := make(map[string]int, len(s.flows))
	for i := range s.flows {
		fn(&s.flows[i])
		if k := s.flows[i].ClientKind; k != "" {
			byClient[k]++
		}
	}
	s.stats.ByClient = byClient
}

func (s *Store) Alerts(limit int) []model.Alert {
	s.mu.Lock()
	defer s.mu.Unlock()
	if limit <= 0 || limit > len(s.alerts) {
		limit = len(s.alerts)
	}
	out := make([]model.Alert, 0, limit)
	for i := len(s.alerts) - 1; i >= 0 && len(out) < limit; i-- {
		out = append(out, s.alerts[i])
	}
	return out
}

func (s *Store) Stats() model.Stats {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.stats
	st.ByProtocol = copyMap(s.stats.ByProtocol)
	st.ByConfidence = copyMap(s.stats.ByConfidence)
	st.ByModel = copyMap(s.stats.ByModel)
	st.ByClient = copyMap(s.stats.ByClient)
	st.ByRule = copyMap(s.stats.ByRule)
	return st
}

func (s *Store) Subscribe() (<-chan Event, func()) {
	ch := make(chan Event, subBuffer)
	s.mu.Lock()
	id := s.nextID
	s.nextID++
	s.subs[id] = ch
	s.mu.Unlock()
	cancel := func() {
		s.mu.Lock()
		delete(s.subs, id)
		s.mu.Unlock()
	}
	return ch, cancel
}

func (s *Store) snapshotSubs() []chan Event {
	out := make([]chan Event, 0, len(s.subs))
	for _, ch := range s.subs {
		out = append(out, ch)
	}
	return out
}

func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var err error
	if s.flowsFile != nil {
		err = s.flowsFile.Close()
	}
	if s.alertsFile != nil {
		if e := s.alertsFile.Close(); err == nil {
			err = e
		}
	}
	return err
}

func copyMap(m map[string]int) map[string]int {
	out := make(map[string]int, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}
