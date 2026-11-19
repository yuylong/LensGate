package store

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
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

	// 详情正文体积大，不常驻内存：JSONL 中只记录每条详情的偏移，
	// 查询时按偏移 ReadAt 读回，进程重启后仍可查看历史详情。
	details     map[string]detailRef
	detailOrder []string
	detailMem   map[string]model.FlowDetail
	detailSize  int64
	detailsFile *os.File

	subs   map[int]chan Event
	nextID int
}

// detailRef 指向 flow-details.jsonl 中一行完整详情。
type detailRef struct {
	offset int64
	length int
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
	detailPath := filepath.Join(dir, "flow-details.jsonl")

	s.loadFlows(flowPath)
	s.loadAlerts(alertPath)
	s.loadDetails(detailPath)

	f, err := os.OpenFile(flowPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return nil, err
	}
	a, err := os.OpenFile(alertPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		f.Close()
		return nil, err
	}
	// 详情文件需要随机读（按偏移取单条），同时继续追加写入。
	d, err := os.OpenFile(detailPath, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0o644)
	if err != nil {
		f.Close()
		a.Close()
		return nil, err
	}
	s.flowsFile = f
	s.alertsFile = a
	s.detailsFile = d
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

// loadDetails 只重建 id → 偏移索引，不把正文读进内存。
func (s *Store) loadDetails(path string) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()
	r := bufio.NewReaderSize(f, 64*1024)
	var offset int64
	for {
		line, readErr := r.ReadBytes('\n')
		if len(line) > 0 {
			var d model.FlowDetail
			if json.Unmarshal(bytes.TrimSpace(line), &d) == nil && d.Flow.ID != "" {
				s.addDetailRef(d.Flow.ID, detailRef{offset: offset, length: len(line)})
			}
			offset += int64(len(line))
		}
		if readErr != nil {
			break
		}
	}
	s.detailSize = offset
}

// addDetailRef 记录索引并按 flowCap 淘汰最旧的详情（与内存流量环一致）。
func (s *Store) addDetailRef(id string, ref detailRef) {
	if s.details == nil {
		s.details = map[string]detailRef{}
	}
	if _, exists := s.details[id]; !exists {
		s.detailOrder = append(s.detailOrder, id)
	}
	s.details[id] = ref
	for len(s.detailOrder) > s.flowCap {
		old := s.detailOrder[0]
		s.detailOrder = s.detailOrder[1:]
		delete(s.details, old)
	}
}

// AddFlowDetail 追加一条流量详情。有数据目录时落盘并只保留索引；
// 没有数据目录（测试场景）时退化为内存保存。
func (s *Store) AddFlowDetail(d model.FlowDetail) {
	if d.Flow.ID == "" {
		return
	}
	data, err := json.Marshal(d)
	if err != nil || len(data) == 0 {
		return
	}
	line := append(data, '\n')

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.detailsFile == nil {
		if s.detailMem == nil {
			s.detailMem = map[string]model.FlowDetail{}
		}
		if _, exists := s.detailMem[d.Flow.ID]; !exists {
			s.detailOrder = append(s.detailOrder, d.Flow.ID)
		}
		s.detailMem[d.Flow.ID] = d
		for len(s.detailOrder) > s.flowCap {
			old := s.detailOrder[0]
			s.detailOrder = s.detailOrder[1:]
			delete(s.detailMem, old)
		}
		return
	}
	offset := s.detailSize
	if _, err := s.detailsFile.Write(line); err != nil {
		return
	}
	s.detailSize += int64(len(line))
	s.addDetailRef(d.Flow.ID, detailRef{offset: offset, length: len(line)})
}

// FlowDetail 按 id 读取单条详情；不存在时返回 false。
func (s *Store) FlowDetail(id string) (model.FlowDetail, bool) {
	s.mu.Lock()
	ref, ok := s.details[id]
	f := s.detailsFile
	mem, hasMem := s.detailMem[id]
	s.mu.Unlock()
	if f == nil {
		return mem, hasMem
	}
	if !ok {
		return model.FlowDetail{}, false
	}
	buf := make([]byte, ref.length)
	if _, err := f.ReadAt(buf, ref.offset); err != nil && err != io.EOF {
		return model.FlowDetail{}, false
	}
	var d model.FlowDetail
	if err := json.Unmarshal(bytes.TrimSpace(buf), &d); err != nil {
		return model.FlowDetail{}, false
	}
	return d, true
}

func (s *Store) AddFlow(f model.Flow) {	data, _ := json.Marshal(f)
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
	if s.detailsFile != nil {
		if e := s.detailsFile.Close(); err == nil {
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
