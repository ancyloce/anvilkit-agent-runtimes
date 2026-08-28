package runtime

import (
	"log/slog"
	"sync"
	"time"
)

// Metrics is a unit's bounded operational count: admission refusals by their
// stable code, answered tasks by governed status and reason, the tasks in
// flight, and what a drain cost.
//
// Every key is a closed vocabulary — a refusal code the canonical boundary
// description names, a status and reason from the governed result registry —
// and never a task, attempt, credential, or fence value, so nothing counted
// here can carry a secret or grow without bound.
//
// It is process memory reported through the structured log: on every drain
// the unit reports how long the drain took, whether the released window
// closed on admitted work, and how many admitted tasks were still unanswered
// when it did. The manifest's telemetry object names no metrics path, so a
// scrape surface is a contract decision rather than one a unit makes for
// itself; until that decision is cut, the log is the export.
type Metrics struct {
	lock     sync.Mutex
	refusals map[string]int
	answers  map[string]int
	inFlight int
}

// NewMetrics starts every count at zero.
func NewMetrics() *Metrics {
	return &Metrics{refusals: map[string]int{}, answers: map[string]int{}}
}

// Refused counts one admission refusal under its stable code.
func (m *Metrics) Refused(code string) {
	if m == nil {
		return
	}
	m.lock.Lock()
	defer m.lock.Unlock()
	m.refusals[code]++
}

// Admitted counts one task entering execution.
func (m *Metrics) Admitted() {
	if m == nil {
		return
	}
	m.lock.Lock()
	defer m.lock.Unlock()
	m.inFlight++
}

// Answered counts one admitted task leaving execution, under the governed
// status and reason it was answered with, or under the refusal code when it
// could not be answered at all.
func (m *Metrics) Answered(status, reason string) {
	if m == nil {
		return
	}
	m.lock.Lock()
	defer m.lock.Unlock()
	m.inFlight--
	m.answers[status+"/"+reason]++
}

// Snapshot is one consistent read of the counts.
type Snapshot struct {
	Refusals map[string]int
	Answers  map[string]int
	InFlight int
}

// Snapshot copies the counts out under the lock.
func (m *Metrics) Snapshot() Snapshot {
	if m == nil {
		return Snapshot{Refusals: map[string]int{}, Answers: map[string]int{}}
	}
	m.lock.Lock()
	defer m.lock.Unlock()
	snapshot := Snapshot{Refusals: make(map[string]int, len(m.refusals)), Answers: make(map[string]int, len(m.answers)), InFlight: m.inFlight}
	for code, count := range m.refusals {
		snapshot.Refusals[code] = count
	}
	for outcome, count := range m.answers {
		snapshot.Answers[outcome] = count
	}
	return snapshot
}

// Drained reports what a drain cost: how long it took, whether the released
// window closed on admitted work, and how many admitted tasks were still
// unanswered when the unit stopped — each of those is a run the control plane
// will replace.
func (m *Metrics) Drained(elapsed time.Duration, windowClosed bool) {
	snapshot := m.Snapshot()
	slog.Info("drained",
		"drainMilliseconds", elapsed.Milliseconds(),
		"windowClosed", windowClosed,
		"unansweredAtShutdown", snapshot.InFlight,
		"admissionRefusals", snapshot.Refusals,
		"answers", snapshot.Answers)
}
