// Package detect is a streaming detection engine that evaluates rules
// against every event as it is appended. Findings are themselves
// emitted back into the audit log, so the record of "what the detector
// saw" is as tamper-evident as the events that triggered it.
package detect

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/PrimelPJ/aegis/internal/audit"
)

// Op is a field comparison operator.
type Op string

const (
	OpEq       Op = "eq"
	OpNeq      Op = "neq"
	OpContains Op = "contains"
	OpPrefix   Op = "prefix"
)

// Condition matches one field of an event.
type Condition struct {
	Field string `json:"field"` // actor|action|resource|outcome|source
	Op    Op     `json:"op"`
	Value string `json:"value"`
}

func fieldValue(e *audit.Event, field string) string {
	switch strings.ToLower(field) {
	case "actor":
		return e.Actor
	case "action":
		return e.Action
	case "resource":
		return e.Resource
	case "outcome":
		return e.Outcome
	case "source":
		return e.Source
	default:
		return e.Meta[field]
	}
}

func (c Condition) match(e *audit.Event) bool {
	got := fieldValue(e, c.Field)
	switch c.Op {
	case OpEq:
		return got == c.Value
	case OpNeq:
		return got != c.Value
	case OpContains:
		return strings.Contains(got, c.Value)
	case OpPrefix:
		return strings.HasPrefix(got, c.Value)
	default:
		return false
	}
}

// Rule is either a single-event match (Threshold == 0) or a windowed
// threshold: more than Threshold matching events sharing the same
// GroupBy value within WindowSeconds.
type Rule struct {
	ID            string      `json:"id"`
	Description   string      `json:"description"`
	Severity      string      `json:"severity"` // low|medium|high|critical
	When          []Condition `json:"when"`     // all must match (AND)
	Threshold     int         `json:"threshold"`
	WindowSeconds int         `json:"window_seconds"`
	GroupBy       string      `json:"group_by"`
}

func (r *Rule) matches(e *audit.Event) bool {
	for _, c := range r.When {
		if !c.match(e) {
			return false
		}
	}
	return true
}

// Finding is a detection result.
type Finding struct {
	RuleID      string `json:"rule_id"`
	Severity    string `json:"severity"`
	Description string `json:"description"`
	Subject     string `json:"subject"`
	TriggerSeq  uint64 `json:"trigger_seq"`
	Count       int    `json:"count"`
	IssuedUnix  int64  `json:"issued_unix_nano"`
}

type window struct {
	times []int64
}

// Engine evaluates rules over the event stream. It is safe for
// concurrent Evaluate calls.
type Engine struct {
	mu       sync.Mutex
	rules    []Rule
	windows  map[string]*window // key: ruleID + "\x00" + groupValue
	findings []Finding
}

// NewEngine builds an engine from a rule set.
func NewEngine(rules []Rule) *Engine {
	return &Engine{rules: rules, windows: make(map[string]*window)}
}

// Evaluate runs every rule against one event and returns any findings
// it produced. Threshold rules fire once when the count first exceeds
// the limit within the rolling window.
func (en *Engine) Evaluate(e *audit.Event) []Finding {
	en.mu.Lock()
	defer en.mu.Unlock()

	var out []Finding
	for i := range en.rules {
		r := &en.rules[i]
		if !r.matches(e) {
			continue
		}

		if r.Threshold <= 0 {
			out = append(out, en.record(r, e, fieldValue(e, r.GroupBy), 1))
			continue
		}

		grp := fieldValue(e, r.GroupBy)
		key := r.ID + "\x00" + grp
		w := en.windows[key]
		if w == nil {
			w = &window{}
			en.windows[key] = w
		}
		now := e.TimeUnixN
		horizon := now - int64(r.WindowSeconds)*int64(time.Second)

		kept := w.times[:0]
		for _, t := range w.times {
			if t >= horizon {
				kept = append(kept, t)
			}
		}
		w.times = append(kept, now)

		if len(w.times) > r.Threshold {
			out = append(out, en.record(r, e, grp, len(w.times)))
			w.times = w.times[:0] // reset after firing to avoid alert storms
		}
	}
	return out
}

func (en *Engine) record(r *Rule, e *audit.Event, subject string, count int) Finding {
	if subject == "" {
		subject = e.Actor
	}
	f := Finding{
		RuleID:      r.ID,
		Severity:    r.Severity,
		Description: r.Description,
		Subject:     subject,
		TriggerSeq:  e.Seq,
		Count:       count,
		IssuedUnix:  time.Now().UnixNano(),
	}
	en.findings = append(en.findings, f)
	return f
}

// Findings returns a copy of all findings produced so far.
func (en *Engine) Findings() []Finding {
	en.mu.Lock()
	defer en.mu.Unlock()
	out := make([]Finding, len(en.findings))
	copy(out, en.findings)
	return out
}

// AsEvent converts a finding into an audit event so the detection
// record is itself written tamper-evidently into the log.
func (f Finding) AsEvent() audit.Event {
	return audit.Event{
		Actor:    "aegis.detector",
		Action:   "detection.finding",
		Resource: f.RuleID,
		Outcome:  f.Severity,
		Source:   "detect-engine",
		Meta: map[string]string{
			"subject":     f.Subject,
			"description": f.Description,
			"trigger_seq": fmt.Sprintf("%d", f.TriggerSeq),
			"count":       fmt.Sprintf("%d", f.Count),
		},
	}
}
