package detect

import (
	"testing"
	"time"

	"github.com/PrimelPJ/aegis/internal/audit"
)

func ev(actor, action, outcome string, tnano int64) *audit.Event {
	return &audit.Event{Actor: actor, Action: action, Outcome: outcome, TimeUnixN: tnano}
}

func TestSingleEventMatchRule(t *testing.T) {
	en := NewEngine([]Rule{{
		ID: "control-disabled", Severity: "high",
		When: []Condition{{Field: "action", Op: OpEq, Value: "control.disable"}},
	}})

	if f := en.Evaluate(ev("admin", "object.read", "success", 1)); len(f) != 0 {
		t.Fatal("non-matching event should not fire")
	}
	f := en.Evaluate(ev("admin", "control.disable", "success", 2))
	if len(f) != 1 || f[0].RuleID != "control-disabled" {
		t.Fatalf("expected one finding, got %v", f)
	}
}

func TestThresholdRuleWindow(t *testing.T) {
	en := NewEngine([]Rule{{
		ID: "brute-force", Severity: "high",
		When:          []Condition{{Field: "action", Op: OpEq, Value: "auth.login"}, {Field: "outcome", Op: OpEq, Value: "failure"}},
		Threshold:     3,
		WindowSeconds: 10,
		GroupBy:       "actor",
	}})

	sec := int64(time.Second)
	var fired int
	for i := 0; i < 4; i++ { // 4 failures within 10s -> exceeds 3
		fired += len(en.Evaluate(ev("victim", "auth.login", "failure", int64(i)*sec)))
	}
	if fired != 1 {
		t.Fatalf("expected exactly one alert after exceeding threshold, got %d", fired)
	}
}

func TestThresholdGroupedByActor(t *testing.T) {
	en := NewEngine([]Rule{{
		ID: "bf", Severity: "high",
		When:          []Condition{{Field: "outcome", Op: OpEq, Value: "failure"}},
		Threshold:     2,
		WindowSeconds: 10,
		GroupBy:       "actor",
	}})
	sec := int64(time.Second)
	// Two different actors, two failures each: neither alone exceeds 2.
	total := 0
	for i := 0; i < 2; i++ {
		total += len(en.Evaluate(ev("alice", "x", "failure", int64(i)*sec)))
		total += len(en.Evaluate(ev("bob", "x", "failure", int64(i)*sec)))
	}
	if total != 0 {
		t.Fatalf("grouping failed: separate actors should not aggregate (%d)", total)
	}
}

func TestWindowExpiry(t *testing.T) {
	en := NewEngine([]Rule{{
		ID: "bf", Severity: "high",
		When:          []Condition{{Field: "outcome", Op: OpEq, Value: "failure"}},
		Threshold:     2,
		WindowSeconds: 5,
		GroupBy:       "actor",
	}})
	sec := int64(time.Second)
	en.Evaluate(ev("u", "x", "failure", 0))
	en.Evaluate(ev("u", "x", "failure", 1*sec))
	// Big time gap: old events fall out of the 5s window.
	fired := len(en.Evaluate(ev("u", "x", "failure", 100*sec)))
	if fired != 0 {
		t.Fatal("stale events outside the window must not count toward threshold")
	}
}

func TestFindingConvertsToAuditEvent(t *testing.T) {
	f := Finding{RuleID: "r1", Severity: "critical", Subject: "mallory", TriggerSeq: 9}
	e := f.AsEvent()
	if e.Action != "detection.finding" || e.Resource != "r1" || e.Meta["subject"] != "mallory" {
		t.Fatalf("finding did not map to an audit event correctly: %+v", e)
	}
}
