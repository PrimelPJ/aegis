package detect

import (
	"encoding/json"
	"os"
)

// DefaultRules is a starter rule set covering common security signals.
func DefaultRules() []Rule {
	return []Rule{
		{
			ID:            "brute-force-auth",
			Description:   "Repeated failed authentication for one actor",
			Severity:      "high",
			When:          []Condition{{Field: "action", Op: OpEq, Value: "auth.login"}, {Field: "outcome", Op: OpEq, Value: "failure"}},
			Threshold:     5,
			WindowSeconds: 60,
			GroupBy:       "actor",
		},
		{
			ID:          "privilege-escalation",
			Description: "Privilege or role elevation performed",
			Severity:    "critical",
			When:        []Condition{{Field: "action", Op: OpEq, Value: "iam.role.grant"}, {Field: "resource", Op: OpContains, Value: "admin"}},
		},
		{
			ID:          "audit-log-tamper-attempt",
			Description: "Direct operation against the audit subsystem",
			Severity:    "critical",
			When:        []Condition{{Field: "resource", Op: OpPrefix, Value: "aegis://"}},
		},
		{
			ID:            "data-exfiltration-volume",
			Description:   "High volume of object reads by one actor",
			Severity:      "medium",
			When:          []Condition{{Field: "action", Op: OpEq, Value: "object.read"}},
			Threshold:     50,
			WindowSeconds: 30,
			GroupBy:       "actor",
		},
		{
			ID:          "security-control-disabled",
			Description: "A security control was disabled",
			Severity:    "high",
			When:        []Condition{{Field: "action", Op: OpEq, Value: "control.disable"}},
		},
	}
}

// LoadRules reads a JSON rule array from path, falling back to
// DefaultRules if path is empty.
func LoadRules(path string) ([]Rule, error) {
	if path == "" {
		return DefaultRules(), nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var rules []Rule
	if err := json.Unmarshal(b, &rules); err != nil {
		return nil, err
	}
	return rules, nil
}
