package corememory

import (
	"errors"
	"fmt"
	"testing"
)

func validCandidate() Candidate {
	return Candidate{Operation: OperationCreate, Key: "preference.response.length", Text: "用户偏好简短回答", Type: MemoryTypePreference, Scope: ScopeOwner, Confidence: 0.95, Importance: 0.8, Sensitivity: SensitivityLow, Evidence: "我喜欢简短回答", Reason: "stable preference"}
}

func TestParseCandidatesRequiresVersionedBoundedJSON(t *testing.T) {
	raw := `{"schema_version":1,"candidates":[{"operation":"create","key":"preference.response.length","text":"short","type":"preference","scope":"owner","confidence":0.9,"importance":0.8,"sensitivity":"low","evidence":"short replies","reason":"stable"}]}`
	items, err := ParseCandidates(raw, 3)
	if err != nil || len(items) != 1 || items[0].Key != "preference.response.length" {
		t.Fatalf("items=%+v err=%v", items, err)
	}
	for _, invalid := range []string{
		`{"schema_version":2,"candidates":[]}`,
		`{"schema_version":1,"candidates":[],"extra":true}`,
		`not json`,
	} {
		if _, err := ParseCandidates(invalid, 3); !errors.Is(err, ErrInvalid) {
			t.Fatalf("raw=%q err=%v", invalid, err)
		}
	}
}

func TestParseCandidatesRejectsOversizedEnvelope(t *testing.T) {
	item := `{"operation":"noop","key":"goal.current","text":"","type":"fact","scope":"owner","confidence":0.9,"importance":0.8,"sensitivity":"low","evidence":"目标","reason":""}`
	raw := `{"schema_version":1,"candidates":[`
	for i := 0; i < MaxCandidates+1; i++ {
		if i > 0 {
			raw += ","
		}
		raw += item
	}
	raw += `]}`
	if _, err := ParseCandidates(raw, 3); !errors.Is(err, ErrInvalid) {
		t.Fatalf("err=%v", err)
	}
}

func TestPolicyAcceptsGroundedDurablePreference(t *testing.T) {
	candidate := validCandidate()
	decision := EvaluateCandidate(candidate, PolicyContext{LatestUserMessage: "请记住，我喜欢简短回答"}, DefaultPolicy())
	if !decision.Accepted || decision.Reason != "accepted" {
		t.Fatalf("decision=%+v", decision)
	}
}

func TestPolicyRejectsSecretsTransientAndUngroundedFacts(t *testing.T) {
	tests := []struct {
		name    string
		message string
		mutate  func(*Candidate)
		reason  string
	}{
		{name: "secret", message: "请记住 api_key=sk-supersecret", mutate: func(c *Candidate) { c.Text, c.Evidence = "sk-supersecret", "api_key=sk-supersecret" }, reason: "secret_detected"},
		{name: "weather city", message: "上海今天天气怎么样", mutate: func(c *Candidate) {
			c.Key, c.Text, c.Evidence = "profile.location.city", "用户住在上海", "上海"
		}, reason: "location_not_durable"},
		{name: "transient", message: "我今天有点累", mutate: func(c *Candidate) {
			c.Key, c.Text, c.Evidence = "profile.status.energy", "用户今天有点累", "我今天有点累"
		}, reason: "transient_fact"},
		{name: "ungrounded", message: "我喜欢简短回答", mutate: func(c *Candidate) { c.Evidence = "我住在上海" }, reason: "ungrounded_evidence"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := validCandidate()
			test.mutate(&candidate)
			decision := EvaluateCandidate(candidate, PolicyContext{LatestUserMessage: test.message}, DefaultPolicy())
			if decision.Accepted || decision.Reason != test.reason {
				t.Fatalf("decision=%+v", decision)
			}
		})
	}
}

func TestPolicyRequiresExplicitRequestForSensitiveMemory(t *testing.T) {
	candidate := validCandidate()
	candidate.Key, candidate.Text, candidate.Evidence, candidate.Sensitivity = "profile.health.condition", "用户有哮喘", "我有哮喘", SensitivitySensitive
	if decision := EvaluateCandidate(candidate, PolicyContext{LatestUserMessage: "我有哮喘"}, DefaultPolicy()); decision.Reason != "sensitive_without_explicit_request" {
		t.Fatalf("decision=%+v", decision)
	}
	if decision := EvaluateCandidate(candidate, PolicyContext{LatestUserMessage: "请记住我有哮喘"}, DefaultPolicy()); !decision.Accepted {
		t.Fatalf("decision=%+v", decision)
	}
}

func TestReconcilerDerivesCreateUpdateDeleteAndNoop(t *testing.T) {
	candidate := validCandidate()
	created, err := ReconcileCandidate(candidate, nil)
	if err != nil || created.Action != ChangeCreate {
		t.Fatalf("created=%+v err=%v", created, err)
	}
	existing := &CanonicalMemory{ID: "memory-1", Key: candidate.Key, Scope: candidate.Scope, Text: "用户偏好简短回答", Type: candidate.Type, Revision: 2}
	unchanged, _ := ReconcileCandidate(candidate, existing)
	if unchanged.Action != ChangeNoop {
		t.Fatalf("unchanged=%+v", unchanged)
	}
	candidate.Operation, candidate.Text = OperationCreate, "用户偏好详细回答"
	updated, _ := ReconcileCandidate(candidate, existing)
	if updated.Action != ChangeUpdate || updated.ExpectedRevision != 2 {
		t.Fatalf("updated=%+v", updated)
	}
	candidate.Operation = OperationDelete
	deleted, _ := ReconcileCandidate(candidate, existing)
	if deleted.Action != ChangeDelete {
		t.Fatalf("deleted=%+v", deleted)
	}
	tombstone := *existing
	tombstone.Deleted = true
	blocked, _ := ReconcileCandidate(candidate, &tombstone)
	if blocked.Action != ChangeNoop || blocked.Reason != "tombstoned" {
		t.Fatalf("blocked=%+v", blocked)
	}
}

func TestCandidateBounds(t *testing.T) {
	candidate := validCandidate()
	candidate.Text = fmt.Sprintf("%0*d", MaxMemoryTextBytes+1, 0)
	if err := candidate.Validate(); !errors.Is(err, ErrInvalid) {
		t.Fatalf("err=%v", err)
	}
}
