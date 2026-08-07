package corememory

import "strings"

type CanonicalMemory struct {
	ID       string
	Key      string
	Scope    Scope
	Text     string
	Type     MemoryType
	Revision int64
	Deleted  bool
}

type ChangeAction string

const (
	ChangeCreate ChangeAction = "create"
	ChangeUpdate ChangeAction = "update"
	ChangeDelete ChangeAction = "delete"
	ChangeNoop   ChangeAction = "noop"
)

type Change struct {
	Action           ChangeAction
	Reason           string
	Key              string
	Scope            Scope
	ExpectedRevision int64
}

// ReconcileCandidate deterministically derives a mutation from canonical
// state. The model's create/update hint never decides whether a row is
// inserted or overwritten.
func ReconcileCandidate(candidate Candidate, existing *CanonicalMemory) (Change, error) {
	candidate = candidate.Normalize()
	if err := candidate.Validate(); err != nil {
		return Change{}, err
	}
	change := Change{Action: ChangeNoop, Reason: "unchanged", Key: candidate.Key, Scope: candidate.Scope}
	if existing != nil {
		if existing.Key != candidate.Key || existing.Scope != candidate.Scope || existing.Revision < 1 {
			return Change{}, ErrInvalid
		}
		change.ExpectedRevision = existing.Revision
		if existing.Deleted {
			change.Reason = "tombstoned"
			return change, nil
		}
	}
	if candidate.Operation == OperationDelete {
		if existing == nil {
			change.Reason = "missing"
			return change, nil
		}
		change.Action, change.Reason = ChangeDelete, "explicit_delete"
		return change, nil
	}
	if candidate.Operation == OperationNoop {
		change.Reason = "model_noop"
		return change, nil
	}
	if existing == nil {
		change.Action, change.Reason = ChangeCreate, "new_canonical_slot"
		return change, nil
	}
	if equivalentMemory(existing.Text, candidate.Text) && existing.Type == candidate.Type {
		return change, nil
	}
	change.Action, change.Reason = ChangeUpdate, "canonical_value_changed"
	return change, nil
}

func equivalentMemory(left, right string) bool {
	normalize := func(value string) string {
		return strings.Join(strings.Fields(strings.ToLower(strings.TrimSpace(value))), " ")
	}
	return normalize(left) == normalize(right)
}
