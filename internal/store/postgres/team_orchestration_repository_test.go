package postgres

import (
	"errors"
	"testing"

	"github.com/YingSuiAI/dirextalk-agent/internal/teamorchestration"
)

func TestTeamOrchestrationRepositoryTranslatesPersistenceErrors(t *testing.T) {
	t.Parallel()
	unknown := errors.New("unknown persistence failure")
	tests := []struct {
		name string
		got  error
		want error
	}{
		{
			name: "invalid",
			got:  orchestrationRepositoryError(ErrTeamFactInvalid),
			want: teamorchestration.ErrInvalid,
		},
		{
			name: "not found",
			got:  orchestrationRepositoryError(ErrTeamFactNotFound),
			want: teamorchestration.ErrNotFound,
		},
		{
			name: "revision",
			got:  orchestrationRepositoryError(ErrTeamFactRevision),
			want: teamorchestration.ErrRevision,
		},
		{
			name: "scope",
			got:  orchestrationRepositoryError(ErrTeamFactScope),
			want: teamorchestration.ErrScopeChanged,
		},
		{
			name: "challenge consumed",
			got:  orchestrationRepositoryError(ErrTeamChallengeConsumed),
			want: teamorchestration.ErrChallengeConsumed,
		},
		{
			name: "corrupt",
			got:  orchestrationRepositoryError(ErrTeamFactCorrupt),
			want: teamorchestration.ErrFactMismatch,
		},
		{
			name: "unknown",
			got:  orchestrationRepositoryError(unknown),
			want: unknown,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			if !errors.Is(test.got, test.want) {
				t.Fatalf(
					"orchestrationRepositoryError()=%v, want %v",
					test.got,
					test.want,
				)
			}
		})
	}
}
