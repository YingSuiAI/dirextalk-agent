package postgres

import "testing"

func TestCanNarrowBootstrapScopes(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name    string
		current []string
		desired []string
		want    bool
	}{
		{
			name:    "admin to pairwise runtime and cloud read",
			current: []string{"admin"},
			desired: []string{"runtime.read", "runtime.write", "runtime.chat", "cloud.read"},
			want:    true,
		},
		{
			name:    "remove one explicit scope",
			current: []string{"runtime.read", "runtime.write", "runtime.chat"},
			desired: []string{"runtime.read", "runtime.chat"},
			want:    true,
		},
		{
			name:    "same scopes in another order",
			current: []string{"runtime.read", "runtime.chat"},
			desired: []string{"runtime.chat", "runtime.read"},
			want:    true,
		},
		{
			name:    "explicit scope expansion",
			current: []string{"runtime.read", "runtime.chat"},
			desired: []string{"runtime.read", "runtime.chat", "cloud.read"},
			want:    false,
		},
		{
			name:    "replace an explicit scope",
			current: []string{"runtime.read", "runtime.chat"},
			desired: []string{"runtime.read", "cloud.read"},
			want:    false,
		},
		{
			name:    "promote to admin",
			current: []string{"runtime.read", "runtime.chat"},
			desired: []string{"admin"},
			want:    false,
		},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if got := canNarrowBootstrapScopes(test.current, test.desired); got != test.want {
				t.Fatalf("canNarrowBootstrapScopes(%q, %q) = %v, want %v", test.current, test.desired, got, test.want)
			}
		})
	}
}
