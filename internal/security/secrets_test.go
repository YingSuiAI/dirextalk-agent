package security

import (
	"regexp"
	"testing"
)

func TestContainsLikelySecret(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		value string
		want  bool
	}{
		{name: "ordinary goal", value: "compile the service and run unit tests", want: false},
		{name: "aws access key", value: "use AKIAABCDEFGHIJKLMNOP", want: true},
		{name: "model token", value: "token sk-abcdefghijklmnopqrstuvwxyz", want: true},
		{name: "github token", value: "ghp_abcdefghijklmnopqrstuvwxyz", want: true},
		{name: "labeled secret", value: "client_secret=abcdefghijklmnopqrstuvwxyz", want: true},
		{name: "dsn password", value: "postgres://agent:not-for-storage@example.test/database", want: true},
		{name: "private key", value: "-----BEGIN PRIVATE KEY-----", want: true},
		{name: "service key", value: "DTX-Service-Key svc_example.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", want: true},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if got := ContainsLikelySecret(test.value); got != test.want {
				t.Fatalf("ContainsLikelySecret() = %v, want %v", got, test.want)
			}
		})
	}
}

func TestRedactText(t *testing.T) {
	t.Parallel()
	input := "connect postgres://agent:super-secret@example.test/db with password=another-secret and Bearer abcdefghijklmnop DTX-Service-Key svc_example.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA -----BEGIN PRIVATE KEY-----\nprivate-canary\n-----END PRIVATE KEY-----"
	redacted := RedactText(input)
	for _, forbidden := range []string{"super-secret", "another-secret", "abcdefghijklmnop", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "private-canary"} {
		if regexp.MustCompile(regexp.QuoteMeta(forbidden)).MatchString(redacted) {
			t.Fatalf("redacted output retained %q: %s", forbidden, redacted)
		}
	}
}
