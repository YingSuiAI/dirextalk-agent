package transientmodel

import (
	"crypto/sha256"
	"testing"
)

func TestTargetIDCanonicalizesPublicProfile(t *testing.T) {
	t.Parallel()
	digest := sha256.Sum256([]byte("credential"))
	canonical := Profile{
		ProfileID: "openai:gpt-test", Provider: "openai_compatible", Model: "gpt-test",
		BaseURL: "https://api.openai.com/v1", MaxOutputTokens: 4096, ContextWindow: 65536,
	}
	withWhitespace := canonical
	withWhitespace.ProfileID = "  openai:gpt-test  "
	withWhitespace.Provider = " openai_compatible "
	withWhitespace.Model = " gpt-test "
	withWhitespace.BaseURL = " https://api.openai.com/v1/ "

	first, err := TargetID(" owner ", " request ", canonical, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	second, err := TargetID("owner", "request", withWhitespace, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatalf("canonical target mismatch: %q != %q", first, second)
	}
}
