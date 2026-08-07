package buildinfo

import (
	"os"
	"testing"
)

func TestValidateReleaseVersion(t *testing.T) {
	original := ReleaseVersion
	t.Cleanup(func() { ReleaseVersion = original })

	for _, version := range []string{"dev", "v1.0.0", "v1.2.3-rc.1+build.7"} {
		ReleaseVersion = version
		if err := Validate(); err != nil {
			t.Fatalf("Validate(%q): %v", version, err)
		}
	}
	for _, version := range []string{"", "1.0.0", "v1", "v01.0.0", "latest", "v1.0.0\nsecret"} {
		ReleaseVersion = version
		if err := Validate(); err == nil {
			t.Fatalf("Validate(%q) unexpectedly succeeded", version)
		}
	}
}

func TestInjectedReleaseVersion(t *testing.T) {
	expected := os.Getenv("AGENT_EXPECT_RELEASE_VERSION")
	if expected == "" {
		t.Skip("build-time release version check")
	}
	if err := Validate(); err != nil {
		t.Fatal(err)
	}
	if Version() != expected {
		t.Fatalf("injected release version = %q, want %q", Version(), expected)
	}
}
