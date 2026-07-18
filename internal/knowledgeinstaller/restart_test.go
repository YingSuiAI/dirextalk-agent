package installer

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

type recordedCommand struct {
	executable string
	args       []string
}

type fakeRunner struct {
	commands []recordedCommand
}

func (f *fakeRunner) Run(_ context.Context, executable string, args ...string) error {
	f.commands = append(f.commands, recordedCommand{executable: executable, args: append([]string(nil), args...)})
	return nil
}

func (*fakeRunner) UnitState(context.Context, string) (UnitState, error) {
	return UnitState{LoadState: "loaded", ActiveState: "inactive"}, nil
}

func TestRestartUsesOnlyFixedCommandsAfterBoundaryValidation(t *testing.T) {
	t.Parallel()
	paths, err := TestPaths(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{
		ReleaseRoot + "/.provenance-sha256", QdrantConfigPath, QdrantUnitPath, AdapterUnitPath,
	} {
		target := paths.Resolve(path)
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(target, []byte("fixed"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	runner := &fakeRunner{}
	value := Installer{Paths: paths, Runner: runner}
	if err := value.RestartV1(context.Background()); err != nil {
		t.Fatal(err)
	}
	want := []recordedCommand{
		{executable: "/usr/bin/systemctl", args: []string{"daemon-reload"}},
		{executable: "/usr/bin/systemctl", args: []string{"restart", "dirextalk-qdrant.service"}},
		{executable: "/usr/bin/systemctl", args: []string{"restart", "dirextalk-knowledge-adapter.service"}},
		{executable: "/usr/bin/systemctl", args: []string{"is-active", "--quiet", "dirextalk-qdrant.service"}},
		{executable: "/usr/bin/systemctl", args: []string{"is-active", "--quiet", "dirextalk-knowledge-adapter.service"}},
	}
	if !reflect.DeepEqual(runner.commands, want) {
		t.Fatalf("commands = %#v, want %#v", runner.commands, want)
	}
}

func TestRestartRejectsSymlinkedBoundaryBeforeCommands(t *testing.T) {
	t.Parallel()
	paths, err := TestPaths(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	target := paths.Resolve(ReleaseRoot + "/.provenance-sha256")
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/etc/passwd", target); err != nil {
		t.Fatal(err)
	}
	runner := &fakeRunner{}
	if err := (Installer{Paths: paths, Runner: runner}).RestartV1(context.Background()); err == nil {
		t.Fatal("expected boundary rejection")
	}
	if len(runner.commands) != 0 {
		t.Fatal("commands ran before validation")
	}
}
