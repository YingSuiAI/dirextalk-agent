package migrations

import (
	"bytes"
	"embed"
	"fmt"
	"io"
	"strconv"
	"strings"
	"testing/fstest"
)

const (
	bundleName  = "agent_migrations.sql"
	beginMarker = "-- dirextalk-agent migration begin "
	endMarker   = "-- dirextalk-agent migration end "
	// CurrentVersion is the latest virtual migration represented in the bundle.
	CurrentVersion = int64(41)
)

// Migration is one virtual migration extracted from the embedded bundle.
// Script is byte-identical to the original migration source file.
type Migration struct {
	Name    string
	Version int64
	Script  []byte
}

//go:embed agent_migrations.sql
var bundle embed.FS

// Files exposes the historical virtual migration files to existing callers.
// The physical source is the single embedded agent_migrations.sql bundle.
var Files migrationFS

var ordered []Migration

func init() {
	raw, err := bundle.ReadFile(bundleName)
	if err != nil {
		panic(fmt.Sprintf("read embedded migration bundle: %v", err))
	}
	parsed, err := ParseBundle(raw)
	if err != nil {
		panic(fmt.Sprintf("parse embedded migration bundle: %v", err))
	}
	ordered = parsed
	entries := make(fstest.MapFS, len(parsed))
	for _, migration := range parsed {
		entries[migration.Name] = &fstest.MapFile{Data: append([]byte(nil), migration.Script...), Mode: 0o444}
	}
	Files = migrationFS{MapFS: entries}
}

// ParseBundle extracts the ordered virtual migrations from raw. Marker lines
// and separators are excluded; every returned Script retains its source bytes.
// Input must contain exactly contiguous versions 1 through 41.
func ParseBundle(raw []byte) ([]Migration, error) {
	if len(raw) == 0 {
		return nil, fmt.Errorf("migration bundle is empty")
	}
	var migrations []Migration
	seen := make(map[string]struct{})
	offset := 0
	expected := int64(1)
	for offset < len(raw) {
		lineEnd := bytes.IndexByte(raw[offset:], '\n')
		if lineEnd < 0 {
			return nil, fmt.Errorf("migration bundle marker at byte %d is not newline-terminated", offset)
		}
		lineEnd += offset
		line := raw[offset:lineEnd]
		name, ok := parseMarker(line, beginMarker)
		if !ok {
			return nil, fmt.Errorf("expected migration %d begin marker at byte %d", expected, offset)
		}
		if _, duplicate := seen[name]; duplicate {
			return nil, fmt.Errorf("duplicate migration marker %q", name)
		}
		version, err := migrationVersion(name)
		if err != nil {
			return nil, err
		}
		if version != expected {
			return nil, fmt.Errorf("noncontiguous migration version %d, expected %d", version, expected)
		}
		seen[name] = struct{}{}
		bodyStart := lineEnd + 1
		cursor := bodyStart
		foundEnd := false
		for cursor < len(raw) {
			nextEnd := bytes.IndexByte(raw[cursor:], '\n')
			if nextEnd < 0 {
				return nil, fmt.Errorf("migration %q end marker is not newline-terminated", name)
			}
			nextEnd += cursor
			candidate := raw[cursor:nextEnd]
			if endName, isEnd := parseMarker(candidate, endMarker); isEnd {
				if endName != name {
					return nil, fmt.Errorf("migration %q closed by %q", name, endName)
				}
				if cursor == bodyStart || raw[cursor-1] != '\n' {
					return nil, fmt.Errorf("migration %q script is not newline-terminated", name)
				}
				migrations = append(migrations, Migration{Name: name, Version: version, Script: append([]byte(nil), raw[bodyStart:cursor]...)})
				offset = nextEnd + 1
				expected++
				foundEnd = true
				break
			}
			if _, isBegin := parseMarker(candidate, beginMarker); isBegin {
				return nil, fmt.Errorf("migration %q has no end marker", name)
			}
			cursor = nextEnd + 1
		}
		if !foundEnd {
			return nil, fmt.Errorf("migration %q has no end marker", name)
		}
	}
	if expected != CurrentVersion+1 {
		return nil, fmt.Errorf("migration bundle ended at version %d, expected %d", expected-1, CurrentVersion)
	}
	return migrations, nil
}

func parseMarker(line []byte, prefix string) (string, bool) {
	if !bytes.HasPrefix(line, []byte(prefix)) {
		return "", false
	}
	name := string(line[len(prefix):])
	if name == "" || bytes.ContainsAny([]byte(name), " \t\r\n") {
		return "", false
	}
	return name, true
}

func migrationVersion(name string) (int64, error) {
	if !strings.HasSuffix(name, ".up.sql") {
		return 0, fmt.Errorf("invalid migration filename %q", name)
	}
	separator := strings.IndexByte(name, '_')
	if separator <= 0 {
		return 0, fmt.Errorf("invalid migration filename %q", name)
	}
	version, err := strconv.ParseInt(name[:separator], 10, 64)
	if err != nil || version < 1 {
		return 0, fmt.Errorf("invalid migration filename %q", name)
	}
	return version, nil
}

// Entries returns virtual migration filenames in application order.
func Entries() []string {
	entries := make([]string, len(ordered))
	for index, migration := range ordered {
		entries[index] = migration.Name
	}
	return entries
}

// Ordered returns a defensive copy of all parsed migrations.
func Ordered() []Migration {
	result := make([]Migration, len(ordered))
	for index, migration := range ordered {
		result[index] = Migration{Name: migration.Name, Version: migration.Version, Script: append([]byte(nil), migration.Script...)}
	}
	return result
}

type migrationFS struct {
	fstest.MapFS
}

func (f migrationFS) ReadFile(name string) ([]byte, error) {
	file, err := f.MapFS.Open(name)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return io.ReadAll(file)
}
