package extensionrunner

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"path"
	"strings"

	"github.com/google/uuid"
)

const (
	maxV2ResultFiles              = 128
	v2StatusDiagnosticReserveByte = 4 << 10 // per stream, after base64 encoding budget is checked below
	sandboxRootAnchorPrefix       = ".dirextalk-sandbox-root-"
)

// RequestV2 is the only request understood by the deployed seqpacket server.
// Host paths and environment values are intentionally absent from this type.
// Argv is the complete exec argv, including argv[0]. An empty value uses
// /app/entry as argv[0]; callers that need positional arguments must include
// the executable name as the first element.
type RequestV2 struct {
	RunID         string     `json:"run_id"`
	TaskID        string     `json:"task_id"`
	TaskFence     string     `json:"task_fence"`
	InstallDigest string     `json:"install_digest"`
	Runtime       string     `json:"runtime,omitempty"`
	Entry         string     `json:"entry"`
	EntrySHA256   string     `json:"entry_sha256,omitempty"`
	Argv          []string   `json:"argv"`
	Stdin         *FDRef     `json:"stdin,omitempty"`
	Secrets       []SecretFD `json:"secrets,omitempty"`
	ResultFiles   []string   `json:"result_files,omitempty"`
	TimeoutMS     int64      `json:"timeout_ms"`
	Limits        LimitsV2   `json:"limits"`
}

// FDRef is an index into the SCM_RIGHTS descriptor array, never a host fd.
type FDRef struct {
	Index  int    `json:"index"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}
type SecretFD struct {
	Name   string `json:"name"`
	Index  int    `json:"index"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}
type LimitsV2 struct {
	CPUSeconds  int64 `json:"cpu_seconds"`
	MemoryBytes int64 `json:"memory_bytes"`
	Processes   int64 `json:"processes"`
	FileBytes   int64 `json:"file_bytes"`
	OpenFiles   int64 `json:"open_files"`
}

var (
	ErrProtocol = errors.New("invalid extension runner protocol")
	ErrReplay   = errors.New("extension runner run already admitted")
	ErrState    = errors.New("invalid extension runner lifecycle transition")
)

func ValidateRequestV2(r RequestV2) error {
	for _, id := range []string{r.RunID, r.TaskID, r.TaskFence} {
		if _, err := idPathPart(id); err != nil {
			return ErrInvalid
		}
	}
	if !digestRE.MatchString(r.InstallDigest) || len(r.Argv) > 128 || len(r.ResultFiles) > maxV2ResultFiles || r.TimeoutMS <= 0 || r.TimeoutMS > 24*60*60*1000 || !validLimitsV2(r.Limits) {
		return ErrInvalid
	}
	if r.Runtime == "" {
		if r.Entry != "entry" || r.EntrySHA256 != "" {
			return ErrInvalid
		}
	} else if r.Runtime == "node" {
		if !safeRelativeSlash(r.Entry) || !digestRE.MatchString(r.EntrySHA256) {
			return ErrInvalid
		}
	} else {
		return ErrInvalid
	}
	for _, a := range r.Argv {
		if len(a) > 16<<10 || strings.IndexByte(a, 0) >= 0 {
			return ErrInvalid
		}
	}
	seenResults := map[string]bool{}
	for _, p := range r.ResultFiles {
		if !safeRelativeSlash(p) || sandboxReservedResultPath(p) || seenResults[p] {
			return ErrInvalid
		}
		seenResults[p] = true
	}
	if err := validateV2ResultStatusBudget(r.RunID, r.ResultFiles); err != nil {
		return err
	}
	if len(r.Secrets) > 64 {
		return ErrInvalid
	}
	seenSecrets := map[string]bool{}
	indices := map[int]bool{}
	if r.Stdin != nil {
		if err := validateFDRef(*r.Stdin); err != nil {
			return err
		}
		indices[r.Stdin.Index] = true
	}
	for _, s := range r.Secrets {
		if !safeName(s.Name) || seenSecrets[s.Name] {
			return ErrInvalid
		}
		seenSecrets[s.Name] = true
		if err := validateFDRef(FDRef{Index: s.Index, Size: s.Size, SHA256: s.SHA256}); err != nil || indices[s.Index] {
			return ErrInvalid
		}
		indices[s.Index] = true
	}
	return nil
}

// validateV2ResultStatusBudget reserves room for terminal diagnostics while
// proving that every registered result's path/digest/size metadata can remain
// on the one V2 response datagram.  Result entries are never silently dropped.
func validateV2ResultStatusBudget(runID string, paths []string) error {
	if len(paths) > maxV2ResultFiles {
		return ErrInvalid
	}
	files := make([]ResultFile, len(paths))
	for i, p := range paths {
		files[i] = ResultFile{Path: p, SHA256: strings.Repeat("f", 64), Size: MaxOutputBytes}
	}
	_, err := EncodeStatusV1(StatusV1{RunID: runID, Phase: PhaseFailed, Error: ErrorCleanup, Status: strings.Repeat("x", 256), Stdout: make([]byte, v2StatusDiagnosticReserveByte), Stderr: make([]byte, v2StatusDiagnosticReserveByte), ResultFiles: files})
	if err != nil {
		return ErrInvalid
	}
	return nil
}
func validLimitsV2(l LimitsV2) bool {
	return l.CPUSeconds > 0 && l.CPUSeconds <= 24*60*60 &&
		l.MemoryBytes > 0 && l.MemoryBytes <= 1<<40 &&
		l.Processes > 0 && l.Processes <= 4096 &&
		l.FileBytes > 0 && l.FileBytes <= 1<<40 &&
		l.OpenFiles > 0 && l.OpenFiles <= 1<<20
}
func validateFDRef(f FDRef) error {
	if f.Index < 0 || f.Index > 4096 || f.Size < 0 || f.Size > MaxStdinBytes || !digestRE.MatchString(f.SHA256) {
		return ErrInvalid
	}
	return nil
}
func safeRelativeSlash(p string) bool {
	return p != "" && !strings.ContainsAny(p, "\\\x00") && !strings.HasPrefix(p, "/") && path.Clean(p) == p && p != "." && p != ".." && !strings.HasPrefix(p, "../")
}

func sandboxReservedResultPath(p string) bool {
	first, _, _ := strings.Cut(p, "/")
	return strings.HasPrefix(first, sandboxRootAnchorPrefix)
}

func ValidateFDSet(r RequestV2, fdCount int) error {
	if err := ValidateRequestV2(r); err != nil {
		return err
	}
	used := map[int]bool{}
	if r.Stdin != nil {
		used[r.Stdin.Index] = true
	}
	for _, s := range r.Secrets {
		used[s.Index] = true
	}
	if len(used) != fdCount {
		return ErrProtocol
	}
	for i := 0; i < fdCount; i++ {
		if !used[i] {
			return ErrProtocol
		}
	}
	return nil
}

func DigestBytes(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }
func idPathPart(id string) (string, error) {
	u, err := uuid.Parse(id)
	if err != nil || u == uuid.Nil || u.String() != id {
		return "", ErrInvalid
	}
	return strings.ToLower(u.String()), nil
}
func requireEntryPath(p string) error {
	if p != "entry" {
		return fmt.Errorf("%w: entry", ErrInvalid)
	}
	return nil
}
