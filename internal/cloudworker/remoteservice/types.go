// Package remoteservice compiles typed jobs and long-running services for an
// SSH-managed persistent worker. It never interprets natural language or a
// shell command string.
package remoteservice

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

var (
	ErrInvalid      = errors.New("invalid remote workload")
	ErrNotConfirmed = errors.New("remote mutation is not exactly confirmed")
	ErrReadback     = errors.New("remote mutation read-back mismatch")
)

type WorkloadKind string

const (
	WorkloadJob     WorkloadKind = "job"
	WorkloadService WorkloadKind = "service"
)

type Command struct {
	Executable string
	Arguments  []string
}

// SecretReference is an opaque reference resolved by the remote executor.
// Secret values must never be placed in Environment or in a compiled unit.
type SecretReference struct {
	Store    string
	Name     string
	Revision string
}

type Service struct {
	Port       uint16
	HealthPath string
	LogLines   uint16
}

type Workload struct {
	ID          string
	Kind        WorkloadKind
	User        string
	WorkDir     string
	Command     Command
	Environment map[string]string
	SecretEnv   map[string]SecretReference
	Service     *Service
	Exposure    *Exposure
}

// Worker owns zero or more independently addressable workloads. PublicIPv4 is
// the ordinary SSH address; it is not a promise of a stable service address.
type Worker struct {
	ID         string
	AccountID  string
	PublicIPv4 string
	Lifecycle  WorkerLifecycle
	Workloads  []Workload
}

// WorkerLifecycle is retained and running by default. Destruction after a job
// is an explicit opt-in and must still be authorized by the worker owner.
type WorkerLifecycle struct {
	DestroyAfterTask bool
}

type WorkerHourlyQuote struct {
	Currency         string
	ComputeMicros    uint64
	PublicIPv4Micros uint64
	TotalMicros      uint64
}

func NewWorkerHourlyQuote(currency string, computeMicros, publicIPv4Micros uint64) (WorkerHourlyQuote, error) {
	if len(currency) != 3 || strings.ToUpper(currency) != currency || computeMicros > ^uint64(0)-publicIPv4Micros {
		return WorkerHourlyQuote{}, ErrInvalid
	}
	return WorkerHourlyQuote{Currency: currency, ComputeMicros: computeMicros, PublicIPv4Micros: publicIPv4Micros, TotalMicros: computeMicros + publicIPv4Micros}, nil
}

type Exposure struct {
	Enabled      bool
	Hostname     string
	TLS          bool
	Confirmation ExactConfirmation
	Domain       *DomainBinding
}

type DomainMode string

const (
	DomainRoute53SameAccount DomainMode = "route53_same_account"
	DomainExternal           DomainMode = "external"
)

type DomainBinding struct {
	Mode     DomainMode
	ZoneID   string
	Hostname string
	TTL      uint32
}

// ExactConfirmation binds a user-visible proof to the digest of one exact
// mutation. Reusing it for any changed mutation fails closed.
type ExactConfirmation struct {
	Proof  string
	Digest string
}

type File struct {
	Path    string
	Mode    uint32
	Content []byte
}

type RemoteCommand struct {
	Executable string
	Arguments  []string
}

type SecretBinding struct {
	EnvironmentName string
	Reference       SecretReference
}

type StatusCommands struct {
	Active  RemoteCommand
	Health  *RemoteCommand
	LogTail RemoteCommand
	Load    RemoteCommand
}

type CompiledWorkload struct {
	WorkloadID     string
	UnitName       string
	Files          []File
	SecretEnvFile  string
	SecretBindings []SecretBinding
	Apply          []RemoteCommand
	Status         StatusCommands
	Caddy          *CompiledCaddy
}

type CompiledCaddy struct {
	File  File
	Apply []RemoteCommand
}

type HealthState string

const (
	HealthUnknown   HealthState = "unknown"
	HealthHealthy   HealthState = "healthy"
	HealthUnhealthy HealthState = "unhealthy"
)

type Load struct {
	One, Five, Fifteen float64
}

type WorkloadStatus struct {
	WorkloadID  string
	ActiveState string
	Health      HealthState
	LogTail     string
	Load        Load
}

var (
	idPattern   = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
	userPattern = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)
	envPattern  = regexp.MustCompile(`^[A-Z_][A-Z0-9_]{0,127}$`)
)

func (workload Workload) validate() error {
	if !idPattern.MatchString(workload.ID) || !userPattern.MatchString(workload.User) ||
		!filepath.IsAbs(workload.WorkDir) || filepath.Clean(workload.WorkDir) != workload.WorkDir ||
		workload.Command.validate() != nil {
		return ErrInvalid
	}
	if workload.Kind != WorkloadJob && workload.Kind != WorkloadService {
		return ErrInvalid
	}
	if workload.Kind == WorkloadJob && (workload.Service != nil || workload.Exposure != nil) {
		return ErrInvalid
	}
	if workload.Kind == WorkloadService {
		if workload.Service == nil || workload.Service.validate() != nil {
			return ErrInvalid
		}
	}
	for name, value := range workload.Environment {
		if !envPattern.MatchString(name) || !safeText(value, 4096) {
			return ErrInvalid
		}
		if _, secret := workload.SecretEnv[name]; secret {
			return ErrInvalid
		}
	}
	for name, reference := range workload.SecretEnv {
		if !envPattern.MatchString(name) || reference.validate() != nil {
			return ErrInvalid
		}
	}
	return nil
}

func (command Command) validate() error {
	if !filepath.IsAbs(command.Executable) || filepath.Clean(command.Executable) != command.Executable || !safeText(command.Executable, 4096) || len(command.Arguments) > 128 {
		return ErrInvalid
	}
	for _, argument := range command.Arguments {
		if !safeText(argument, 16<<10) {
			return ErrInvalid
		}
	}
	return nil
}

func (reference SecretReference) validate() error {
	if !safeToken(reference.Store, 64) || !safeToken(reference.Name, 256) || (reference.Revision != "" && !safeToken(reference.Revision, 128)) {
		return ErrInvalid
	}
	return nil
}

func (service Service) validate() error {
	if service.Port == 0 || !validHealthPath(service.HealthPath) || service.LogLines > 2000 {
		return ErrInvalid
	}
	return nil
}

func (worker Worker) Validate() error {
	if !idPattern.MatchString(worker.ID) || !validAccountID(worker.AccountID) || len(worker.Workloads) > 64 {
		return ErrInvalid
	}
	if worker.PublicIPv4 != "" {
		address, err := netip.ParseAddr(worker.PublicIPv4)
		if err != nil || !address.Is4() {
			return ErrInvalid
		}
	}
	seen := make(map[string]struct{}, len(worker.Workloads))
	for _, workload := range worker.Workloads {
		if workload.validate() != nil {
			return ErrInvalid
		}
		if _, duplicate := seen[workload.ID]; duplicate {
			return ErrInvalid
		}
		seen[workload.ID] = struct{}{}
	}
	return nil
}

func (exposure Exposure) exactText(workerID, workloadID string, port uint16) string {
	domain := ""
	if exposure.Domain != nil {
		domain = strings.Join([]string{string(exposure.Domain.Mode), exposure.Domain.ZoneID, canonicalHostname(exposure.Domain.Hostname), fmt.Sprint(exposure.Domain.TTL)}, "\x00")
	}
	return strings.Join([]string{"exposure-v1", workerID, workloadID, fmt.Sprint(port), canonicalHostname(exposure.Hostname), fmt.Sprint(exposure.TLS), domain}, "\x00")
}

func exposureDigest(workerID, workloadID string, port uint16, exposure Exposure) string {
	sum := sha256.Sum256([]byte(exposure.exactText(workerID, workloadID, port)))
	return hex.EncodeToString(sum[:])
}

// ExposureDigest returns the exact value that an exposure confirmation must
// bind. It performs the same structural validation as compilation.
func ExposureDigest(workerID string, workload Workload) (string, error) {
	if !idPattern.MatchString(workerID) || workload.validate() != nil || workload.Kind != WorkloadService || workload.Service == nil || workload.Exposure == nil || !workload.Exposure.Enabled || !validHostname(workload.Exposure.Hostname) {
		return "", ErrInvalid
	}
	if workload.Exposure.Domain != nil && workload.Exposure.Domain.validate(workload.Exposure.Hostname) != nil {
		return "", ErrInvalid
	}
	return exposureDigest(workerID, workload.ID, workload.Service.Port, *workload.Exposure), nil
}

func requireExact(confirmation ExactConfirmation, digest string) error {
	if strings.TrimSpace(confirmation.Proof) == "" || len(digest) != sha256.Size*2 || !strings.EqualFold(strings.TrimSpace(confirmation.Digest), digest) {
		return ErrNotConfirmed
	}
	return nil
}

func sortedKeys[V any](values map[string]V) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func safeText(value string, max int) bool {
	return value != "" && len(value) <= max && !strings.ContainsAny(value, "\x00\r\n")
}

func safeToken(value string, max int) bool {
	return safeText(value, max) && strings.TrimSpace(value) == value && !strings.ContainsAny(value, " \t")
}

func validHealthPath(value string) bool {
	return strings.HasPrefix(value, "/") && !strings.HasPrefix(value, "//") && safeText(value, 2048) && !strings.ContainsAny(value, " \t#")
}

func validAccountID(value string) bool {
	if len(value) != 12 {
		return false
	}
	for _, character := range value {
		if character < '0' || character > '9' {
			return false
		}
	}
	return true
}

func canonicalHostname(value string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(value)), ".")
}
