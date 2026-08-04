package coreextension

import (
	"context"
	"sync"
	"time"

	coreconfirmation "github.com/YingSuiAI/dirextalk-agent/internal/coreconfirmation"
)

// Repository is the persistence boundary. Implementations must retain version
// records immutably and replay an idempotent mutation byte-for-byte.
type Repository interface {
	Search(context.Context, SearchQuery) (Page, error)
	Get(context.Context, string) (Installation, error)
	List(context.Context, ListQuery) (InstallationPage, error)
	CreateMutation(context.Context, Mutation) (MutationResult, error)
	UpdateMutation(context.Context, Mutation, State) (MutationResult, error)
	RemoveMutation(context.Context, Mutation) (MutationResult, error)
	SetEnabled(context.Context, ToggleCommand) (Installation, error)
	RequestLifecycle(context.Context, LifecycleRequest) (MutationResult, error)
	ConfirmLifecycle(context.Context, coreconfirmation.ConfirmCommand) (coreconfirmation.Confirmation, error)
	ConsumeLifecycle(context.Context, coreconfirmation.ConsumeCommand) (coreconfirmation.Confirmation, error)
	CompleteLifecycle(context.Context, Completion) (Installation, error)
}
type ListQuery struct {
	Kind      Kind
	Source    Source
	State     State
	PageSize  int
	PageToken string
}
type InstallationPage struct {
	Installations []Installation `json:"installations"`
	NextPageToken string         `json:"next_page_token"`
}

type replayMutation struct {
	digest        string
	requestDigest string
	result        MutationResult
}
type MemoryRepository struct {
	mu               sync.Mutex
	now              func() time.Time
	items            map[string]Installation
	order            []string
	replay           map[string]replayMutation
	lifecycleReplay  map[string]lifecycleReplay
	completionReplay map[string]completionReplay
	toggleReplay     map[string]toggleReplay
	lifecycles       map[string]LifecycleRecord
	tasks            map[string]Task
	confirmations    map[string]coreconfirmation.Confirmation
	reservations     map[string]coreconfirmation.Reservation
	requestFailpoint func() error
	registry         *Registry
	artifactStore    ArtifactStore
	secretStore      SecretStore
}

func (r *MemoryRepository) nowUTC() time.Time {
	if r == nil || r.now == nil {
		return time.Now().UTC()
	}
	return r.now().UTC()
}

type completionReplay struct {
	digest string
	result Installation
}
type toggleReplay struct {
	digest string
	result Installation
}
type lifecycleReplay struct {
	digest       string
	result       MutationResult
	confirmation coreconfirmation.Confirmation
	task         Task
	err          error
}

func cloneConfirmationValue(v coreconfirmation.Confirmation) coreconfirmation.Confirmation {
	v.Binding.NetworkGrants = append([]string(nil), v.Binding.NetworkGrants...)
	v.Binding.SecretGrants = append([]coreconfirmation.SecretGrant(nil), v.Binding.SecretGrants...)
	return v
}

func NewMemoryRepository(now ...func() time.Time) *MemoryRepository {
	clock := time.Now
	if len(now) > 0 && now[0] != nil {
		clock = now[0]
	}
	return &MemoryRepository{now: clock, items: map[string]Installation{}, replay: map[string]replayMutation{}, lifecycleReplay: map[string]lifecycleReplay{}, completionReplay: map[string]completionReplay{}, toggleReplay: map[string]toggleReplay{}, lifecycles: map[string]LifecycleRecord{}, tasks: map[string]Task{}, confirmations: map[string]coreconfirmation.Confirmation{}, reservations: map[string]coreconfirmation.Reservation{}}
}
func (r *MemoryRepository) SetRequestFailpoint(f func() error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.requestFailpoint = f
}
func (r *MemoryRepository) SetSourceRegistry(reg *Registry) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.registry = reg
}
func (r *MemoryRepository) SetArtifactStore(store ArtifactStore) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.artifactStore = store
}
func (r *MemoryRepository) SetSecretStore(store SecretStore) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.secretStore = store
}
