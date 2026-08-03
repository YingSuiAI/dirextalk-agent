package taskinput

import (
	"errors"
	"regexp"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloud/canonical"
	"github.com/google/uuid"
)

const (
	InputSchemaV2 = "dirextalk.agent.task-input/v2"

	SourceEmpty            SourceKind = "empty"
	SourceGitHubRepository SourceKind = "github_repository"
	SourceWorkspaceArchive SourceKind = "workspace_archive"

	GitProviderGitHub = "github"
	GitHubHost        = "github.com"
)

var (
	ErrInvalidInput        = errors.New("invalid task input")
	gitNamePattern         = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,99}$`)
	gitObjectDigestPattern = regexp.MustCompile(
		`^(?:[0-9a-f]{40}|[0-9a-f]{64})$`,
	)
)

type SourceKind string

// GitRepositoryV1 identifies repository content without carrying a clone
// credential or caller-controlled URL. RepositoryID is the provider's stable
// numeric identity; Owner and Name are display and deterministic clone facts.
type GitRepositoryV1 struct {
	Provider      string `json:"provider"`
	Host          string `json:"host"`
	ConnectionID  string `json:"connection_id"`
	RepositoryID  string `json:"repository_id"`
	Owner         string `json:"owner"`
	Name          string `json:"name"`
	BaseCommitSHA string `json:"base_commit_sha"`
	BaseRef       string `json:"base_ref,omitempty"`
}

// InputV2 binds exactly one primary source to an owner, Task, and goal. The
// zero value of the unused source projection is included deliberately so the
// canonical document has one fixed shape.
type InputV2 struct {
	SchemaVersion string          `json:"schema_version"`
	InputID       string          `json:"input_id"`
	OwnerID       string          `json:"owner_id"`
	TaskID        string          `json:"task_id"`
	GoalDigest    string          `json:"goal_digest"`
	SourceDigest  string          `json:"source_digest"`
	SourceKind    SourceKind      `json:"source_kind"`
	Repository    GitRepositoryV1 `json:"repository"`
	Workspace     BindingV1       `json:"workspace"`
}

// BindingV2 is the de-secreted projection signed by a Team Plan and copied to
// the resulting execution. InputDigest authenticates the owner and Task facts
// that are intentionally not repeated in this projection.
type BindingV2 struct {
	SchemaVersion string          `json:"schema_version"`
	InputID       string          `json:"input_id"`
	InputDigest   string          `json:"input_digest"`
	SourceDigest  string          `json:"source_digest"`
	SourceKind    SourceKind      `json:"source_kind"`
	Repository    GitRepositoryV1 `json:"repository"`
	Workspace     BindingV1       `json:"workspace"`
}

func NewEmptyInput(
	ownerID,
	taskID,
	goalDigest string,
) (InputV2, error) {
	snapshot, err := NewEmpty(ownerID, taskID, goalDigest)
	if err != nil {
		return InputV2{}, ErrInvalidInput
	}
	workspace, err := snapshot.Binding()
	if err != nil {
		return InputV2{}, ErrInvalidInput
	}
	return newInput(
		ownerID,
		taskID,
		goalDigest,
		SourceEmpty,
		GitRepositoryV1{},
		workspace,
	)
}

func NewWorkspaceInput(
	ownerID,
	taskID,
	goalDigest,
	workspaceDigest string,
	workspaceSizeBytes int64,
) (InputV2, error) {
	snapshot, err := New(
		ownerID,
		taskID,
		goalDigest,
		workspaceDigest,
		workspaceSizeBytes,
	)
	if err != nil {
		return InputV2{}, ErrInvalidInput
	}
	workspace, err := snapshot.Binding()
	if err != nil {
		return InputV2{}, ErrInvalidInput
	}
	return newInput(
		ownerID,
		taskID,
		goalDigest,
		SourceWorkspaceArchive,
		GitRepositoryV1{},
		workspace,
	)
}

func NewGitHubInput(
	ownerID,
	taskID,
	goalDigest string,
	repository GitRepositoryV1,
) (InputV2, error) {
	return newInput(
		ownerID,
		taskID,
		goalDigest,
		SourceGitHubRepository,
		repository,
		BindingV1{},
	)
}

func newInput(
	ownerID,
	taskID,
	goalDigest string,
	sourceKind SourceKind,
	repository GitRepositoryV1,
	workspace BindingV1,
) (InputV2, error) {
	taskUUID, err := uuid.Parse(taskID)
	if err != nil ||
		taskUUID == uuid.Nil ||
		taskUUID.String() != taskID {
		return InputV2{}, ErrInvalidInput
	}
	sourceDigest, err := inputSourceDigest(
		sourceKind,
		repository,
		workspace,
	)
	if err != nil {
		return InputV2{}, err
	}
	input := InputV2{
		SchemaVersion: InputSchemaV2,
		InputID: uuid.NewSHA1(
			taskUUID,
			[]byte("task-input/v2\x00"+sourceDigest),
		).String(),
		OwnerID:      ownerID,
		TaskID:       taskID,
		GoalDigest:   goalDigest,
		SourceDigest: sourceDigest,
		SourceKind:   sourceKind,
		Repository:   repository,
		Workspace:    workspace,
	}
	if input.Validate() != nil {
		return InputV2{}, ErrInvalidInput
	}
	return input, nil
}

func (input InputV2) Validate() error {
	if input.SchemaVersion != InputSchemaV2 ||
		!canonicalUUID(input.InputID) ||
		!validOwnerID(input.OwnerID) ||
		!canonicalUUID(input.TaskID) ||
		!digestPattern.MatchString(input.GoalDigest) ||
		!digestPattern.MatchString(input.SourceDigest) ||
		!validInputSource(
			input.SourceKind,
			input.Repository,
			input.Workspace,
		) {
		return ErrInvalidInput
	}
	sourceDigest, err := inputSourceDigest(
		input.SourceKind,
		input.Repository,
		input.Workspace,
	)
	if err != nil {
		return ErrInvalidInput
	}
	if input.SourceDigest != sourceDigest {
		return ErrInvalidInput
	}
	expectedID := uuid.NewSHA1(
		uuid.MustParse(input.TaskID),
		[]byte("task-input/v2\x00"+sourceDigest),
	).String()
	if input.InputID != expectedID {
		return ErrInvalidInput
	}
	return nil
}

func (input InputV2) Digest() (string, error) {
	if input.Validate() != nil {
		return "", ErrInvalidInput
	}
	return canonical.Digest(input)
}

func (input InputV2) CanonicalCBOR() ([]byte, error) {
	if input.Validate() != nil {
		return nil, ErrInvalidInput
	}
	return canonical.Marshal(input)
}

func (input InputV2) Binding() (BindingV2, error) {
	digest, err := input.Digest()
	if err != nil {
		return BindingV2{}, err
	}
	binding := BindingV2{
		SchemaVersion: input.SchemaVersion,
		InputID:       input.InputID,
		InputDigest:   digest,
		SourceDigest:  input.SourceDigest,
		SourceKind:    input.SourceKind,
		Repository:    input.Repository,
		Workspace:     input.Workspace,
	}
	if binding.Validate() != nil {
		return BindingV2{}, ErrInvalidInput
	}
	return binding, nil
}

func (binding BindingV2) Validate() error {
	if binding.SchemaVersion != InputSchemaV2 ||
		!canonicalUUID(binding.InputID) ||
		!digestPattern.MatchString(binding.InputDigest) ||
		!digestPattern.MatchString(binding.SourceDigest) ||
		!validInputSource(
			binding.SourceKind,
			binding.Repository,
			binding.Workspace,
		) {
		return ErrInvalidInput
	}
	sourceDigest, err := inputSourceDigest(
		binding.SourceKind,
		binding.Repository,
		binding.Workspace,
	)
	if err != nil || sourceDigest != binding.SourceDigest {
		return ErrInvalidInput
	}
	return nil
}

func (binding BindingV2) Digest() (string, error) {
	if binding.Validate() != nil {
		return "", ErrInvalidInput
	}
	return canonical.Digest(binding)
}

// FromBinding restores the complete TaskInput at a trusted boundary and
// verifies that the signed digest binds the supplied owner, Task, and goal.
func FromBinding(
	ownerID,
	taskID,
	goalDigest string,
	binding BindingV2,
) (InputV2, error) {
	input := InputV2{
		SchemaVersion: binding.SchemaVersion,
		InputID:       binding.InputID,
		OwnerID:       ownerID,
		TaskID:        taskID,
		GoalDigest:    goalDigest,
		SourceDigest:  binding.SourceDigest,
		SourceKind:    binding.SourceKind,
		Repository:    binding.Repository,
		Workspace:     binding.Workspace,
	}
	digest, err := input.Digest()
	if err != nil || digest != binding.InputDigest {
		return InputV2{}, ErrInvalidInput
	}
	return input, nil
}

func (binding BindingV2) ValidateFor(
	ownerID,
	taskID,
	goalDigest string,
) error {
	_, err := FromBinding(ownerID, taskID, goalDigest, binding)
	return err
}

func (binding BindingV2) Matches(input InputV2) bool {
	actual, err := input.Binding()
	return err == nil && actual == binding
}

func IsEmptyInput(binding BindingV2) bool {
	return binding.Validate() == nil &&
		binding.SourceKind == SourceEmpty &&
		IsEmpty(binding.Workspace)
}

func inputSourceDigest(
	sourceKind SourceKind,
	repository GitRepositoryV1,
	workspace BindingV1,
) (string, error) {
	if !validInputSource(sourceKind, repository, workspace) {
		return "", ErrInvalidInput
	}
	return canonical.Digest(struct {
		SourceKind SourceKind      `json:"source_kind"`
		Repository GitRepositoryV1 `json:"repository"`
		Workspace  BindingV1       `json:"workspace"`
	}{
		SourceKind: sourceKind,
		Repository: repository,
		Workspace:  workspace,
	})
}

func validInputSource(
	sourceKind SourceKind,
	repository GitRepositoryV1,
	workspace BindingV1,
) bool {
	switch sourceKind {
	case SourceEmpty:
		return repository == (GitRepositoryV1{}) &&
			IsEmpty(workspace)
	case SourceWorkspaceArchive:
		return repository == (GitRepositoryV1{}) &&
			workspace.Validate() == nil
	case SourceGitHubRepository:
		return repository.Validate() == nil &&
			workspace == (BindingV1{})
	default:
		return false
	}
}

func (repository GitRepositoryV1) Validate() error {
	repositoryID, err := strconv.ParseUint(
		repository.RepositoryID,
		10,
		64,
	)
	if repository.Provider != GitProviderGitHub ||
		repository.Host != GitHubHost ||
		!canonicalUUID(repository.ConnectionID) ||
		err != nil ||
		repositoryID == 0 ||
		strconv.FormatUint(repositoryID, 10) !=
			repository.RepositoryID ||
		!gitNamePattern.MatchString(repository.Owner) ||
		!gitNamePattern.MatchString(repository.Name) ||
		!gitObjectDigestPattern.MatchString(
			repository.BaseCommitSHA,
		) ||
		!validGitRef(repository.BaseRef) {
		return ErrInvalidInput
	}
	return nil
}

func validGitRef(value string) bool {
	if value == "" {
		return true
	}
	if value != strings.TrimSpace(value) ||
		len(value) > 255 ||
		!utf8.ValidString(value) ||
		(!strings.HasPrefix(value, "refs/heads/") &&
			!strings.HasPrefix(value, "refs/tags/")) ||
		strings.Contains(value, "..") ||
		strings.Contains(value, "@{") ||
		strings.Contains(value, "\\") ||
		strings.Contains(value, "//") ||
		strings.HasSuffix(value, "/") ||
		strings.HasSuffix(value, ".") {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) ||
			unicode.IsSpace(character) {
			return false
		}
	}
	for _, component := range strings.Split(value, "/") {
		if component == "" ||
			component == "." ||
			component == ".." {
			return false
		}
	}
	return true
}
