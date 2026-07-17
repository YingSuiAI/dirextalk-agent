package roothelper

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"sync"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloud/canonical"
	"github.com/YingSuiAI/dirextalk-agent/internal/installer"
	"github.com/google/uuid"
)

var fenceDigestPattern = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)

const (
	DeliveryFenceSchemaV1    = "dirextalk.agent.root-helper-delivery-fence/v1"
	DefaultDeliveryFencePath = "/var/lib/dirextalk-installer/root-helper-delivery-fence.cbor"
	maxDeliveryFenceBytes    = 16 << 10
)

type DeliveryFenceValue struct {
	SchemaVersion   string `json:"schema_version"`
	DeploymentID    string `json:"deployment_id"`
	DeliveryID      string `json:"delivery_id"`
	BindingRevision int64  `json:"binding_revision"`
	PublicKeyDigest string `json:"public_key_digest"`
}

type DeliveryFence interface {
	Accept(context.Context, DeliveryFenceValue) error
	Match(context.Context, DeliveryFenceValue) error
}

type FileDeliveryFence struct {
	path                 string
	requireRootOwnership bool
	syncParent           func(string) error
	mu                   sync.Mutex
	current              *DeliveryFenceValue
}

func OpenRootOwnedDeliveryFence() (*FileDeliveryFence, error) {
	return openDeliveryFence(DefaultDeliveryFencePath, true)
}

func openDeliveryFence(name string, requireRootOwnership bool) (*FileDeliveryFence, error) {
	parentSync := syncDirectory
	if !requireRootOwnership {
		parentSync = func(string) error { return nil }
	}
	return openDeliveryFenceWithSync(name, requireRootOwnership, parentSync)
}

func openDeliveryFenceWithSync(name string, requireRootOwnership bool, parentSync func(string) error) (*FileDeliveryFence, error) {
	clean := filepath.Clean(name)
	if name == "" || !filepath.IsAbs(clean) || clean != name || parentSync == nil {
		return nil, ErrInvalid
	}
	if requireRootOwnership && validateRootOwnedRestartJournalParent(filepath.Dir(clean)) != nil {
		return nil, ErrUnavailable
	}
	fence := &FileDeliveryFence{path: clean, requireRootOwnership: requireRootOwnership, syncParent: parentSync}
	content, err := os.ReadFile(clean)
	if errors.Is(err, os.ErrNotExist) {
		return fence, nil
	}
	if err != nil || len(content) == 0 || len(content) > maxDeliveryFenceBytes {
		return nil, ErrUnavailable
	}
	defer clear(content)
	if requireRootOwnership && validateRootOwnedRestartJournalFile(clean) != nil {
		return nil, ErrUnavailable
	}
	var value DeliveryFenceValue
	if decodeFence(content, &value) != nil {
		return nil, ErrUnavailable
	}
	fence.current = &value
	return fence, nil
}

func (fence *FileDeliveryFence) Accept(ctx context.Context, value DeliveryFenceValue) error {
	if fence == nil || ctx == nil || validateFenceValue(value) != nil || ctx.Err() != nil {
		return ErrInvalid
	}
	fence.mu.Lock()
	defer fence.mu.Unlock()
	if fence.current != nil {
		current := *fence.current
		if value.DeploymentID != current.DeploymentID || value.BindingRevision < current.BindingRevision {
			return ErrUnauthorized
		}
		if value.BindingRevision == current.BindingRevision {
			if value != current {
				return ErrUnauthorized
			}
			return nil
		}
	}
	if err := fence.persist(ctx, value); err != nil {
		return err
	}
	cloned := value
	fence.current = &cloned
	return nil
}

func (fence *FileDeliveryFence) Match(ctx context.Context, value DeliveryFenceValue) error {
	if fence == nil || ctx == nil || validateFenceValue(value) != nil || ctx.Err() != nil {
		return ErrInvalid
	}
	fence.mu.Lock()
	defer fence.mu.Unlock()
	if fence.current == nil || *fence.current != value {
		return ErrUnauthorized
	}
	return nil
}

func (fence *FileDeliveryFence) persist(ctx context.Context, value DeliveryFenceValue) error {
	payload, err := canonical.Marshal(value)
	if err != nil || len(payload) > maxDeliveryFenceBytes {
		return ErrUnavailable
	}
	defer clear(payload)
	parent := filepath.Dir(fence.path)
	temporary, err := os.CreateTemp(parent, ".root-helper-fence.tmp-")
	if err != nil {
		return ErrUnavailable
	}
	temporaryName := temporary.Name()
	renamed := false
	defer func() {
		_ = temporary.Close()
		if !renamed {
			_ = os.Remove(temporaryName)
		}
	}()
	if configureDeliveryFenceTemporary(temporary, fence.requireRootOwnership) != nil {
		return ErrUnavailable
	}
	if _, err := temporary.Write(payload); err != nil || ctx.Err() != nil ||
		temporary.Sync() != nil || temporary.Close() != nil {
		return ErrUnavailable
	}
	if os.Rename(temporaryName, fence.path) != nil {
		return ErrUnavailable
	}
	renamed = true
	if fence.requireRootOwnership && validateRootOwnedRestartJournalFile(fence.path) != nil {
		return ErrUnavailable
	}
	if fence.syncParent(parent) != nil {
		return ErrUnavailable
	}
	return nil
}

func decodeFence(payload []byte, value *DeliveryFenceValue) error {
	if err := installer.DecodeCanonical(payload, value); err != nil {
		return err
	}
	return validateFenceValue(*value)
}

func validateFenceValue(value DeliveryFenceValue) error {
	deployment, deploymentErr := uuid.Parse(value.DeploymentID)
	delivery, deliveryErr := uuid.Parse(value.DeliveryID)
	if value.SchemaVersion != DeliveryFenceSchemaV1 ||
		deploymentErr != nil || deployment == uuid.Nil || deployment.String() != value.DeploymentID ||
		deliveryErr != nil || delivery == uuid.Nil || delivery.String() != value.DeliveryID ||
		value.BindingRevision < 1 || !fenceDigestPattern.MatchString(value.PublicKeyDigest) {
		return ErrInvalid
	}
	return nil
}
