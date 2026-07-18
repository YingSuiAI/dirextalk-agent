package roothelper

import (
	"context"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloud/canonical"
	"github.com/YingSuiAI/dirextalk-agent/internal/installer"
	"github.com/YingSuiAI/dirextalk-agent/internal/knowledgeprofile"
)

const restartObservationSchemaV1 = "dirextalk.agent.root-helper-restart-observation/v1"

// LocalObserver derives both digests from root-observed state. The Worker
// cannot supply either digest. Artifact verification reads and hashes the
// installed root-owned files before the signed manifest digest is returned.
type LocalObserver struct {
	Artifacts           installer.ArtifactInspector
	State               InstalledStateInspector
	KnowledgeGeneration KnowledgeGenerationInspector
	Now                 func() time.Time
}

type InstalledStateInspector interface {
	VerifySecret(context.Context, installer.SecretV1) error
	VerifyVolume(context.Context, installer.VolumeV1) error
}

type KnowledgeGenerationInspector interface {
	CurrentGeneration(context.Context) (string, error)
}

func (observer LocalObserver) InstalledManifestDigest(ctx context.Context, delivery installer.DeliveryV1) (string, error) {
	if ctx == nil || observer.Artifacts == nil || installer.ValidateDeliveryTrust(delivery) != nil {
		return "", ErrInvalid
	}
	for _, artifact := range delivery.ArtifactManifest.Manifest.Artifacts {
		if err := observer.Artifacts.Verify(ctx, artifact); err != nil {
			return "", ErrUnavailable
		}
	}
	if (len(delivery.ArtifactManifest.Manifest.Secrets) != 0 ||
		len(delivery.ArtifactManifest.Manifest.Volumes) != 0) && observer.State == nil {
		return "", ErrUnavailable
	}
	for _, secret := range delivery.ArtifactManifest.Manifest.Secrets {
		if err := observer.State.VerifySecret(ctx, secret); err != nil {
			return "", ErrUnavailable
		}
	}
	for _, volume := range delivery.ArtifactManifest.Manifest.Volumes {
		if err := observer.State.VerifyVolume(ctx, volume); err != nil {
			return "", ErrUnavailable
		}
	}
	digest, err := canonical.Digest(delivery.ArtifactManifest.Manifest)
	if err != nil {
		return "", ErrInvalid
	}
	return digest, nil
}

func (observer LocalObserver) RestartObservationDigest(ctx context.Context, delivery installer.DeliveryV1,
	command installer.CommandV1) (string, error) {
	if ctx == nil || observer.Now == nil || installer.ValidateDeliveryTrust(delivery) != nil {
		return "", ErrInvalid
	}
	declared, found := declaredCommand(delivery, command.CommandID)
	if !found {
		return "", ErrUnauthorized
	}
	declaredDigest, err := canonical.Digest(declared)
	if err != nil {
		return "", ErrInvalid
	}
	commandDigest, err := canonical.Digest(command)
	if err != nil || commandDigest != declaredDigest {
		return "", ErrUnauthorized
	}
	switch command.CommandID {
	case knowledgeprofile.BackupCommandID, knowledgeprofile.RestoreCommandID,
		knowledgeprofile.UpgradeCommandID, knowledgeprofile.RollbackCommandID:
		if observer.KnowledgeGeneration == nil {
			return "", ErrUnavailable
		}
		generation, generationErr := observer.KnowledgeGeneration.CurrentGeneration(ctx)
		if generationErr != nil {
			return "", ErrUnavailable
		}
		return generation, nil
	}
	planDigest, err := canonical.Digest(delivery.SignedPlan.Plan)
	if err != nil {
		return "", ErrInvalid
	}
	observedAt := observer.Now().UTC()
	if observedAt.IsZero() {
		return "", ErrInvalid
	}
	return canonical.Digest(struct {
		SchemaVersion string `json:"schema_version"`
		TrustID       string `json:"trust_id"`
		PlanDigest    string `json:"plan_digest"`
		CommandID     string `json:"command_id"`
		CommandDigest string `json:"command_digest"`
		Status        string `json:"status"`
		ObservedAt    string `json:"observed_at"`
	}{
		SchemaVersion: restartObservationSchemaV1,
		TrustID:       delivery.TrustID,
		PlanDigest:    planDigest,
		CommandID:     command.CommandID,
		CommandDigest: commandDigest,
		Status:        "succeeded",
		ObservedAt:    observedAt.Format(time.RFC3339Nano),
	})
}

var _ Observer = LocalObserver{}
