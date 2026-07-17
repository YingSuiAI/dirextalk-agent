package app

import (
	"context"
	"errors"
	"time"

	cloudapproval "github.com/YingSuiAI/dirextalk-agent/internal/cloud/approval"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloud/canonical"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudstatus"
	"github.com/YingSuiAI/dirextalk-agent/internal/pairing"
	"github.com/YingSuiAI/dirextalk-agent/internal/planning"
	"github.com/YingSuiAI/dirextalk-agent/internal/worker"
	"github.com/google/uuid"
)

type pairingFacts interface {
	LoadPlan(context.Context, string, string) (cloudapproval.PlanV1, error)
	ResolveRecipeDraft(context.Context, string, string, string) (planning.RecipeDraft, error)
}

type pairingCurrent interface {
	GetDeployment(context.Context, string, string) (cloudstatus.Deployment, error)
}

type pairingRuntime struct {
	agentInstanceID string
	sessions        *pairing.Service
	facts           pairingFacts
	current         pairingCurrent
}

func newPairingRuntime(agentInstanceID string, sessions *pairing.Service, facts pairingFacts, current pairingCurrent) (*pairingRuntime, error) {
	if !exactUUID(agentInstanceID) || sessions == nil || facts == nil || current == nil {
		return nil, pairing.ErrInvalid
	}
	return &pairingRuntime{agentInstanceID: agentInstanceID, sessions: sessions, facts: facts, current: current}, nil
}

func pairingIDForDeployment(deploymentID string) (string, error) {
	parsed, err := uuid.Parse(deploymentID)
	if err != nil || parsed == uuid.Nil || parsed.String() != deploymentID {
		return "", pairing.ErrInvalid
	}
	return uuid.NewSHA1(parsed, []byte("dirextalk-pairing/v1")).String(), nil
}

func (runtime *pairingRuntime) Ensure(ctx context.Context, ownerID, deploymentID string) (pairing.SessionV1, error) {
	if runtime == nil || ctx == nil {
		return pairing.SessionV1{}, pairing.ErrInvalid
	}
	pairingID, err := pairingIDForDeployment(deploymentID)
	if err != nil {
		return pairing.SessionV1{}, err
	}
	if current, getErr := runtime.sessions.Get(ctx, ownerID, pairingID); getErr == nil {
		if err := runtime.validateCurrentSession(ctx, current); err != nil {
			return pairing.SessionV1{}, err
		}
		return current, nil
	} else if !isPairingNotFound(getErr) {
		return pairing.SessionV1{}, getErr
	}
	deployment, draft, manifestDigest, err := runtime.currentFacts(ctx, ownerID, deploymentID)
	if err != nil {
		return pairing.SessionV1{}, err
	}
	contract := draft.Recipe.Pairing
	return runtime.sessions.Create(ctx, pairing.CreateCommand{
		OwnerID: ownerID, IdempotencyKey: uuid.NewSHA1(uuid.MustParse(pairingID), []byte("create")).String(), SessionID: pairingID,
		DeploymentID: deploymentID, DeploymentRevision: deployment.Worker.Revision,
		PlanID: deployment.PlanID, ConnectionID: deployment.ConnectionID,
		TaskID: deployment.Worker.TaskID, StepID: deployment.Worker.StepID, RecipeID: draft.RecipeID, RecipeDigest: draft.Digest,
		RecipeRevision: draft.Revision, ExecutionManifestDigest: manifestDigest,
		BeginCommand: contract.BeginCommandID, ResumeCommand: contract.ResumeCommandID,
		Timeout: time.Duration(contract.TimeoutSeconds) * time.Second,
	})
}

func (runtime *pairingRuntime) Retrieve(ctx context.Context, command pairing.RetrieveCommand) (pairing.SessionV1, pairing.PayloadResult, error) {
	if runtime == nil || ctx == nil {
		return pairing.SessionV1{}, pairing.PayloadResult{}, pairing.ErrInvalid
	}
	session, err := runtime.sessions.Get(ctx, command.OwnerID, command.SessionID)
	if err != nil || session.DeploymentID != command.DeploymentID {
		return pairing.SessionV1{}, pairing.PayloadResult{}, pairing.ErrRevisionConflict
	}
	if err := runtime.validateCurrentSession(ctx, session); err != nil {
		return pairing.SessionV1{}, pairing.PayloadResult{}, err
	}
	updated, payload, err := runtime.sessions.Retrieve(ctx, command)
	if err != nil {
		return pairing.SessionV1{}, pairing.PayloadResult{}, err
	}
	if err := runtime.validateCurrentSession(ctx, updated); err != nil {
		return pairing.SessionV1{}, pairing.PayloadResult{}, err
	}
	return updated, payload, nil
}

// Resume is the only approval-to-execution bridge. It rechecks the live
// deployment binding immediately before and after the durable session action,
// so a signed approval cannot dispatch against a superseded deployment.
func (runtime *pairingRuntime) Resume(ctx context.Context, command pairing.ResumeCommand) (pairing.SessionV1, error) {
	if runtime == nil || ctx == nil {
		return pairing.SessionV1{}, pairing.ErrInvalid
	}
	session, err := runtime.sessions.Get(ctx, command.OwnerID, command.SessionID)
	if err != nil || session.DeploymentID != command.DeploymentID {
		return pairing.SessionV1{}, pairing.ErrRevisionConflict
	}
	if err := runtime.validateCurrentSession(ctx, session); err != nil {
		return pairing.SessionV1{}, err
	}
	updated, err := runtime.sessions.Resume(ctx, command)
	if err != nil {
		return pairing.SessionV1{}, err
	}
	if err := runtime.validateCurrentSession(ctx, updated); err != nil {
		return pairing.SessionV1{}, err
	}
	return updated, nil
}

func (runtime *pairingRuntime) BuildPairingResumeScope(ctx context.Context, ownerID, pairingID string) (pairing.ResumeScopeV1, error) {
	if runtime == nil || ctx == nil {
		return pairing.ResumeScopeV1{}, pairing.ErrInvalid
	}
	session, err := runtime.sessions.Get(ctx, ownerID, pairingID)
	if err != nil || (session.Status != pairing.StatusWaitingUser && session.Status != pairing.StatusPayloadReady) {
		return pairing.ResumeScopeV1{}, pairing.ErrRevisionConflict
	}
	deployment, _, manifestDigest, err := runtime.currentFacts(ctx, ownerID, session.DeploymentID)
	if err != nil || deployment.PlanID != session.PlanID || deployment.ConnectionID != session.ConnectionID ||
		deployment.Worker.Revision != session.DeploymentRevision || deployment.Worker.TaskID != session.TaskID ||
		deployment.Worker.StepID != session.StepID || manifestDigest != session.ExecutionManifestDigest {
		return pairing.ResumeScopeV1{}, pairing.ErrRevisionConflict
	}
	return pairing.ResumeScopeV1{
		SchemaVersion: pairing.ResumeScopeSchemaV1, Intent: pairing.ResumeIntent, PairingID: session.SessionID, OwnerID: ownerID,
		DeploymentID: session.DeploymentID, DeploymentRevision: session.DeploymentRevision, PlanID: session.PlanID, ConnectionID: session.ConnectionID,
		TaskID: session.TaskID, StepID: session.StepID, RecipeDigest: session.RecipeDigest,
		ExecutionManifestDigest: session.ExecutionManifestDigest, PairingRevision: session.Revision,
	}, nil
}

func (runtime *pairingRuntime) validateCurrentSession(ctx context.Context, session pairing.SessionV1) error {
	deployment, _, manifestDigest, err := runtime.currentFacts(ctx, session.OwnerID, session.DeploymentID)
	if err != nil || deployment.PlanID != session.PlanID || deployment.ConnectionID != session.ConnectionID ||
		deployment.Worker.Revision != session.DeploymentRevision || deployment.Worker.TaskID != session.TaskID ||
		deployment.Worker.StepID != session.StepID || manifestDigest != session.ExecutionManifestDigest {
		return pairing.ErrRevisionConflict
	}
	return nil
}

func (runtime *pairingRuntime) currentFacts(ctx context.Context, ownerID, deploymentID string) (cloudstatus.Deployment, planning.RecipeDraft, string, error) {
	deployment, err := runtime.current.GetDeployment(ctx, ownerID, deploymentID)
	if err != nil || deployment.Worker.DeploymentID != deploymentID || deployment.Worker.OwnerID != ownerID ||
		deployment.Worker.State != worker.StateFinished || deployment.Worker.Outcome != worker.OutcomeSucceeded ||
		deployment.Worker.Revision < 1 || deployment.Worker.InstallerDelivery == nil || !exactUUID(deployment.PlanID) ||
		!exactUUID(deployment.ConnectionID) || !exactUUID(deployment.Worker.TaskID) || !exactUUID(deployment.Worker.StepID) {
		return cloudstatus.Deployment{}, planning.RecipeDraft{}, "", pairing.ErrRevisionConflict
	}
	plan, err := runtime.facts.LoadPlan(ctx, ownerID, deployment.PlanID)
	if err != nil || plan.Validate() != nil || plan.Status != cloudapproval.PlanApproved || plan.AgentInstanceID != runtime.agentInstanceID || plan.OwnerID != ownerID ||
		plan.PlanID != deployment.PlanID || plan.ConnectionID != deployment.ConnectionID {
		return cloudstatus.Deployment{}, planning.RecipeDraft{}, "", pairing.ErrRevisionConflict
	}
	draft, err := runtime.facts.ResolveRecipeDraft(ctx, ownerID, plan.Recipe.RecipeID, plan.Recipe.Digest)
	if err != nil || draft.Revision < 1 || draft.Recipe.Validate() != nil || draft.Recipe.Pairing == nil ||
		draft.RecipeID != plan.Recipe.RecipeID || draft.Digest != plan.Recipe.Digest ||
		!installerDeliveryDeclaresCommand(deployment.Worker.InstallerDelivery, draft.Recipe.Pairing.BeginCommandID) ||
		!installerDeliveryDeclaresCommand(deployment.Worker.InstallerDelivery, draft.Recipe.Pairing.ResumeCommandID) {
		return cloudstatus.Deployment{}, planning.RecipeDraft{}, "", pairing.ErrRevisionConflict
	}
	manifestDigest, err := canonical.Digest(deployment.Worker.InstallerDelivery.ArtifactManifest.Manifest)
	if err != nil {
		return cloudstatus.Deployment{}, planning.RecipeDraft{}, "", pairing.ErrRevisionConflict
	}
	return deployment, draft, manifestDigest, nil
}

func isPairingNotFound(err error) bool { return errors.Is(err, pairing.ErrNotFound) }

type pairingDeviceAdapter struct {
	devices cloudapproval.DeviceKeyRepository
}

func (adapter pairingDeviceAdapter) GetPairingDeviceKey(ctx context.Context, keyID string) (pairing.DeviceKeyV1, error) {
	if adapter.devices == nil {
		return pairing.DeviceKeyV1{}, pairing.ErrApprovalRequired
	}
	value, err := adapter.devices.GetDeviceKey(ctx, keyID)
	if err != nil {
		return pairing.DeviceKeyV1{}, err
	}
	return pairing.DeviceKeyV1{KeyID: value.KeyID, AgentInstanceID: value.AgentInstanceID, OwnerID: value.OwnerID,
		PublicKey: append([]byte(nil), value.PublicKey...), Active: value.Status == cloudapproval.DeviceKeyActive,
		NotBefore: value.NotBefore, ExpiresAt: value.ExpiresAt}, nil
}

func (adapter pairingDeviceAdapter) GetCurrentPairingDeviceKey(ctx context.Context, ownerID string, now time.Time) (pairing.DeviceKeyV1, error) {
	resolver, ok := adapter.devices.(interface {
		GetCurrentDeviceKey(context.Context, string, time.Time) (cloudapproval.DeviceKeyV1, error)
	})
	if !ok {
		return pairing.DeviceKeyV1{}, pairing.ErrApprovalRequired
	}
	value, err := resolver.GetCurrentDeviceKey(ctx, ownerID, now)
	if err != nil {
		return pairing.DeviceKeyV1{}, err
	}
	return adapter.GetPairingDeviceKey(ctx, value.KeyID)
}

var _ pairing.ResumeScopeBuilder = (*pairingRuntime)(nil)
var _ pairing.Resumer = (*pairingRuntime)(nil)
var _ pairing.DeviceRepository = pairingDeviceAdapter{}
var _ pairing.CurrentDeviceRepository = pairingDeviceAdapter{}
