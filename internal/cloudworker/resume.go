package cloudworker

import cloudaws "github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/aws"

// ControllerContext is the task-fenced, non-mutating plan/execution snapshot
// used for quote validation before confirmation consumption or state changes.
type ControllerContext struct {
	Plan      Plan
	Execution Execution
}

// ResumeContext is the immutable first-launch authority paired with the
// current CoreTask fence. A reclaimed controller observes or destroys the
// original AWS identity; it never stages again, authorizes a new runtime task,
// or issues a second create intent.
type ResumeContext struct {
	Plan                 Plan
	Execution            Execution
	InitialAuthorization LaunchAuthorization
	StagedManifest       StagedInputManifest
	Qualification        RuntimeQualification
	Material             RuntimeTaskMaterial
	// DispatchPrepared is true only after MarkDispatchPrepared committed the
	// immutable AWS identity to the Core execution. AWSRecord can already be
	// populated while this is false when the controller crashed after
	// Provider.Prepare persisted the intent but before the Core CAS.
	DispatchPrepared bool
	AWSRecord        cloudaws.LedgerRecord
	Resources        []Resource
	CurrentFence     RuntimeTaskFence
}

func (context *ResumeContext) Destroy() {
	if context == nil {
		return
	}
	context.Material.Destroy()
	*context = ResumeContext{}
}
