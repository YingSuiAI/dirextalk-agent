package worker

import (
	"bytes"
	"context"
	"time"

	cloudruntime "github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/runtime"
)

type WorkspacePreparer interface {
	Prepare(context.Context, ClaimedTask) (cloudruntime.Workspace, func(), error)
}

type PiProxy interface {
	URL() string
	AuthorizeRelay(string) error
}

type PiTaskExecutorConfig struct {
	Release                   cloudruntime.PiRelease
	Processes                 cloudruntime.ProcessRunner
	Outputs                   cloudruntime.OutputCollector
	Workspaces                WorkspacePreparer
	StateRoot                 string
	SearchPath                string
	PiProxy                   PiProxy
	ModelRelayTrustBundlePath string
	RuntimeGID                uint32
	Now                       func() time.Time
}

// PiTaskExecutor creates one sealed Pi runtime per claimed task so the claim's
// exact input manifest, isolated workspace, and short-lived model grant cannot
// leak into a later execution.
type PiTaskExecutor struct{ config PiTaskExecutorConfig }

func NewPiTaskExecutor(config PiTaskExecutorConfig) (*PiTaskExecutor, error) {
	if config.Processes == nil || config.Workspaces == nil ||
		config.PiProxy == nil || config.PiProxy.URL() != cloudruntime.PiLoopbackProxyURL ||
		config.ModelRelayTrustBundlePath != cloudruntime.PiModelRelayTrustBundlePath || config.RuntimeGID == 0 {
		return nil, ErrInvalid
	}
	if config.Now == nil {
		config.Now = func() time.Time { return time.Now().UTC() }
	}
	// NewPiExecutor performs the authoritative release/path checks after the
	// claim supplies its closed model tuple. Constructor validation here stays
	// limited to dependencies that do not vary per task.
	return &PiTaskExecutor{config: config}, nil
}

func (executor *PiTaskExecutor) Run(
	ctx context.Context,
	claimed ClaimedTask,
	progress func(ProgressPhase) error,
) (cloudruntime.Result, error) {
	if executor == nil || ctx == nil ||
		progress == nil || validateClaimedTask(claimed, claimed.Binding, executor.config.Now()) != nil {
		return cloudruntime.Result{}, ErrInvalid
	}
	workspace, cleanup, err := executor.config.Workspaces.Prepare(ctx, claimed)
	if err != nil {
		if cleanup != nil {
			cleanup()
		}
		return cloudruntime.Result{}, ErrUnavailable
	}
	resolver := &claimedInputResolver{
		manifest:  bytes.Clone(claimed.InputManifestJSON),
		workspace: workspace, cleanup: cleanup,
	}
	if err := progress(ProgressRunningPi); err != nil {
		resolver.destroy()
		return cloudruntime.Result{}, err
	}
	if err := executor.config.PiProxy.AuthorizeRelay(claimed.Task.ModelRelayBaseURL); err != nil {
		resolver.destroy()
		return cloudruntime.Result{}, ErrIdentityChanged
	}
	processes := executor.config.Processes
	if binder, ok := processes.(cloudruntime.ProcessBinder); ok {
		runtimeTaskSHA256, digestErr := claimed.Task.Digest()
		if digestErr != nil {
			resolver.destroy()
			return cloudruntime.Result{}, ErrInvalid
		}
		processes, err = binder.BindProcess(cloudruntime.ProcessBinding{
			ExecutionID: claimed.Binding.ExecutionID, TaskID: claimed.Binding.TaskID,
			Attempt: claimed.Binding.Attempt, LeaseEpoch: claimed.Binding.LeaseEpoch,
			RuntimeTaskSHA256: runtimeTaskSHA256,
		})
		if err != nil {
			resolver.destroy()
			return cloudruntime.Result{}, ErrInvalid
		}
	}
	credentialEnvironment := "OPENAI_API_KEY"
	if claimed.Task.ModelProvider == "deepseek" {
		credentialEnvironment = "DEEPSEEK_API_KEY"
	}
	runner, err := cloudruntime.NewPiExecutor(cloudruntime.PiConfig{
		Release: executor.config.Release,
		Models: []cloudruntime.QualifiedModel{{
			ProfileID: claimed.Task.ModelProfileID,
			Provider:  claimed.Task.ModelProvider, Model: claimed.Task.Model,
			Interface:             claimed.Task.ModelInterface,
			CredentialEnvironment: credentialEnvironment,
			RelayBaseURL:          claimed.Task.ModelRelayBaseURL,
			RelayEndpointSHA256:   claimed.Task.ModelRelayEndpointSHA256,
			MaximumOutputTokens:   claimed.Task.MaxOutputTokens,
		}},
		Inputs: resolver, Processes: processes,
		Outputs: executor.config.Outputs, StateRoot: executor.config.StateRoot,
		SearchPath: executor.config.SearchPath, Now: executor.config.Now,
		OutboundProxyURL:          executor.config.PiProxy.URL(),
		ModelRelayTrustBundlePath: executor.config.ModelRelayTrustBundlePath,
		RuntimeGID:                executor.config.RuntimeGID,
	})
	if err != nil {
		resolver.destroy()
		return cloudruntime.Result{}, ErrInvalid
	}
	return runner.Run(ctx, claimed.Task, claimed.ModelGrant)
}

type claimedInputResolver struct {
	manifest  []byte
	workspace cloudruntime.Workspace
	cleanup   func()
	used      bool
}

func (resolver *claimedInputResolver) Resolve(
	context.Context,
	cloudruntime.Task,
) (cloudruntime.Inputs, error) {
	if resolver == nil || resolver.used {
		return cloudruntime.Inputs{}, cloudruntime.ErrInvalid
	}
	resolver.used = true
	manifest := resolver.manifest
	resolver.manifest = nil
	cleanup := resolver.cleanup
	resolver.cleanup = nil
	return cloudruntime.Inputs{
		InputManifestJSON: manifest, Workspace: resolver.workspace, Cleanup: cleanup,
	}, nil
}

func (resolver *claimedInputResolver) destroy() {
	if resolver == nil {
		return
	}
	clear(resolver.manifest)
	if resolver.cleanup != nil {
		resolver.cleanup()
	}
	*resolver = claimedInputResolver{}
}

var _ TaskExecutor = (*PiTaskExecutor)(nil)
