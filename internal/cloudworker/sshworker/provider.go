package sshworker

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
)

type Provider struct {
	aws   AWS
	keys  KeyMaterial
	ssh   SSHExecutor
	store Store
	now   func() time.Time
}

func New(awsClient AWS, keys KeyMaterial, ssh SSHExecutor, store Store) (*Provider, error) {
	if awsClient == nil || keys == nil || ssh == nil || store == nil {
		return nil, ErrInvalid
	}
	return &Provider{aws: awsClient, keys: keys, ssh: ssh, store: store, now: time.Now}, nil
}

// Discover performs only live read operations. It is intentionally usable
// before the owner confirms a quote.
func (provider *Provider) Discover(ctx context.Context, credential CredentialIdentity) (Discovery, error) {
	if provider == nil || ctx == nil || credential.validate() != nil {
		return Discovery{}, ErrInvalid
	}
	if err := provider.aws.VerifyIdentity(ctx, credential); err != nil {
		return Discovery{}, err
	}
	discovery, err := provider.aws.Discover(ctx, credential)
	if err != nil {
		return Discovery{}, err
	}
	if discovery.validate() != nil {
		return Discovery{}, ErrInvalid
	}
	return discovery, nil
}

// Execute reconciles a single deterministic resource set. A retry after an
// unknown AWS response finds that set instead of creating another instance.
func (provider *Provider) Execute(ctx context.Context, request ExecuteRequest) (ExecutionResult, error) {
	if provider == nil || ctx == nil || request.validate() != nil {
		if request.Confirmation.validate() != nil {
			return ExecutionResult{}, ErrNotConfirmed
		}
		return ExecutionResult{}, ErrInvalid
	}
	if err := provider.aws.VerifyIdentity(ctx, request.Credential); err != nil {
		return ExecutionResult{}, err
	}
	record, exists, err := provider.store.Load(ctx, request.ExecutionID)
	if err != nil {
		return ExecutionResult{}, err
	}
	if !exists {
		record = Record{ExecutionID: request.ExecutionID, Credential: request.Credential,
			ConfirmationProof: request.Confirmation.Proof, Phase: PhaseProvisioning}
		if err := provider.save(ctx, &record); err != nil {
			return ExecutionResult{}, err
		}
	} else if record.Credential != request.Credential || record.ConfirmationProof != request.Confirmation.Proof {
		return ExecutionResult{}, ErrIdentity
	}
	if record.Phase == PhaseCompleted {
		return record.Result, nil
	}

	tags := resourceTags(request)
	if err := provider.provision(ctx, request, tags, &record); err != nil {
		record.Phase = PhaseCleaning
		if saveErr := provider.save(ctx, &record); saveErr != nil {
			return ExecutionResult{}, errors.Join(err, saveErr)
		}
		return ExecutionResult{}, errors.Join(err, provider.cleanupAfter(ctx, request, tags, &record))
	}
	var executionErr error
	if !record.Executed {
		record.Phase = PhaseRunning
		if err := provider.save(ctx, &record); err != nil {
			return ExecutionResult{}, err
		}
		result, err := provider.ssh.Execute(ctx, SSHRequest{
			ExecutionID: request.ExecutionID, Host: record.Instance.PublicIP, User: request.Discovery.SSHUser,
			PrivateKeyPath: provider.privateKeyPath(ctx, request.ExecutionID), WorkerScript: request.WorkerScript,
			WorkerScriptSHA256: request.WorkerScriptSHA256, WorkspacePath: request.WorkspacePath,
			MaxWorkspaceBytes: request.MaxWorkspaceBytes, MaxResultBytes: request.MaxResultBytes, Sink: request.Sink,
		})
		if err == nil {
			record.Result = result
			record.Executed = true
			if saveErr := provider.save(ctx, &record); saveErr != nil {
				return ExecutionResult{}, saveErr
			}
		} else {
			executionErr = err
		}
	}

	record.Phase = PhaseCleaning
	if err := provider.save(ctx, &record); err != nil {
		return ExecutionResult{}, errors.Join(executionErr, err)
	}
	cleanupErr := provider.cleanupAfter(ctx, request, tags, &record)
	if executionErr != nil || cleanupErr != nil {
		return record.Result, errors.Join(executionErr, cleanupErr)
	}
	record.Phase = PhaseCompleted
	if err := provider.save(ctx, &record); err != nil {
		return record.Result, err
	}
	return record.Result, nil
}

func (provider *Provider) cleanupAfter(ctx context.Context, request ExecuteRequest, tags ResourceTags, record *Record) error {
	cleanupContext, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Minute)
	defer cancel()
	return provider.cleanup(cleanupContext, request, tags, record)
}

func (provider *Provider) provision(ctx context.Context, request ExecuteRequest, tags ResourceTags, record *Record) error {
	keyName, securityGroupName, clientToken := resourceNames(request.ExecutionID)
	privateKeyPath, authorizedKey, err := provider.keys.Ensure(ctx, request.ExecutionID)
	if err != nil || strings.TrimSpace(privateKeyPath) == "" || len(authorizedKey) == 0 {
		return errors.Join(ErrInvalid, err)
	}
	keyPair, found, err := provider.aws.FindKeyPair(ctx, request.Credential, keyName, tags)
	if err != nil {
		return err
	}
	if !found {
		keyPair, err = provider.aws.ImportKeyPair(ctx, request.Credential, request.Confirmation, keyName, authorizedKey, tags)
		if err != nil {
			keyPair, found, _ = provider.aws.FindKeyPair(ctx, request.Credential, keyName, tags)
			if !found {
				return errors.Join(ErrAmbiguous, err)
			}
		}
	}
	record.KeyPair = keyPair
	if err := provider.save(ctx, record); err != nil {
		return err
	}

	securityGroup, found, err := provider.aws.FindSecurityGroup(ctx, request.Credential, securityGroupName, tags)
	if err != nil {
		return err
	}
	if !found {
		securityGroup, err = provider.aws.CreateSecurityGroup(ctx, request.Credential, request.Confirmation,
			securityGroupName, request.Discovery.VPCID, tags)
		if err != nil {
			securityGroup, found, _ = provider.aws.FindSecurityGroup(ctx, request.Credential, securityGroupName, tags)
			if !found {
				return errors.Join(ErrAmbiguous, err)
			}
		}
	}
	record.SecurityGroup = securityGroup
	if err := provider.save(ctx, record); err != nil {
		return err
	}
	if err := provider.aws.AuthorizeSSH(ctx, request.Credential, request.Confirmation, securityGroup, request.Discovery.PublicEgressCIDR); err != nil {
		return err
	}

	instance, found, err := provider.aws.FindInstance(ctx, request.Credential, clientToken, tags)
	if err != nil {
		return err
	}
	if !found {
		instance, err = provider.aws.RunInstance(ctx, request.Credential, request.Confirmation, LaunchRequest{
			ExecutionID: request.ExecutionID, ClientToken: clientToken, Discovery: request.Discovery,
			InstanceType: request.InstanceType, VolumeGiB: request.VolumeGiB,
			KeyName: keyPair.Name, SecurityGroupID: securityGroup.ID, Tags: tags,
		})
		if err != nil {
			instance, found, _ = provider.aws.FindInstance(ctx, request.Credential, clientToken, tags)
			if !found {
				return errors.Join(ErrAmbiguous, err)
			}
		}
	}
	record.Instance = instance
	if err := provider.save(ctx, record); err != nil {
		return err
	}
	return provider.waitRunning(ctx, request, tags, record)
}

func (provider *Provider) waitRunning(ctx context.Context, request ExecuteRequest, tags ResourceTags, record *Record) error {
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()
	for {
		instance, found, err := provider.aws.ObserveInstance(ctx, request.Credential, record.Instance.ID, tags)
		if err != nil {
			return err
		}
		if !found || instance.State == "terminated" || instance.State == "shutting-down" {
			return fmt.Errorf("worker instance ended before SSH: %w", ErrAmbiguous)
		}
		if instance.State == "running" && strings.TrimSpace(instance.PublicIP) != "" {
			record.Instance = instance
			return provider.save(ctx, record)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func (provider *Provider) cleanup(ctx context.Context, request ExecuteRequest, tags ResourceTags, record *Record) error {
	if !record.InstanceGone && record.Instance.ID != "" {
		instance, found, err := provider.aws.ObserveInstance(ctx, request.Credential, record.Instance.ID, tags)
		if err != nil {
			return err
		}
		if found && instance.State != "terminated" {
			if err := provider.aws.TerminateInstance(ctx, request.Credential, request.Confirmation, instance, tags); err != nil {
				instance, found, _ = provider.aws.ObserveInstance(ctx, request.Credential, record.Instance.ID, tags)
				if found && instance.State != "shutting-down" && instance.State != "terminated" {
					return errors.Join(ErrAmbiguous, err)
				}
			}
		}
		if err := provider.waitTerminated(ctx, request, tags, record.Instance.ID); err != nil {
			return err
		}
		record.InstanceGone = true
		if err := provider.save(ctx, record); err != nil {
			return err
		}
	}
	if !record.SecurityGroupGone && record.SecurityGroup.ID != "" {
		if err := provider.aws.DeleteSecurityGroup(ctx, request.Credential, request.Confirmation, record.SecurityGroup, tags); err != nil {
			_, found, _ := provider.aws.FindSecurityGroup(ctx, request.Credential, record.SecurityGroup.Name, tags)
			if found {
				return errors.Join(ErrAmbiguous, err)
			}
		}
		record.SecurityGroupGone = true
		if err := provider.save(ctx, record); err != nil {
			return err
		}
	}
	if !record.KeyPairGone && record.KeyPair.Name != "" {
		if err := provider.aws.DeleteKeyPair(ctx, request.Credential, request.Confirmation, record.KeyPair, tags); err != nil {
			_, found, _ := provider.aws.FindKeyPair(ctx, request.Credential, record.KeyPair.Name, tags)
			if found {
				return errors.Join(ErrAmbiguous, err)
			}
		}
		record.KeyPairGone = true
		if err := provider.save(ctx, record); err != nil {
			return err
		}
	}
	if err := provider.keys.Delete(ctx, request.ExecutionID); err != nil {
		return err
	}
	return nil
}

func (provider *Provider) waitTerminated(ctx context.Context, request ExecuteRequest, tags ResourceTags, instanceID string) error {
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()
	for {
		instance, found, err := provider.aws.ObserveInstance(ctx, request.Credential, instanceID, tags)
		if err != nil {
			return err
		}
		if !found || instance.State == "terminated" {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func (provider *Provider) save(ctx context.Context, record *Record) error {
	record.UpdatedAt = provider.now().UTC()
	return provider.store.Save(ctx, *record)
}

func (provider *Provider) privateKeyPath(ctx context.Context, executionID string) string {
	path, _, _ := provider.keys.Ensure(ctx, executionID)
	return path
}
