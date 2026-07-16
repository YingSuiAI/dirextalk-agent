package workerami

import (
	"context"
	"errors"
	"time"
)

const (
	defaultPollInterval    = 10 * time.Second
	defaultCleanupTimeout  = 10 * time.Minute
	defaultDestroyTimeout  = 30 * time.Minute
	imageReconcileAttempts = 12
)

type Clock interface {
	Now() time.Time
	After(time.Duration) <-chan time.Time
}

type realClock struct{}

func (realClock) Now() time.Time                                { return time.Now().UTC() }
func (realClock) After(duration time.Duration) <-chan time.Time { return time.After(duration) }

type Option func(*Service) error

func WithClock(clock Clock) Option {
	return func(service *Service) error {
		if clock == nil {
			return ErrInvalidInput
		}
		service.clock = clock
		return nil
	}
}

func WithPollInterval(interval time.Duration) Option {
	return func(service *Service) error {
		if interval <= 0 || interval > time.Minute {
			return ErrInvalidInput
		}
		service.pollInterval = interval
		return nil
	}
}

func WithDestroyTimeout(timeout time.Duration) Option {
	return func(service *Service) error {
		if timeout < time.Minute || timeout > 2*time.Hour {
			return ErrInvalidInput
		}
		service.destroyTimeout = timeout
		return nil
	}
}

// Service publishes and manages only fixed Worker AMIs. It holds no AWS SDK
// client directly and cannot expand the Provider capability surface.
type Service struct {
	provider       Provider
	clock          Clock
	pollInterval   time.Duration
	cleanupTimeout time.Duration
	destroyTimeout time.Duration
}

type builderCleanupState struct {
	evidence BuilderCleanupEvidenceV1
	recorder func(BuilderCleanupEvidenceV1) error
}

func newBuilderCleanupState(validated validatedBuild) (*builderCleanupState, error) {
	state := &builderCleanupState{recorder: validated.request.RecordBuilderCleanupEvidence}
	if validated.request.ExistingBuilderCleanupEvidence == nil {
		return state, nil
	}
	evidence, err := validateBuilderCleanupEvidenceForBuild(*validated.request.ExistingBuilderCleanupEvidence, validated)
	if err != nil {
		return nil, err
	}
	state.evidence = evidence
	return state, nil
}

func (state *builderCleanupState) capture(observation BuilderObservationV1, validated validatedBuild) error {
	evidence, err := builderCleanupEvidenceFromObservation(observation, validated)
	if err != nil {
		return err
	}
	if state.evidence.SchemaVersion != "" && !equalBuilderCleanupEvidence(state.evidence, evidence) {
		return ErrOwnershipMismatch
	}
	state.evidence = evidence
	if state.recorder != nil && state.recorder(evidence) != nil {
		return ErrCleanupFailed
	}
	return nil
}

func equalBuilderCleanupEvidence(left, right BuilderCleanupEvidenceV1) bool {
	return left.SchemaVersion == right.SchemaVersion && left.AgentInstanceID == right.AgentInstanceID && left.AccountID == right.AccountID &&
		left.Region == right.Region && left.ReleaseManifestDigest == right.ReleaseManifestDigest && left.WorkerRootFSDigest == right.WorkerRootFSDigest &&
		left.WorkerBinaryDigest == right.WorkerBinaryDigest && left.BuildDigest == right.BuildDigest && left.BuilderInstanceID == right.BuilderInstanceID &&
		left.BuilderRootVolumeID == right.BuilderRootVolumeID && len(left.BuilderNetworkInterfaceIDs) == 1 && len(right.BuilderNetworkInterfaceIDs) == 1 &&
		left.BuilderNetworkInterfaceIDs[0] == right.BuilderNetworkInterfaceIDs[0]
}

func New(provider Provider, options ...Option) (*Service, error) {
	if provider == nil {
		return nil, ErrInvalidInput
	}
	service := &Service{
		provider: provider, clock: realClock{}, pollInterval: defaultPollInterval,
		cleanupTimeout: defaultCleanupTimeout, destroyTimeout: defaultDestroyTimeout,
	}
	for _, option := range options {
		if option == nil || option(service) != nil {
			return nil, ErrInvalidInput
		}
	}
	return service, nil
}

// Build validates the local bytes before its first provider call, reconciles
// deterministic cloud names before every mutation, and withholds the manifest
// unless image/snapshot read-back and temporary-resource cleanup both succeed.
func (service *Service) Build(ctx context.Context, request BuildRequestV1) (manifest ImageManifestV1, err error) {
	if ctx == nil || service == nil || service.provider == nil || service.clock == nil {
		return ImageManifestV1{}, ErrInvalidInput
	}
	validated, validationErr := validateBuildRequest(request)
	if validationErr != nil {
		return ImageManifestV1{}, validationErr
	}
	if request.RecordBuilderCleanupEvidence == nil {
		return ImageManifestV1{}, ErrInvalidInput
	}
	cleanupState, validationErr := newBuilderCleanupState(validated)
	if validationErr != nil {
		return ImageManifestV1{}, validationErr
	}
	archive, validationErr := openValidatedArchive(validated.request.RootFS)
	if validationErr != nil {
		return ImageManifestV1{}, validationErr
	}
	defer archive.Close()

	buildCtx, cancel := context.WithTimeout(ctx, validated.request.Timeout)
	defer cancel()
	if providerErr := service.provider.ValidateEnvironment(buildCtx, validated.environment); providerErr != nil {
		return ImageManifestV1{}, operationError(buildCtx)
	}

	var artifactVersion string
	var builderID string
	if cleanupState.evidence.SchemaVersion != "" {
		builderID = cleanupState.evidence.BuilderInstanceID
	}
	imageMutationAttempted := false
	defer func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.WithoutCancel(ctx), service.cleanupTimeout)
		defer cleanupCancel()
		cleanupErr := service.cleanup(cleanupCtx, validated, cleanupState, builderID, artifactVersion)
		if imageMutationAttempted && (err != nil || cleanupErr != nil) {
			if imageCleanupErr := service.cleanupBuildImage(cleanupCtx, validated); imageCleanupErr != nil {
				cleanupErr = errors.Join(cleanupErr, imageCleanupErr)
			}
		}
		if cleanupErr != nil {
			manifest = ImageManifestV1{}
			if err == nil {
				err = ErrCleanupFailed
			} else {
				err = errors.Join(err, ErrCleanupFailed)
			}
		}
	}()

	builderObservation, builderFound, providerErr := service.provider.FindBuilder(buildCtx, BuilderLookupV1{
		Name: validated.builderName, BuildDigest: validated.buildDigest,
		AccountID: validated.request.AccountID, Region: validated.request.Region,
	})
	if providerErr != nil {
		return ImageManifestV1{}, operationError(buildCtx)
	}
	if builderFound {
		if validationErr = validateBuilderObservation(builderObservation, validated); validationErr != nil {
			return ImageManifestV1{}, validationErr
		}
		builderID = builderObservation.InstanceID
	}

	artifactObservation, artifactFound, providerErr := service.provider.FindArtifact(buildCtx, validated.object)
	if providerErr != nil {
		return ImageManifestV1{}, operationError(buildCtx)
	}
	if artifactFound {
		if validationErr = validateArtifactVersion(artifactObservation); validationErr != nil {
			return ImageManifestV1{}, validationErr
		}
		artifactVersion = artifactObservation.VersionID
	}

	imageObservation, imageFound, providerErr := service.provider.FindImage(buildCtx, ImageLookupV1{
		Name: validated.imageName, AccountID: validated.request.AccountID, Region: validated.request.Region,
	})
	if providerErr != nil {
		return ImageManifestV1{}, operationError(buildCtx)
	}
	if imageFound {
		if validationErr = validateImageObservation(imageObservation, validated, false); validationErr != nil {
			return ImageManifestV1{}, validationErr
		}
		imageObservation, err = service.waitImageAvailable(buildCtx, validated, imageObservation)
		if err != nil {
			return ImageManifestV1{}, err
		}
		return service.readBackBuild(buildCtx, validated, imageObservation)
	}

	if builderFound && builderObservation.State == BuilderTerminated {
		return ImageManifestV1{}, ErrBuildFailed
	}
	if !builderFound {
		if !artifactFound {
			artifactObservation, providerErr = service.provider.PutArtifact(buildCtx, validated.object, archive)
			responseErr := validateArtifactVersion(artifactObservation)
			if providerErr != nil || responseErr != nil {
				recovered, found, recoverErr := service.provider.FindArtifact(buildCtx, validated.object)
				if recoverErr != nil {
					return ImageManifestV1{}, operationError(buildCtx)
				}
				if !found || validateArtifactVersion(recovered) != nil {
					if providerErr != nil {
						return ImageManifestV1{}, operationError(buildCtx)
					}
					return ImageManifestV1{}, ErrReadBackMismatch
				}
				artifactObservation = recovered
			}
			artifactVersion = artifactObservation.VersionID
		}
		presignedURL, presignErr := service.provider.PresignArtifactGET(buildCtx, validated.object, artifactVersion, validated.request.Timeout+10*time.Minute)
		if presignErr != nil {
			return ImageManifestV1{}, operationError(buildCtx)
		}
		if validationErr = validatePresignedURL(presignedURL, validated.object.Bucket, validated.request.Region); validationErr != nil {
			return ImageManifestV1{}, validationErr
		}
		userData, userDataErr := fixedUserData(presignedURL, validated.object, validated.request.RootFS.Manifest.BinaryDigest)
		if userDataErr != nil {
			return ImageManifestV1{}, userDataErr
		}
		launch := LaunchBuilderV1{
			Name: validated.builderName, ClientToken: validated.clientToken, BaseAMIID: validated.request.BaseAMIID,
			PrivateSubnetID: validated.request.PrivateSubnetID, ZeroIngressSGID: validated.request.ZeroIngressSGID,
			InstanceType: validated.request.BuilderInstanceType, RootDeviceName: validated.request.RootDeviceName,
			UserData: userData, Tags: cloneTags(validated.builderTags), AssociatePublicIPAddress: false,
			AttachIAMInstanceProfile: false, EncryptedRootVolumeRequired: true, DeleteRootVolumeOnTermination: true,
			IMDSv2Required: true, InstanceInitiatedStop: true,
		}
		builderObservation, providerErr = service.provider.LaunchBuilder(buildCtx, launch)
		responseErr := validateBuilderObservation(builderObservation, validated)
		if providerErr != nil || responseErr != nil {
			recovered, found, recoverErr := service.provider.FindBuilder(buildCtx, BuilderLookupV1{
				Name: validated.builderName, BuildDigest: validated.buildDigest,
				AccountID: validated.request.AccountID, Region: validated.request.Region,
			})
			if recoverErr != nil {
				return ImageManifestV1{}, operationError(buildCtx)
			}
			if !found || validateBuilderObservation(recovered, validated) != nil {
				if providerErr != nil {
					return ImageManifestV1{}, operationError(buildCtx)
				}
				return ImageManifestV1{}, ErrReadBackMismatch
			}
			builderObservation = recovered
		}
		builderID = builderObservation.InstanceID
	} else if builderObservation.State != BuilderStopped && !artifactFound {
		// A running builder whose exact versioned input disappeared cannot be
		// repaired by uploading a different version behind its existing URL.
		return ImageManifestV1{}, ErrBuildFailed
	}

	builderObservation, err = service.waitBuilderStopped(buildCtx, validated, builderObservation)
	if err != nil {
		return ImageManifestV1{}, err
	}
	if err = cleanupState.capture(builderObservation, validated); err != nil {
		return ImageManifestV1{}, err
	}

	imageObservation, imageFound, providerErr = service.provider.FindImage(buildCtx, ImageLookupV1{
		Name: validated.imageName, AccountID: validated.request.AccountID, Region: validated.request.Region,
	})
	if providerErr != nil {
		return ImageManifestV1{}, operationError(buildCtx)
	}
	if !imageFound {
		imageMutationAttempted = true
		imageObservation, providerErr = service.provider.CreateImage(buildCtx, CreateImageV1{
			Name: validated.imageName, BuilderInstanceID: builderObservation.InstanceID, RootDeviceName: validated.request.RootDeviceName,
			ImageTags: cloneTags(validated.artifactTags), SnapshotTags: cloneTags(validated.artifactTags),
			NoReboot: true, EncryptedRootRequired: true, SingleRootSnapshotOnly: true,
		})
		responseErr := validateImageObservation(imageObservation, validated, false)
		if providerErr != nil || responseErr != nil {
			recovered, found, recoverErr := service.reconcileImageByName(buildCtx, validated)
			if recoverErr != nil {
				return ImageManifestV1{}, operationError(buildCtx)
			}
			if !found || validateImageObservation(recovered, validated, false) != nil {
				if providerErr != nil {
					return ImageManifestV1{}, operationError(buildCtx)
				}
				return ImageManifestV1{}, ErrReadBackMismatch
			}
			imageObservation = recovered
		}
	}
	if validationErr = validateImageObservation(imageObservation, validated, false); validationErr != nil {
		return ImageManifestV1{}, validationErr
	}
	imageObservation, err = service.waitImageAvailable(buildCtx, validated, imageObservation)
	if err != nil {
		return ImageManifestV1{}, err
	}
	return service.readBackBuild(buildCtx, validated, imageObservation)
}

func (service *Service) readBackBuild(ctx context.Context, validated validatedBuild, observation ImageObservationV1) (ImageManifestV1, error) {
	manifest, err := imageManifestFromObservation(observation, validated)
	if err != nil {
		return ImageManifestV1{}, err
	}
	snapshot, found, providerErr := service.provider.ObserveSnapshot(ctx, manifest.RootSnapshotID)
	if providerErr != nil {
		return ImageManifestV1{}, operationError(ctx)
	}
	if !found || validateSnapshotForBuild(snapshot, manifest) != nil {
		return ImageManifestV1{}, ErrReadBackMismatch
	}
	return manifest, nil
}

func (service *Service) waitBuilderStopped(ctx context.Context, validated validatedBuild, observation BuilderObservationV1) (BuilderObservationV1, error) {
	for {
		if err := validateBuilderObservation(observation, validated); err != nil {
			return BuilderObservationV1{}, err
		}
		switch observation.State {
		case BuilderStopped:
			return observation, nil
		case BuilderFailed, BuilderTerminated:
			return BuilderObservationV1{}, ErrBuildFailed
		}
		if err := service.pause(ctx); err != nil {
			return BuilderObservationV1{}, err
		}
		var found bool
		var providerErr error
		observation, found, providerErr = service.provider.ObserveBuilder(ctx, observation.InstanceID)
		if providerErr != nil {
			return BuilderObservationV1{}, operationError(ctx)
		}
		if !found {
			return BuilderObservationV1{}, ErrReadBackMismatch
		}
	}
}

func (service *Service) waitImageAvailable(ctx context.Context, validated validatedBuild, observation ImageObservationV1) (ImageObservationV1, error) {
	for {
		if err := validateImageObservation(observation, validated, false); err != nil {
			return ImageObservationV1{}, err
		}
		if observation.State == ImageAvailable {
			return observation, nil
		}
		if err := service.pause(ctx); err != nil {
			return ImageObservationV1{}, err
		}
		var found bool
		var providerErr error
		observation, found, providerErr = service.provider.ObserveImage(ctx, observation.ImageID)
		if providerErr != nil {
			return ImageObservationV1{}, operationError(ctx)
		}
		if !found {
			return ImageObservationV1{}, ErrReadBackMismatch
		}
	}
}

// reconcileImageByName closes CreateImage's response-loss and eventual-
// visibility window with bounded, deterministic-name read-back.
func (service *Service) reconcileImageByName(ctx context.Context, validated validatedBuild) (ImageObservationV1, bool, error) {
	lookup := ImageLookupV1{Name: validated.imageName, AccountID: validated.request.AccountID, Region: validated.request.Region}
	for attempt := 0; attempt < imageReconcileAttempts; attempt++ {
		observation, found, providerErr := service.provider.FindImage(ctx, lookup)
		if providerErr != nil {
			return ImageObservationV1{}, false, operationError(ctx)
		}
		if found {
			return observation, true, nil
		}
		if attempt+1 < imageReconcileAttempts {
			if err := service.pause(ctx); err != nil {
				return ImageObservationV1{}, false, err
			}
		}
	}
	return ImageObservationV1{}, false, nil
}

func (service *Service) cleanup(ctx context.Context, validated validatedBuild, cleanupState *builderCleanupState, builderID, artifactVersion string) error {
	failed := false
	if builderID == "" {
		observation, found, providerErr := service.provider.FindBuilder(ctx, BuilderLookupV1{
			Name: validated.builderName, BuildDigest: validated.buildDigest,
			AccountID: validated.request.AccountID, Region: validated.request.Region,
		})
		if providerErr != nil {
			failed = true
		} else if found {
			if validateBuilderObservation(observation, validated) != nil {
				// A deterministic-name collision without the exact build binding
				// is not ours to terminate.
				failed = true
			} else {
				builderID = observation.InstanceID
			}
		}
	}
	if artifactVersion == "" {
		observation, found, providerErr := service.provider.FindArtifact(ctx, validated.object)
		if providerErr != nil {
			failed = true
		} else if found {
			if validateArtifactVersion(observation) != nil {
				// Never feed an unvalidated provider result to a destructive call.
				failed = true
			} else {
				artifactVersion = observation.VersionID
			}
		}
	}
	if builderID != "" && service.terminateBuilder(ctx, validated, cleanupState, builderID) != nil {
		failed = true
	}
	if artifactVersion != "" && service.deleteArtifact(ctx, validated.object, artifactVersion) != nil {
		failed = true
	}
	if failed {
		return ErrCleanupFailed
	}
	return nil
}

// cleanupBuildImage destroys only the exact deterministic image and its exact
// tagged encrypted root snapshot. It is used when this Build invocation called
// CreateImage but cannot durably return a publication manifest.
func (service *Service) cleanupBuildImage(ctx context.Context, validated validatedBuild) error {
	observation, found, err := service.reconcileImageByName(ctx, validated)
	if err != nil {
		return ErrCleanupFailed
	}
	if !found {
		// The bounded repeated name read-back is the only absence evidence
		// available when CreateImage returned no image ID.
		return nil
	}
	if validateImageObservation(observation, validated, false) != nil {
		return ErrCleanupFailed
	}
	manifest, err := cleanupManifestFromObservation(observation, validated)
	if err != nil {
		return ErrCleanupFailed
	}

	imageAbsent := false
	for attempt := 0; attempt < imageReconcileAttempts; attempt++ {
		_ = service.provider.DeregisterImage(ctx, manifest.ImageID)
		current, stillFound, providerErr := service.provider.ObserveImage(ctx, manifest.ImageID)
		if providerErr != nil {
			return ErrCleanupFailed
		}
		if !stillFound {
			imageAbsent = true
			break
		}
		if validateManifestImageObservation(current, manifest, false) != nil {
			return ErrCleanupFailed
		}
		if attempt+1 < imageReconcileAttempts && service.pause(ctx) != nil {
			return ErrCleanupFailed
		}
	}
	if !imageAbsent {
		return ErrCleanupFailed
	}

	snapshot, found, providerErr := service.provider.ObserveSnapshot(ctx, manifest.RootSnapshotID)
	if providerErr != nil {
		return ErrCleanupFailed
	}
	if !found {
		return nil
	}
	if validateSnapshotObservation(snapshot, manifest, false) != nil {
		return ErrCleanupFailed
	}
	for attempt := 0; attempt < imageReconcileAttempts; attempt++ {
		_ = service.provider.DeleteSnapshot(ctx, manifest.RootSnapshotID)
		current, stillFound, observeErr := service.provider.ObserveSnapshot(ctx, manifest.RootSnapshotID)
		if observeErr != nil {
			return ErrCleanupFailed
		}
		if !stillFound {
			return nil
		}
		if validateSnapshotObservation(current, manifest, false) != nil {
			return ErrCleanupFailed
		}
		if attempt+1 < imageReconcileAttempts && service.pause(ctx) != nil {
			return ErrCleanupFailed
		}
	}
	return ErrCleanupFailed
}

func cleanupManifestFromObservation(observation ImageObservationV1, expected validatedBuild) (ImageManifestV1, error) {
	if validateImageObservation(observation, expected, false) != nil {
		return ImageManifestV1{}, ErrOwnershipMismatch
	}
	return ImageManifestV1{
		SchemaVersion: ImageManifestSchemaV1, AgentInstanceID: expected.request.AgentInstanceID,
		ImageID: observation.ImageID, ImageName: observation.Name, RootSnapshotID: observation.RootSnapshotID,
		AccountID: observation.AccountID, Region: observation.Region, Architecture: observation.Architecture,
		BaseAMIID: expected.request.BaseAMIID, BaseAMIOwnerID: expected.request.BaseAMIOwnerID, RootDeviceName: observation.RootDeviceName,
		ReleaseManifestDigest: expected.request.ReleaseManifestDigest, WorkerRootFSDigest: expected.request.RootFS.Manifest.RootFSDigest,
		WorkerBinaryDigest: expected.request.RootFS.Manifest.BinaryDigest,
		CreatedAt:          observation.CreatedAt.UTC().Truncate(time.Second).Format(time.RFC3339),
	}.normalized()
}

func (service *Service) terminateBuilder(ctx context.Context, validated validatedBuild, cleanupState *builderCleanupState, builderID string) error {
	if cleanupState == nil {
		return ErrCleanupFailed
	}
	observation, found, providerErr := service.provider.ObserveBuilder(ctx, builderID)
	if providerErr != nil {
		return ErrCleanupFailed
	}
	if !found {
		if cleanupState.evidence.SchemaVersion == "" || cleanupState.evidence.BuilderInstanceID != builderID {
			return ErrCleanupFailed
		}
		if service.waitBuilderDependenciesAbsent(ctx, cleanupState.evidence) != nil {
			return ErrCleanupFailed
		}
		return nil
	}
	if validateBuilderObservation(observation, validated) != nil {
		return ErrCleanupFailed
	}
	if observation.State != BuilderTerminated {
		if err := cleanupState.capture(observation, validated); err != nil {
			return ErrCleanupFailed
		}
	} else if cleanupState.evidence.SchemaVersion == "" {
		if err := cleanupState.capture(observation, validated); err != nil {
			return ErrCleanupFailed
		}
	} else if cleanupState.evidence.BuilderInstanceID != builderID {
		return ErrCleanupFailed
	}
	if observation.State != BuilderTerminated {
		_ = service.provider.TerminateBuilder(ctx, builderID)
		for {
			observation, found, providerErr = service.provider.ObserveBuilder(ctx, builderID)
			if providerErr != nil {
				return ErrCleanupFailed
			}
			if !found || observation.State == BuilderTerminated {
				break
			}
			if validateBuilderObservation(observation, validated) != nil {
				return ErrCleanupFailed
			}
			if service.pause(ctx) != nil {
				return ErrCleanupFailed
			}
		}
	}
	if service.waitBuilderDependenciesAbsent(ctx, cleanupState.evidence) != nil {
		return ErrCleanupFailed
	}
	return nil
}

func (service *Service) waitBuilderDependenciesAbsent(ctx context.Context, evidence BuilderCleanupEvidenceV1) error {
	if evidence.Validate() != nil {
		return ErrCleanupFailed
	}
	for {
		found, providerErr := service.provider.ObserveBuilderVolume(ctx, evidence.BuilderRootVolumeID)
		if providerErr != nil {
			return ErrCleanupFailed
		}
		if !found {
			break
		}
		if service.pause(ctx) != nil {
			return ErrCleanupFailed
		}
	}
	for _, networkInterfaceID := range evidence.BuilderNetworkInterfaceIDs {
		for {
			found, providerErr := service.provider.ObserveBuilderNetworkInterface(ctx, networkInterfaceID)
			if providerErr != nil {
				return ErrCleanupFailed
			}
			if !found {
				break
			}
			if service.pause(ctx) != nil {
				return ErrCleanupFailed
			}
		}
	}
	return nil
}

func (service *Service) deleteArtifact(ctx context.Context, object ArtifactObjectV1, versionID string) error {
	_ = service.provider.DeleteArtifactVersion(ctx, object, versionID)
	for {
		found, providerErr := service.provider.ObserveArtifactVersion(ctx, object, versionID)
		if providerErr != nil {
			return ErrCleanupFailed
		}
		if !found {
			return nil
		}
		if service.pause(ctx) != nil {
			return ErrCleanupFailed
		}
	}
}

// VerifyBuilderCleanup performs fresh provider reads for the terminated
// builder, its root EBS volume, and every recorded network interface. A
// terminated instance is the EC2 terminal absence state; EBS and ENI IDs must
// no longer be returned. Provider errors and malformed IDs fail closed.
func (service *Service) VerifyBuilderCleanup(ctx context.Context, input BuilderCleanupEvidenceV1) error {
	if ctx == nil || service == nil || service.provider == nil {
		return ErrInvalidInput
	}
	evidence, err := input.normalized()
	if err != nil {
		return err
	}
	builder, found, providerErr := service.provider.ObserveBuilder(ctx, evidence.BuilderInstanceID)
	if providerErr != nil {
		return operationError(ctx)
	}
	if found && validateTerminatedBuilderForCleanup(builder, evidence) != nil {
		return ErrOwnershipMismatch
	}
	volumeFound, providerErr := service.provider.ObserveBuilderVolume(ctx, evidence.BuilderRootVolumeID)
	if providerErr != nil {
		return operationError(ctx)
	}
	if volumeFound {
		return ErrReadBackMismatch
	}
	for _, networkInterfaceID := range evidence.BuilderNetworkInterfaceIDs {
		networkFound, observeErr := service.provider.ObserveBuilderNetworkInterface(ctx, networkInterfaceID)
		if observeErr != nil {
			return operationError(ctx)
		}
		if networkFound {
			return ErrReadBackMismatch
		}
	}
	return nil
}

// Verify independently reads both image and snapshot and rejects any identity,
// ownership, encryption, state, timestamp, or attestation-tag mismatch.
func (service *Service) Verify(ctx context.Context, input ImageManifestV1) error {
	if ctx == nil || service == nil || service.provider == nil {
		return ErrInvalidInput
	}
	manifest, err := input.normalized()
	if err != nil {
		return err
	}
	image, found, providerErr := service.provider.ObserveImage(ctx, manifest.ImageID)
	if providerErr != nil {
		return operationError(ctx)
	}
	if !found || validateManifestImageObservation(image, manifest, true) != nil {
		return ErrReadBackMismatch
	}
	snapshot, found, providerErr := service.provider.ObserveSnapshot(ctx, manifest.RootSnapshotID)
	if providerErr != nil {
		return operationError(ctx)
	}
	if !found || validateSnapshotObservation(snapshot, manifest, true) != nil {
		return ErrReadBackMismatch
	}
	return nil
}

// Destroy verifies ownership before each destructive call, deregisters the
// image first, then deletes only the exact tagged root snapshot. Repeated calls
// succeed only after both resources independently read absent.
func (service *Service) Destroy(ctx context.Context, input ImageManifestV1) error {
	if ctx == nil || service == nil || service.provider == nil {
		return ErrInvalidInput
	}
	manifest, err := input.normalized()
	if err != nil {
		return err
	}
	destroyCtx, cancel := context.WithTimeout(ctx, service.destroyTimeout)
	defer cancel()
	image, found, providerErr := service.provider.ObserveImage(destroyCtx, manifest.ImageID)
	if providerErr != nil {
		return operationError(destroyCtx)
	}
	if found {
		if err = validateManifestImageObservation(image, manifest, true); err != nil {
			return ErrOwnershipMismatch
		}
		_ = service.provider.DeregisterImage(destroyCtx, manifest.ImageID)
		if err = service.waitImageAbsent(destroyCtx, manifest.ImageID); err != nil {
			return err
		}
	}

	snapshot, found, providerErr := service.provider.ObserveSnapshot(destroyCtx, manifest.RootSnapshotID)
	if providerErr != nil {
		return operationError(destroyCtx)
	}
	if found {
		if err = validateSnapshotObservation(snapshot, manifest, true); err != nil {
			return ErrOwnershipMismatch
		}
		_ = service.provider.DeleteSnapshot(destroyCtx, manifest.RootSnapshotID)
		if err = service.waitSnapshotAbsent(destroyCtx, manifest.RootSnapshotID); err != nil {
			return err
		}
	}
	return nil
}

func (service *Service) waitImageAbsent(ctx context.Context, imageID string) error {
	for {
		_, found, providerErr := service.provider.ObserveImage(ctx, imageID)
		if providerErr != nil {
			return operationError(ctx)
		}
		if !found {
			return nil
		}
		if err := service.pause(ctx); err != nil {
			return err
		}
	}
}

func (service *Service) waitSnapshotAbsent(ctx context.Context, snapshotID string) error {
	for {
		_, found, providerErr := service.provider.ObserveSnapshot(ctx, snapshotID)
		if providerErr != nil {
			return operationError(ctx)
		}
		if !found {
			return nil
		}
		if err := service.pause(ctx); err != nil {
			return err
		}
	}
}

func (service *Service) pause(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return operationError(ctx)
	case <-service.clock.After(service.pollInterval):
		return nil
	}
}

func operationError(ctx context.Context) error {
	if ctx != nil {
		switch ctx.Err() {
		case context.DeadlineExceeded:
			return ErrTimedOut
		case context.Canceled:
			return context.Canceled
		}
	}
	return ErrProviderOperation
}
