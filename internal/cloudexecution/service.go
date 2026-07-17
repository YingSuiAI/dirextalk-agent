package cloudexecution

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"reflect"
	"strings"
	"time"

	cloudapproval "github.com/YingSuiAI/dirextalk-agent/internal/cloud/approval"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudapp"
	"github.com/YingSuiAI/dirextalk-agent/internal/installer"
	installerbootstrap "github.com/YingSuiAI/dirextalk-agent/internal/installer/bootstrap"
	"github.com/YingSuiAI/dirextalk-agent/internal/recipe"
	"github.com/YingSuiAI/dirextalk-agent/internal/resource"
	"github.com/YingSuiAI/dirextalk-agent/internal/security"
	"github.com/YingSuiAI/dirextalk-agent/internal/task"
	"github.com/YingSuiAI/dirextalk-agent/internal/worker"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/google/uuid"
)

type Service struct {
	agentInstanceID  string
	facts            FactReader
	connections      ConnectionReader
	recipes          RecipeResolver
	tasks            TaskCreator
	bundles          BundlePublisher
	workers          WorkerCreator
	bootstraps       BootstrapPublisher
	resourcePlans    ResourcePlanBuilder
	resources        ResourceProvisioner
	operations       Repository
	now              func() time.Time
	installerTrust   *installer.TrustIssuer
	artifactResolver InstallerArtifactResolver
	secretResolver   InstallerSecretResolver
}

func WithInstallerSecretResolver(resolver InstallerSecretResolver) ServiceOption {
	return func(service *Service) error {
		if service == nil || resolver == nil {
			return ErrInvalid
		}
		service.secretResolver = resolver
		return nil
	}
}

func WithInstallerArtifactResolver(resolver InstallerArtifactResolver) ServiceOption {
	return func(service *Service) error {
		if service == nil || resolver == nil {
			return ErrInvalid
		}
		service.artifactResolver = resolver
		return nil
	}
}

type ServiceOption func(*Service) error

func WithInstallerTrustIssuer(issuer *installer.TrustIssuer) ServiceOption {
	return func(service *Service) error {
		if service == nil || issuer == nil {
			return ErrInvalid
		}
		service.installerTrust = issuer
		return nil
	}
}

func NewService(
	agentInstanceID string,
	facts FactReader,
	connections ConnectionReader,
	recipes RecipeResolver,
	tasks TaskCreator,
	bundles BundlePublisher,
	workers WorkerCreator,
	bootstraps BootstrapPublisher,
	resourcePlans ResourcePlanBuilder,
	resources ResourceProvisioner,
	operations Repository,
	now func() time.Time,
	options ...ServiceOption,
) (*Service, error) {
	parsed, err := uuid.Parse(strings.TrimSpace(agentInstanceID))
	if err != nil || parsed == uuid.Nil || facts == nil || connections == nil || recipes == nil || tasks == nil || bundles == nil || workers == nil || bootstraps == nil || resourcePlans == nil || resources == nil || operations == nil || now == nil {
		return nil, ErrInvalid
	}
	service := &Service{
		agentInstanceID: parsed.String(), facts: facts, connections: connections, recipes: recipes, tasks: tasks,
		bundles: bundles, workers: workers, bootstraps: bootstraps, resourcePlans: resourcePlans,
		resources: resources, operations: operations, now: now,
	}
	for _, option := range options {
		if option == nil || option(service) != nil {
			return nil, ErrInvalid
		}
	}
	return service, nil
}

func (service *Service) LaunchApprovedPlan(ctx context.Context, caller cloudapp.MutationScope, request LaunchRequest) (Operation, error) {
	operation, plan, approval, boundRecipe, err := service.prepare(ctx, caller, request)
	if err != nil {
		return Operation{}, err
	}
	if operation.State == StateActive {
		return operation, nil
	}
	intent := operation.Intent
	connection, err := service.connections.LoadConnection(ctx, request.OwnerID, plan.ConnectionID)
	if err != nil || connection.Status != "active" || connection.OwnerID != request.OwnerID || connection.ConnectionID != plan.ConnectionID || connection.Region != plan.ResourceScope.Region {
		if err == nil {
			err = ErrNotReady
		}
		return service.fail(ctx, operation, err)
	}

	mutationScope := task.MutationScope{ClientID: operation.Caller.ClientID, CredentialID: operation.Caller.CredentialID}
	createdTask, err := service.tasks.Create(ctx, mutationScope, task.CreateCommand{
		IdempotencyKey: deterministicID(intent.OperationID, "task-create"), OwnerID: request.OwnerID,
		Goal: "Execute approved cloud recipe: " + boundRecipe.Name, Retention: taskRetention(plan.RetentionScope.Class),
		Steps: []task.StepDefinition{{StepID: intent.TaskStepID, Name: "Run approved recipe on exclusive cloud Worker", ExecutorKind: task.ExecutorCloudWorker}},
	})
	if err != nil {
		return service.fail(ctx, operation, err)
	}
	if operation.TaskID == "" || operation.State == StateIntent || operation.State == StateFailedRetriable {
		operation.TaskID = createdTask.TaskID
		operation.State = StateTaskReady
		operation, err = service.save(ctx, operation)
		if err != nil {
			return Operation{}, err
		}
	} else if operation.TaskID != createdTask.TaskID {
		return Operation{}, ErrRevisionConflict
	}

	delivery := operation.InstallerDelivery
	if delivery == nil {
		delivery, err = issueInstallerDelivery(boundRecipe, plan, approval, operation, createdTask.TaskID, service.installerTrust, service.now().UTC())
		if err != nil {
			return service.fail(ctx, operation, err)
		}
	}
	compiled, err := compileBundles(boundRecipe, delivery, service.now().UTC())
	if err != nil {
		return service.fail(ctx, operation, err)
	}
	defer clear(compiled.RecipeBytes)
	defer clear(compiled.ExecutionBytes)
	cleanupPending := false
	if err := service.resolveInstallerArtifacts(ctx, boundRecipe, &compiled); err != nil {
		return service.fail(ctx, operation, err)
	}
	if err := service.resolveInstallerSecrets(ctx, operation, plan, &compiled); err != nil {
		return service.fail(ctx, operation, err)
	}
	if len(compiled.InstallerArtifacts) != 0 {
		cleanupPending = true
		defer func() {
			if cleanupPending {
				_ = cleanupInstallerArtifacts(compiled.InstallerArtifacts)
			}
		}()
	}
	if operation.InstallerDelivery == nil && compiled.InstallerDelivery != nil {
		operation.InstallerDelivery = cloneDelivery(compiled.InstallerDelivery)
		operation.InstallerCommandIDs = append([]string(nil), compiled.InstallerCommandIDs...)
		operation.InstallerRootTrust = cloneInstallerRootTrust(compiled.InstallerRootTrust)
		operation, err = service.save(ctx, operation)
		if err != nil {
			return Operation{}, err
		}
	} else if !reflect.DeepEqual(operation.InstallerDelivery, compiled.InstallerDelivery) ||
		!reflect.DeepEqual(operation.InstallerCommandIDs, compiled.InstallerCommandIDs) || !reflect.DeepEqual(operation.InstallerRootTrust, compiled.InstallerRootTrust) {
		return Operation{}, ErrRevisionConflict
	}

	secretRefs := make([]string, 0, len(plan.SecretScope))
	for _, reference := range plan.SecretScope {
		secretRefs = append(secretRefs, reference.SecretRef)
	}
	published, err := service.bundles.PublishBundles(ctx, connection, intent.DeploymentID, compiled, secretRefs)
	cleanupErr := cleanupInstallerArtifacts(compiled.InstallerArtifacts)
	if cleanupErr == nil {
		cleanupPending = false
	}
	if cleanupErr != nil {
		return service.fail(ctx, operation, ErrUnavailable)
	}
	if err != nil || validatePublishedBundles(published, compiled, secretRefs) != nil {
		if err == nil {
			err = ErrUnavailable
		}
		return service.fail(ctx, operation, err)
	}
	if len(operation.InstallerArtifacts) == 0 && len(published.InstallerArtifacts) != 0 {
		operation.InstallerArtifacts = append([]installerbootstrap.ArtifactSourceV1(nil), published.InstallerArtifacts...)
	} else if !reflect.DeepEqual(operation.InstallerArtifacts, published.InstallerArtifacts) {
		return Operation{}, ErrRevisionConflict
	}
	if len(operation.InstallerSecrets) == 0 && len(published.InstallerSecrets) != 0 {
		operation.InstallerSecrets = append([]installerbootstrap.SecretSourceV1(nil), published.InstallerSecrets...)
	} else if !reflect.DeepEqual(operation.InstallerSecrets, published.InstallerSecrets) {
		return Operation{}, ErrRevisionConflict
	}
	if operation.State == StateTaskReady || operation.State == StateFailedRetriable || operation.RecipeBundle.S3Ref == "" {
		operation.RecipeBundle, operation.ExecutionBundle = published.Recipe, published.Execution
		operation.State = StateBundlesReady
		operation, err = service.save(ctx, operation)
		if err != nil {
			return Operation{}, err
		}
	}

	workerID := deterministicID(intent.DeploymentID, "worker")
	deployment, credential, err := service.workers.CreateDeployment(ctx, WorkerCreateMutation{
		ClientID: "internal.cloud-launcher", CredentialID: deterministicID(service.agentInstanceID, "worker-control"),
		IdempotencyKey: deterministicID(intent.OperationID, "worker-create"),
	}, worker.CreateDeploymentRequest{
		DeploymentID: intent.DeploymentID, OwnerID: request.OwnerID, TaskID: createdTask.TaskID, StepID: intent.TaskStepID,
		ControlPlaneEndpoint: request.ControlPlaneTarget, RecipeBundle: published.Recipe, ExecutionBundle: published.Execution,
		ExecutionTimeout:  time.Duration(boundRecipe.Install.TimeoutSeconds) * time.Second,
		InstallerDelivery: cloneDelivery(operation.InstallerDelivery), InstallerCommandIDs: append([]string(nil), operation.InstallerCommandIDs...),
		Access: published.Access, EnrollmentTTL: 15 * time.Minute,
	})
	if err != nil {
		return service.fail(ctx, operation, err)
	}
	if deployment.DeploymentID != intent.DeploymentID || deployment.TaskID != createdTask.TaskID || deployment.StepID != intent.TaskStepID {
		credential.Destroy()
		return service.fail(ctx, operation, ErrRevisionConflict)
	}
	if operation.State == StateBundlesReady || operation.State == StateFailedRetriable {
		operation.State = StateWorkerRegistered
		operation, err = service.save(ctx, operation)
		if err != nil {
			credential.Destroy()
			return Operation{}, err
		}
	}

	credentialBytes := credential.Reveal()
	credential.Destroy()
	bootstrap, bootstrapErr := service.bootstraps.PublishBootstrap(ctx, connection, BootstrapRequest{
		DeploymentID: intent.DeploymentID, WorkerID: workerID, ControlPlaneTarget: request.ControlPlaneTarget,
		Launch: published.Launch, EnrollmentCredential: credentialBytes, EnrollmentRevision: deployment.Revision,
	})
	clear(credentialBytes)
	if bootstrapErr != nil || validateBootstrap(bootstrap) != nil {
		if bootstrapErr == nil {
			bootstrapErr = ErrUnavailable
		}
		return service.fail(ctx, operation, bootstrapErr)
	}
	if operation.State == StateWorkerRegistered || operation.State == StateFailedRetriable || operation.Bootstrap.Reference == "" {
		operation.Bootstrap = bootstrap
		operation.State = StateBootstrapReady
		operation, err = service.save(ctx, operation)
		if err != nil {
			return Operation{}, err
		}
	}

	provisionSpecs, err := service.resourcePlans.Build(plan, connection, boundRecipe, operation)
	if err != nil || len(provisionSpecs) == 0 {
		if err == nil {
			err = ErrInvalid
		}
		return service.fail(ctx, operation, err)
	}
	if operation.State != StateProvisioning {
		operation.State = StateProvisioning
		operation, err = service.save(ctx, operation)
		if err != nil {
			return Operation{}, err
		}
	}
	resourceIDs := make([]string, 0, len(provisionSpecs))
	createAuthorization := resource.ProviderCreateAuthorization{
		ApprovalExpiresAt: approval.ExpiresAt,
		QuoteValidUntil:   approval.QuoteValidUntil,
	}
	for _, spec := range provisionSpecs {
		created, provisionErr := service.resources.Provision(ctx, connection, spec, createAuthorization)
		if provisionErr != nil {
			return service.fail(ctx, operation, provisionErr)
		}
		resourceIDs = append(resourceIDs, created.ResourceID)
	}
	operation.ResourceIDs = resourceIDs
	operation.State = StateActive
	operation.RedactedError = ""
	return service.save(ctx, operation)
}

func (service *Service) resolveInstallerArtifacts(ctx context.Context, value recipe.RecipeV1, compiled *CompiledBundles) error {
	if compiled == nil {
		return ErrInvalid
	}
	if len(compiled.InstallerArtifacts) == 0 {
		return nil
	}
	if service.artifactResolver == nil {
		return ErrNotReady
	}

	sources := make(map[string]recipe.SourceV1, len(value.Sources))
	for _, source := range value.Sources {
		if source.ID == "" {
			continue
		}
		if _, exists := sources[source.ID]; exists {
			return ErrInvalid
		}
		sources[source.ID] = source
	}
	for index := range compiled.InstallerArtifacts {
		artifact := &compiled.InstallerArtifacts[index]
		source, ok := sources[artifact.SourceID]
		if !ok || artifact.SourceID == "" || !source.Official || source.ArtifactDigest != artifact.SHA256 || source.URL == "" {
			_ = cleanupInstallerArtifacts(compiled.InstallerArtifacts)
			return ErrNotReady
		}
		content, err := service.artifactResolver.Resolve(ctx, InstallerArtifactResolveRequest{
			SourceID: artifact.SourceID, SourceURL: source.URL, Official: source.Official,
			SHA256: artifact.SHA256, SizeBytes: artifact.SizeBytes, TargetPath: artifact.TargetPath,
			RecipeDigest: artifact.RecipeDigest,
		})
		if err != nil || content == nil {
			_ = cleanupInstallerArtifacts(compiled.InstallerArtifacts)
			return ErrNotReady
		}
		artifact.Content = content
	}
	return nil
}

func cleanupInstallerArtifacts(artifacts []InstallerArtifactStagingInput) error {
	var failed bool
	for index := range artifacts {
		if artifacts[index].Content != nil && artifacts[index].Content.Cleanup() != nil {
			failed = true
		}
	}
	if failed {
		return ErrUnavailable
	}
	return nil
}

func (service *Service) resolveInstallerSecrets(ctx context.Context, operation Operation, plan cloudapproval.PlanV1, compiled *CompiledBundles) error {
	if compiled == nil {
		return ErrInvalid
	}
	if len(compiled.InstallerSecrets) == 0 {
		return nil
	}
	if service.secretResolver == nil || strings.TrimSpace(operation.SecretClientID) == "" {
		return ErrNotReady
	}
	purposes := make(map[string]string, len(plan.SecretScope))
	for _, scope := range plan.SecretScope {
		if _, duplicate := purposes[scope.SecretRef]; duplicate {
			return ErrInvalid
		}
		purposes[scope.SecretRef] = scope.Purpose
	}
	for index := range compiled.InstallerSecrets {
		secret := &compiled.InstallerSecrets[index]
		purpose, ok := purposes[secret.SecretRef]
		if !ok {
			return ErrNotReady
		}
		content, err := service.secretResolver.Resolve(ctx, InstallerSecretResolveRequest{
			CallerClientID: operation.SecretClientID, OwnerID: operation.Launch.OwnerID, PlanID: operation.Launch.PlanID,
			SlotID: secret.SlotID, Purpose: purpose, SecretRef: secret.SecretRef, SecretName: secret.SecretName,
			VersionID: secret.VersionID, TargetPath: secret.TargetPath, FileMode: secret.FileMode,
			OwnerUID: secret.OwnerUID, OwnerGID: secret.OwnerGID, RecipeDigest: secret.RecipeDigest,
		})
		if err != nil || content == nil {
			return ErrNotReady
		}
		secret.Content = content
	}
	return nil
}

// PrepareApprovedPlan performs all immutable approval/Recipe validation and
// writes the durable operation intent, but does not call Task, Worker, S3, or
// AWS resource mutations. A background Dispatcher can safely acknowledge the
// API request after this method and resume the operation after process restart.
func (service *Service) PrepareApprovedPlan(ctx context.Context, caller cloudapp.MutationScope, request LaunchRequest) (Operation, error) {
	operation, _, _, _, err := service.prepare(ctx, caller, request)
	return operation, err
}

func (service *Service) prepare(ctx context.Context, caller cloudapp.MutationScope, request LaunchRequest) (Operation, cloudapproval.PlanV1, cloudapproval.ApprovalV1, recipe.RecipeV1, error) {
	if service == nil || ctx == nil || caller.Validate() != nil || validateLaunchRequest(request) != nil {
		return Operation{}, cloudapproval.PlanV1{}, cloudapproval.ApprovalV1{}, recipe.RecipeV1{}, ErrInvalid
	}
	plan, err := service.facts.LoadPlan(ctx, request.OwnerID, request.PlanID)
	if err != nil {
		return Operation{}, cloudapproval.PlanV1{}, cloudapproval.ApprovalV1{}, recipe.RecipeV1{}, mapDependencyError(err)
	}
	approval, err := service.facts.LoadApproval(ctx, request.OwnerID, request.ApprovalID)
	if err != nil || !matchesDurableApproval(plan, approval) {
		return Operation{}, cloudapproval.PlanV1{}, cloudapproval.ApprovalV1{}, recipe.RecipeV1{}, ErrNotReady
	}
	boundRecipe, err := service.recipes.ResolveRecipe(ctx, request.OwnerID, plan.Recipe.RecipeID, plan.Recipe.Digest)
	if err != nil {
		return Operation{}, cloudapproval.PlanV1{}, cloudapproval.ApprovalV1{}, recipe.RecipeV1{}, mapDependencyError(err)
	}
	if err := validateExecutionRecipe(boundRecipe); err != nil {
		return Operation{}, cloudapproval.PlanV1{}, cloudapproval.ApprovalV1{}, recipe.RecipeV1{}, err
	}

	intent, err := service.intent(caller, request, plan, approval)
	if err != nil {
		return Operation{}, cloudapproval.PlanV1{}, cloudapproval.ApprovalV1{}, recipe.RecipeV1{}, err
	}
	operation, _, err := service.operations.Begin(ctx, intent)
	if err != nil {
		return Operation{}, cloudapproval.PlanV1{}, cloudapproval.ApprovalV1{}, recipe.RecipeV1{}, mapDependencyError(err)
	}
	return operation, plan, approval, boundRecipe, nil
}

func (service *Service) intent(caller cloudapp.MutationScope, request LaunchRequest, plan cloudapproval.PlanV1, approval cloudapproval.ApprovalV1) (Intent, error) {
	operationID := deterministicID(service.agentInstanceID, "cloud-launch\x00"+plan.PlanID)
	secretClientID := caller.ClientID
	// The external caller is authenticated at entry. Durable launch work uses a
	// stable internal scope so Service Key rotation cannot strand an approved,
	// billable resource without a recoverable controller.
	caller = cloudapp.MutationScope{ClientID: "internal.cloud-launcher", CredentialID: deterministicID(service.agentInstanceID, "cloud-launcher")}
	encoded, err := json.Marshal(struct {
		Request  LaunchRequest `json:"request"`
		PlanHash string        `json:"plan_hash"`
	}{request, approval.PlanHash})
	if err != nil {
		return Intent{}, ErrInvalid
	}
	now := service.now().UTC().Truncate(time.Microsecond)
	return Intent{
		OperationID: operationID, RequestHash: sha256.Sum256(encoded), Caller: caller, SecretClientID: secretClientID, Launch: request,
		ConnectionID: plan.ConnectionID, ApprovedPlanHash: approval.PlanHash, TaskStepID: deterministicID(operationID, "task-step"),
		DeploymentID: deterministicID(operationID, "deployment"), RecordedAt: now,
	}, nil
}

func (service *Service) save(ctx context.Context, operation Operation) (Operation, error) {
	operation.UpdatedAt = service.now().UTC().Truncate(time.Microsecond)
	stored, err := service.operations.Save(ctx, operation, operation.Revision)
	if err != nil {
		return Operation{}, mapDependencyError(err)
	}
	return stored, nil
}

func (service *Service) fail(ctx context.Context, operation Operation, cause error) (Operation, error) {
	operation.State = StateFailedRetriable
	operation.RedactedError = safeError(cause)
	if operation.Revision > 0 {
		if stored, err := service.save(ctx, operation); err == nil {
			operation = stored
		}
	}
	return operation, mapDependencyError(cause)
}

func validateLaunchRequest(request LaunchRequest) error {
	for _, value := range []string{request.IdempotencyKey, request.PlanID, request.ApprovalID} {
		parsed, err := uuid.Parse(strings.TrimSpace(value))
		if err != nil || parsed == uuid.Nil {
			return ErrInvalid
		}
	}
	if strings.TrimSpace(request.OwnerID) == "" || len(request.OwnerID) > 255 {
		return ErrInvalid
	}
	endpoint, err := url.Parse(strings.TrimSpace(request.ControlPlaneTarget))
	if err != nil || endpoint.Scheme != "grpcs" || endpoint.Host == "" || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" {
		return ErrInvalid
	}
	return nil
}

func matchesDurableApproval(plan cloudapproval.PlanV1, approval cloudapproval.ApprovalV1) bool {
	if plan.Status != cloudapproval.PlanApproved || approval.OwnerID != plan.OwnerID || approval.PlanID != plan.PlanID || approval.PlanRevision+1 != plan.Revision {
		return false
	}
	signedPlan := plan
	signedPlan.Status = cloudapproval.PlanReadyForConfirmation
	signedPlan.Revision = approval.PlanRevision
	validationTime := approval.ExpiresAt
	if approval.QuoteValidUntil.Before(validationTime) {
		validationTime = approval.QuoteValidUntil
	}
	return approval.ValidateAgainstPlan(signedPlan, validationTime.Add(-time.Nanosecond)) == nil
}

func validatePublishedBundles(published PublishedBundles, compiled CompiledBundles, secretRefs []string) error {
	if published.Recipe.Validate() != nil || published.Execution.Validate() != nil || validateLaunchArtifact(published.Launch) != nil || published.Access.Validate() != nil || len(published.SecretBindings) != len(secretRefs) || len(published.Access.SecretRefs) != len(secretRefs) {
		return ErrUnavailable
	}
	resolved := make(map[string]struct{}, len(published.Access.SecretRefs))
	for _, reference := range published.Access.SecretRefs {
		resolved[reference] = struct{}{}
	}
	for _, requested := range secretRefs {
		bound, ok := published.SecretBindings[requested]
		if !ok {
			return ErrUnavailable
		}
		if _, ok := resolved[bound]; !ok {
			return ErrUnavailable
		}
	}
	recipeDigest, executionDigest := sha256.Sum256(compiled.RecipeBytes), sha256.Sum256(compiled.ExecutionBytes)
	if published.Recipe.SHA256 != recipeDigest || published.Execution.SHA256 != executionDigest {
		return ErrUnavailable
	}
	if !reflect.DeepEqual(published.InstallerRootTrust, compiled.InstallerRootTrust) {
		return ErrUnavailable
	}
	if compiled.InstallerRootTrust == nil {
		if len(published.InstallerArtifacts) != 0 || len(published.InstallerSecrets) != 0 {
			return ErrUnavailable
		}
	} else {
		if len(published.InstallerArtifacts) == 0 {
			return ErrUnavailable
		}
		key, err := arn.Parse(published.InstallerArtifacts[0].KMSKeyARN)
		if err != nil || installerbootstrap.ValidateArtifactSources(*compiled.InstallerRootTrust, published.InstallerArtifacts,
			compiled.InstallerRootTrust.ArtifactManifest.Manifest.Binding.DeploymentID, installerbootstrap.InstanceIdentityV1{
				AccountID: key.AccountID, Region: key.Region, InstanceID: "i-00000000",
			}) != nil {
			return ErrUnavailable
		}
		if len(compiled.InstallerSecrets) != len(published.InstallerSecrets) {
			return ErrUnavailable
		}
		if len(published.InstallerSecrets) != 0 {
			secretKey, secretErr := arn.Parse(published.InstallerSecrets[0].KMSKeyARN)
			if secretErr != nil || installerbootstrap.ValidateSecretSources(*compiled.InstallerRootTrust, published.InstallerSecrets,
				compiled.InstallerRootTrust.ArtifactManifest.Manifest.Binding.DeploymentID, installerbootstrap.InstanceIdentityV1{
					AccountID: secretKey.AccountID, Region: secretKey.Region, InstanceID: "i-00000000",
				}) != nil {
				return ErrUnavailable
			}
		}
	}
	return nil
}

func cloneInstallerRootTrust(value *InstallerRootTrustV1) *InstallerRootTrustV1 {
	if value == nil {
		return nil
	}
	clone := *value
	clone.PublicKey = append([]byte(nil), value.PublicKey...)
	clone.ConfigCBOR = append([]byte(nil), value.ConfigCBOR...)
	clone.ArtifactManifest.Manifest.Artifacts = append([]installer.ArtifactV1(nil), value.ArtifactManifest.Manifest.Artifacts...)
	clone.ArtifactManifest.Signature = append([]byte(nil), value.ArtifactManifest.Signature...)
	return &clone
}

func validateBootstrap(value BootstrapArtifact) error {
	if validateLaunchArtifact(value) != nil || strings.TrimSpace(value.EnrollmentMaterialRef) == "" {
		return ErrUnavailable
	}
	return nil
}

func validateLaunchArtifact(value BootstrapArtifact) error {
	parsed, err := url.Parse(strings.TrimSpace(value.Reference))
	var zero [sha256.Size]byte
	if err != nil || parsed.Scheme != "s3" || parsed.Host == "" || parsed.Path == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || value.SHA256 == zero {
		return ErrUnavailable
	}
	return nil
}

func taskRetention(value cloudapproval.RetentionClass) task.RetentionPolicy {
	if value == cloudapproval.RetentionManaged {
		return task.RetentionManaged
	}
	return task.RetentionEphemeralAutoDestroy
}

func deterministicID(namespace, label string) string {
	return uuid.NewSHA1(uuid.MustParse(namespace), []byte(label)).String()
}

func safeError(err error) string {
	if err == nil {
		return ""
	}
	value := security.RedactText(strings.TrimSpace(err.Error()))
	if len(value) > 512 {
		value = value[:512]
	}
	return value
}

func mapDependencyError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, ErrInvalid), errors.Is(err, ErrUnsupportedRecipe):
		return err
	case errors.Is(err, ErrNotReady):
		return ErrNotReady
	case errors.Is(err, cloudapp.ErrNotFound), errors.Is(err, task.ErrNotFound), errors.Is(err, worker.ErrNotFound), errors.Is(err, resource.ErrNotFound), errors.Is(err, resource.ErrCreateAuthorizationExpired):
		return ErrNotReady
	case errors.Is(err, cloudapp.ErrRevisionConflict), errors.Is(err, task.ErrRevisionConflict), errors.Is(err, worker.ErrRevisionConflict), errors.Is(err, resource.ErrRevisionConflict):
		return ErrRevisionConflict
	default:
		return fmt.Errorf("%w: %s", ErrUnavailable, safeError(err))
	}
}
