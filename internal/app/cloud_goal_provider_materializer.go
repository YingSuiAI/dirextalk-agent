package app

import (
	"context"
	"crypto/sha256"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/awsprovider"
	cloudapproval "github.com/YingSuiAI/dirextalk-agent/internal/cloud/approval"
	cloudquote "github.com/YingSuiAI/dirextalk-agent/internal/cloud/quote"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudapp"
	"github.com/YingSuiAI/dirextalk-agent/internal/planning"
	"github.com/YingSuiAI/dirextalk-agent/internal/recipe"
	"github.com/YingSuiAI/dirextalk-agent/internal/secretbootstrap"
	"github.com/YingSuiAI/dirextalk-agent/internal/task"
	"github.com/google/uuid"
)

const (
	cloudGoalRuntimeHours             = uint32(730)
	cloudGoalEndpointDataMiB          = uint64(1)
	cloudGoalDestroyGrace             = uint32(30 * 60)
	cloudGoalMaximumLifetime          = uint64(24 * 60 * 60)
	cloudGoalVolumeIOPS               = uint32(3000)
	cloudGoalVolumeThroughput         = uint32(125)
	cloudGoalS3EndpointKey            = "worker-s3-gateway"
	cloudGoalSecretsEndpointKey       = "worker-secretsmanager-interface"
	cloudGoalWorkerControlEndpointKey = "worker-worker-control-interface"
)

type cloudGoalConnectionLoader interface {
	LoadConnection(context.Context, string, string) (cloudapp.Connection, error)
}

type cloudGoalPlacementPlanner interface {
	ValidateConnection(cloudapp.Connection, string, string) error
	Resolve(context.Context, cloudapp.Connection, cloudapp.ActivePlacementRequestV1) (awsprovider.PlacementV1, error)
}

type cloudGoalQuotePlanner interface {
	Quote(context.Context, cloudapp.Connection, cloudquote.RequestV1, recipe.RecipeV1) (cloudquote.QuoteV1, error)
}

type cloudGoalProviderFacts interface {
	PersistQuote(context.Context, cloudapp.MutationScope, string, [sha256.Size]byte, cloudquote.QuoteV1) (cloudquote.QuoteV1, error)
	LoadQuote(context.Context, string, string) (cloudquote.QuoteV1, error)
	PersistCloudGoalPlan(context.Context, cloudapp.MutationScope, string, string, cloudapproval.PlanV1) (cloudapproval.PlanV1, error)
	LoadPlan(context.Context, string, string) (cloudapproval.PlanV1, error)
}

type cloudGoalSecretSessionLocator interface {
	FindUploaded(context.Context, string, secretbootstrap.BindingV1) (secretbootstrap.SessionV1, error)
}

var ErrCloudGoalSecretsNotReady = planning.ErrCloudGoalSecretsNotReady

// cloudGoalProviderPlanMaterializer is deliberately not an AWS mutation
// coordinator. Its only provider operations are active-Connection placement
// discovery and price read-back; PostgreSQL remains the Quote/Plan fact source.
type cloudGoalProviderPlanMaterializer struct {
	agentInstanceID          string
	workerControlEndpoint    string
	workerControlServiceName string
	connections              cloudGoalConnectionLoader
	placements               cloudGoalPlacementPlanner
	quotes                   cloudGoalQuotePlanner
	facts                    cloudGoalProviderFacts
	secrets                  cloudGoalSecretSessionLocator
	now                      func() time.Time
}

func newCloudGoalProviderPlanMaterializer(
	agentInstanceID string,
	connections cloudGoalConnectionLoader,
	placements cloudGoalPlacementPlanner,
	quotes cloudGoalQuotePlanner,
	facts cloudGoalProviderFacts,
	secrets cloudGoalSecretSessionLocator,
	workerControlEndpoint, workerControlServiceName string,
	now func() time.Time,
) (*cloudGoalProviderPlanMaterializer, error) {
	parsed, err := uuid.Parse(strings.TrimSpace(agentInstanceID))
	if err != nil || parsed == uuid.Nil || parsed.String() != agentInstanceID || connections == nil || placements == nil || quotes == nil || facts == nil || secrets == nil || now == nil ||
		cloudquote.ValidateWorkerControlPrivateLink(workerControlEndpoint, workerControlServiceName) != nil {
		return nil, cloudapp.ErrInvalid
	}
	return &cloudGoalProviderPlanMaterializer{
		agentInstanceID: agentInstanceID, workerControlEndpoint: workerControlEndpoint, workerControlServiceName: workerControlServiceName,
		connections: connections, placements: placements, quotes: quotes, facts: facts, secrets: secrets, now: now,
	}, nil
}

func (materializer *cloudGoalProviderPlanMaterializer) MaterializeProviderPlan(
	ctx context.Context,
	request planning.ProviderPlanMaterializationRequest,
) (planning.ProviderPlanMaterialization, error) {
	if materializer == nil || ctx == nil {
		return planning.ProviderPlanMaterialization{}, cloudapp.ErrInvalid
	}
	now := materializer.now().UTC()
	if now.IsZero() || request.AgentInstanceID != materializer.agentInstanceID || planning.ValidateProviderPlanMaterializationRequest(request, now) != nil {
		return planning.ProviderPlanMaterialization{}, cloudapp.ErrInvalid
	}
	caller := cloudapp.MutationScope{ClientID: request.Stage.Caller.ClientID, CredentialID: request.Stage.Caller.CredentialID}
	if caller.Validate() != nil {
		return planning.ProviderPlanMaterialization{}, cloudapp.ErrInvalid
	}
	secretScope, err := materializer.resolveSecretScope(ctx, caller.ClientID, request)
	if err != nil {
		return planning.ProviderPlanMaterialization{}, err
	}
	connection, err := materializer.connections.LoadConnection(ctx, request.Stage.Binding.OwnerID, request.Stage.Binding.ConnectionID)
	if err != nil || materializer.placements.ValidateConnection(connection, request.Stage.Binding.OwnerID, request.Stage.Binding.ConnectionID) != nil {
		return planning.ProviderPlanMaterialization{}, cloudapp.ErrUnavailable
	}

	quoted, err := materializer.loadOrCreateQuote(ctx, caller, connection, request, secretScope, now)
	if err != nil {
		return planning.ProviderPlanMaterialization{}, err
	}
	plan, err := materializer.loadOrCreatePlan(ctx, caller, connection, request, quoted, now)
	if err != nil {
		return planning.ProviderPlanMaterialization{}, err
	}
	return planning.ProviderPlanMaterialization{Quote: quoted, Plan: plan}, nil
}

func (materializer *cloudGoalProviderPlanMaterializer) loadOrCreateQuote(
	ctx context.Context,
	caller cloudapp.MutationScope,
	connection cloudapp.Connection,
	request planning.ProviderPlanMaterializationRequest,
	secretScope []cloudquote.SecretScopeV1,
	now time.Time,
) (cloudquote.QuoteV1, error) {
	quoted, err := materializer.facts.LoadQuote(ctx, request.Stage.Binding.OwnerID, request.QuoteID)
	if err == nil {
		if validateCloudGoalProviderQuote(materializer.agentInstanceID, materializer.workerControlEndpoint, materializer.workerControlServiceName, connection, request, secretScope, quoted, now) != nil {
			return cloudquote.QuoteV1{}, cloudapp.ErrInvalid
		}
		return quoted, nil
	}
	if !errors.Is(err, cloudapp.ErrNotFound) {
		return cloudquote.QuoteV1{}, cloudapp.ErrUnavailable
	}

	requirements, err := cloudGoalPlacementRequirements(request.Draft.Recipe.Requirements, request.Candidates)
	if err != nil {
		return cloudquote.QuoteV1{}, cloudapp.ErrInvalid
	}
	placement, err := materializer.placements.Resolve(ctx, connection, cloudapp.ActivePlacementRequestV1{
		OwnerID: request.Stage.Binding.OwnerID, ConnectionID: request.Stage.Binding.ConnectionID,
		Placement: awsprovider.PlacementRequestV1{
			Requirements: requirements, PublicIPv4: false, RuntimeHoursPerMonth: cloudGoalRuntimeHours,
			PrivateConnectivity:    cloudquote.PrivateConnectivityNoNATEndpointsV1,
			ControlPlaneEndpoint:   materializer.workerControlEndpoint,
			PrivateEndpointDataMiB: 2 * cloudGoalEndpointDataMiB,
		},
	})
	if err != nil {
		return cloudquote.QuoteV1{}, cloudapp.ErrUnavailable
	}
	quoteRequest, command, err := buildCloudGoalQuoteRequest(materializer.agentInstanceID, materializer.workerControlEndpoint, materializer.workerControlServiceName, connection, request, placement, secretScope)
	if err != nil {
		return cloudquote.QuoteV1{}, cloudapp.ErrInvalid
	}
	created, err := materializer.quotes.Quote(ctx, connection, quoteRequest, request.Draft.Recipe)
	if err != nil || validateCloudGoalProviderQuote(materializer.agentInstanceID, materializer.workerControlEndpoint, materializer.workerControlServiceName, connection, request, secretScope, created, now) != nil {
		return cloudquote.QuoteV1{}, cloudapp.ErrUnavailable
	}
	requestDigest, err := command.Digest()
	if err != nil {
		return cloudquote.QuoteV1{}, cloudapp.ErrInvalid
	}
	if _, err = materializer.facts.PersistQuote(ctx, caller, request.Stage.OutputIdempotencyKey, requestDigest, created); err != nil {
		return cloudquote.QuoteV1{}, err
	}
	readBack, err := materializer.facts.LoadQuote(ctx, request.Stage.Binding.OwnerID, request.QuoteID)
	if err != nil || validateCloudGoalProviderQuote(materializer.agentInstanceID, materializer.workerControlEndpoint, materializer.workerControlServiceName, connection, request, secretScope, readBack, now) != nil || !sameCloudGoalQuote(created, readBack) {
		return cloudquote.QuoteV1{}, cloudapp.ErrUnavailable
	}
	return readBack, nil
}

func (materializer *cloudGoalProviderPlanMaterializer) loadOrCreatePlan(
	ctx context.Context,
	caller cloudapp.MutationScope,
	connection cloudapp.Connection,
	request planning.ProviderPlanMaterializationRequest,
	quoted cloudquote.QuoteV1,
	now time.Time,
) (cloudapproval.PlanV1, error) {
	expected, err := buildCloudGoalPlan(materializer.agentInstanceID, request, quoted, now)
	if err != nil {
		return cloudapproval.PlanV1{}, cloudapp.ErrInvalid
	}
	persisted, err := materializer.facts.LoadPlan(ctx, request.Stage.Binding.OwnerID, request.PlanID)
	if err == nil {
		if validateCloudGoalProviderPlan(connection, request, quoted, expected, persisted, now) != nil {
			return cloudapproval.PlanV1{}, cloudapp.ErrInvalid
		}
		return persisted, nil
	}
	if !errors.Is(err, cloudapp.ErrNotFound) {
		return cloudapproval.PlanV1{}, cloudapp.ErrUnavailable
	}
	if _, err = materializer.facts.PersistCloudGoalPlan(ctx, caller, request.Stage.OutputIdempotencyKey, request.Stage.Attempt.TaskID, expected); err != nil {
		return cloudapproval.PlanV1{}, err
	}
	readBack, err := materializer.facts.LoadPlan(ctx, request.Stage.Binding.OwnerID, request.PlanID)
	if err != nil || validateCloudGoalProviderPlan(connection, request, quoted, expected, readBack, now) != nil {
		return cloudapproval.PlanV1{}, cloudapp.ErrUnavailable
	}
	return readBack, nil
}

func buildCloudGoalPlan(agentInstanceID string, request planning.ProviderPlanMaterializationRequest, quoted cloudquote.QuoteV1, now time.Time) (cloudapproval.PlanV1, error) {
	recommended, found := quoted.Candidate(cloudquote.CandidateRecommended)
	if !found {
		return cloudapproval.PlanV1{}, cloudapp.ErrInvalid
	}
	command := cloudapp.CreatePlanCommand{
		IdempotencyKey: request.Stage.OutputIdempotencyKey, QuoteID: quoted.QuoteID,
		CandidateID: cloudquote.CandidateRecommended, CurrentScope: recommended.Scope,
	}
	if command.Validate() != nil {
		return cloudapproval.PlanV1{}, cloudapp.ErrInvalid
	}
	return cloudapp.BuildPlan(agentInstanceID, request.PlanID, quoted, command.CandidateID, command.CurrentScope, now)
}

func buildCloudGoalQuoteRequest(
	agentInstanceID string,
	workerControlEndpoint, workerControlServiceName string,
	connection cloudapp.Connection,
	request planning.ProviderPlanMaterializationRequest,
	placement awsprovider.PlacementV1,
	secretScope []cloudquote.SecretScopeV1,
) (cloudquote.RequestV1, cloudapp.CreateQuoteCommand, error) {
	if placement.Region != connection.Region || len(placement.Candidates) != 3 ||
		placement.Usage != cloudGoalUsage() ||
		placement.Network.SecurityGroupMode != cloudquote.SecurityGroupCreateDedicated ||
		placement.Network.SecurityGroupID != "" || placement.Network.PublicIPv4 || placement.Network.EntryPoint != cloudquote.EntryPointNone ||
		placement.Network.PublicExposure || len(placement.Network.IngressPorts) != 0 || placement.Network.RouteTableID == "" ||
		placement.Network.PrivateConnectivity != cloudquote.PrivateConnectivityNoNATEndpointsV1 ||
		placement.Network.ControlPlaneEndpoint != workerControlEndpoint {
		return cloudquote.RequestV1{}, cloudapp.CreateQuoteCommand{}, cloudapp.ErrInvalid
	}
	retention := cloudGoalRetention(request.Stage.Binding.Retention)
	if retention.Class == "" {
		return cloudquote.RequestV1{}, cloudapp.CreateQuoteCommand{}, cloudapp.ErrInvalid
	}
	byProfile := make(map[cloudquote.CandidateProfile]awsprovider.PlacementCandidateV1, len(placement.Candidates))
	for _, candidate := range placement.Candidates {
		if _, exists := byProfile[candidate.Profile]; exists {
			return cloudquote.RequestV1{}, cloudapp.CreateQuoteCommand{}, cloudapp.ErrInvalid
		}
		byProfile[candidate.Profile] = candidate
	}
	requestValue := cloudquote.RequestV1{QuoteID: request.QuoteID, Usage: placement.Usage}
	serviceOperations := cloudGoalEndpointOperations(workerControlServiceName)
	for _, profile := range cloudGoalQuoteProfiles() {
		candidate, found := byProfile[profile]
		expected, expectedFound := cloudGoalCandidateForProfile(request.Candidates, profile)
		if !found || !expectedFound || candidate.Architecture != expected.Architecture || len(candidate.AvailabilityZones) == 0 ||
			candidate.VCPU < expected.VCPU || candidate.MemoryMiB < expected.MemoryMiB || candidate.DiskGiB < expected.DiskGiB ||
			(expected.GPURequired && (candidate.GPUCount == 0 || candidate.GPUMemoryMiB < expected.GPUMemoryMiB)) {
			return cloudquote.RequestV1{}, cloudapp.CreateQuoteCommand{}, cloudapp.ErrInvalid
		}
		requestValue.Scopes = append(requestValue.Scopes, cloudquote.ScopeV1{
			SchemaVersion: cloudquote.ScopeSchemaV2, AgentInstanceID: agentInstanceID,
			OwnerID: request.Stage.Binding.OwnerID, ConnectionID: request.Stage.Binding.ConnectionID,
			Recipe: cloudquote.RecipeBindingV1{RecipeID: request.Draft.RecipeID, Digest: request.Draft.Digest, Maturity: recipe.MaturityExperimental},
			Resource: cloudquote.ResourceScopeV1{
				CandidateID: profile, Region: placement.Region, AvailabilityZones: append([]string(nil), candidate.AvailabilityZones...),
				InstanceType: candidate.InstanceType, InstanceCount: 1, Architecture: candidate.Architecture,
				VCPU: candidate.VCPU, MemoryMiB: candidate.MemoryMiB, GPUType: candidate.GPUType,
				GPUCount: candidate.GPUCount, GPUMemoryMiB: candidate.GPUMemoryMiB, DiskGiB: candidate.DiskGiB,
				VolumeType: "gp3", VolumeIOPS: cloudGoalVolumeIOPS, VolumeThroughputMiBPS: cloudGoalVolumeThroughput,
				VolumeEncrypted: true, PurchaseOption: cloudquote.PurchaseOnDemand,
			},
			Network: placement.Network, SecretScope: append([]cloudquote.SecretScopeV1(nil), secretScope...), Retention: retention,
			ServiceOperations: &serviceOperations,
		})
	}
	command := cloudapp.CreateQuoteCommand{IdempotencyKey: request.Stage.OutputIdempotencyKey, Scopes: requestValue.Scopes, Usage: requestValue.Usage}
	// The internal materializer is the only path allowed to bind the
	// operator-frozen Worker Control service. Public CreateQuoteCommand
	// validation deliberately rejects that service to prevent caller injection.
	validation := requestValue
	validation.Scopes = append([]cloudquote.ScopeV1(nil), requestValue.Scopes...)
	for index := range validation.Scopes {
		validation.Scopes[index].Resource.WorkerImageID = "ami-00000000000000000"
		validation.Scopes[index].Resource.WorkerImageDigest = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
	}
	if validation.Validate() != nil {
		return cloudquote.RequestV1{}, cloudapp.CreateQuoteCommand{}, cloudapp.ErrInvalid
	}
	return requestValue, command, nil
}

func cloudGoalPlacementRequirements(base recipe.ResourceRequirementsV1, candidates []planning.ResourceCandidateV1) (recipe.ResourceRequirementsV1, error) {
	if planning.ValidateCandidatesAgainstRecipe(candidates, base) != nil {
		return recipe.ResourceRequirementsV1{}, cloudapp.ErrInvalid
	}
	result := base
	result.DataLocations = append([]recipe.DataLocationRequirementV1(nil), base.DataLocations...)
	var family string
	for _, candidate := range candidates {
		divisor := uint64(1)
		switch candidate.Tier {
		case planning.TierEconomy:
		case planning.TierRecommended:
			divisor = 2
		case planning.TierPerformance:
			divisor = 4
		default:
			return recipe.ResourceRequirementsV1{}, cloudapp.ErrInvalid
		}
		result.MinVCPU = max(result.MinVCPU, uint32(ceilCloudGoal(uint64(candidate.VCPU), divisor)))
		result.MinMemoryMiB = max(result.MinMemoryMiB, ceilCloudGoal(candidate.MemoryMiB, divisor))
		result.MinDiskGiB = max(result.MinDiskGiB, ceilCloudGoal(candidate.DiskGiB, divisor))
		if candidate.GPURequired {
			if family == "" {
				family = candidate.GPUFamily
			}
			if family != candidate.GPUFamily {
				return recipe.ResourceRequirementsV1{}, cloudapp.ErrInvalid
			}
			result.GPURequired = true
			result.MinGPUMemoryMiB = max(result.MinGPUMemoryMiB, candidate.GPUMemoryMiB)
		}
	}
	if base.GPURequired {
		if family != "" && !strings.EqualFold(family, base.GPUFamily) {
			return recipe.ResourceRequirementsV1{}, cloudapp.ErrInvalid
		}
		family = base.GPUFamily
	}
	if result.GPURequired {
		result.GPUFamily = family
	}
	if (&awsprovider.PlacementRequestV1{Requirements: result, PublicIPv4: false, RuntimeHoursPerMonth: cloudGoalRuntimeHours}).Validate() != nil {
		return recipe.ResourceRequirementsV1{}, cloudapp.ErrInvalid
	}
	return result, nil
}

func validateCloudGoalProviderQuote(
	agentInstanceID string,
	workerControlEndpoint, workerControlServiceName string,
	connection cloudapp.Connection,
	request planning.ProviderPlanMaterializationRequest,
	secretScope []cloudquote.SecretScopeV1,
	quoted cloudquote.QuoteV1,
	now time.Time,
) error {
	if quoted.QuoteID != request.QuoteID || quoted.Validate() != nil || !now.Before(quoted.ValidUntil) ||
		quoted.Usage != cloudGoalUsage() {
		return cloudapp.ErrInvalid
	}
	retention := cloudGoalRetention(request.Stage.Binding.Retention)
	for _, profile := range cloudGoalQuoteProfiles() {
		candidate, found := quoted.Candidate(profile)
		planningCandidate, planningFound := cloudGoalCandidateForProfile(request.Candidates, profile)
		if !found || !planningFound || candidate.Scope.AgentInstanceID != agentInstanceID || candidate.Scope.OwnerID != connection.OwnerID ||
			candidate.Scope.SchemaVersion != cloudquote.ScopeSchemaV2 ||
			candidate.Scope.ConnectionID != connection.ConnectionID || candidate.Scope.Recipe.RecipeID != request.Draft.RecipeID ||
			candidate.Scope.Recipe.Digest != request.Draft.Digest || candidate.Scope.Recipe.Maturity != recipe.MaturityExperimental ||
			candidate.Scope.Resource.CandidateID != profile || candidate.Scope.Resource.Region != connection.Region ||
			candidate.Scope.Resource.Architecture != planningCandidate.Architecture || candidate.Scope.Resource.VCPU < planningCandidate.VCPU ||
			candidate.Scope.Resource.MemoryMiB < planningCandidate.MemoryMiB || candidate.Scope.Resource.DiskGiB < planningCandidate.DiskGiB ||
			candidate.Scope.Resource.InstanceCount != 1 || candidate.Scope.Resource.VolumeType != "gp3" ||
			candidate.Scope.Resource.VolumeIOPS != cloudGoalVolumeIOPS || candidate.Scope.Resource.VolumeThroughputMiBPS != cloudGoalVolumeThroughput ||
			!candidate.Scope.Resource.VolumeEncrypted || candidate.Scope.Resource.PurchaseOption != cloudquote.PurchaseOnDemand ||
			candidate.Scope.Network.SecurityGroupMode != cloudquote.SecurityGroupCreateDedicated || candidate.Scope.Network.SecurityGroupID != "" ||
			candidate.Scope.Network.PublicIPv4 || candidate.Scope.Network.EntryPoint != cloudquote.EntryPointNone || candidate.Scope.Network.PublicExposure ||
			candidate.Scope.Network.RouteTableID == "" || candidate.Scope.Network.PrivateConnectivity != cloudquote.PrivateConnectivityNoNATEndpointsV1 ||
			candidate.Scope.Network.ControlPlaneEndpoint != workerControlEndpoint ||
			len(candidate.Scope.Network.IngressPorts) != 0 || len(candidate.Scope.IntegrationScope) != 0 ||
			!slices.Equal(candidate.Scope.SecretScope, secretScope) || candidate.Scope.Retention != retention ||
			candidate.Scope.ServiceOperations == nil || !sameCloudGoalEndpointOperations(*candidate.Scope.ServiceOperations, workerControlServiceName) {
			return cloudapp.ErrInvalid
		}
		if planningCandidate.GPURequired && (candidate.Scope.Resource.GPUCount == 0 || candidate.Scope.Resource.GPUMemoryMiB < planningCandidate.GPUMemoryMiB) {
			return cloudapp.ErrInvalid
		}
	}
	return nil
}

func cloudGoalUsage() cloudquote.UsageV1 {
	return cloudquote.UsageV1{
		RuntimeHoursPerMonth:   cloudGoalRuntimeHours,
		PrivateEndpointHours:   2 * cloudGoalRuntimeHours,
		PrivateEndpointDataMiB: 2 * cloudGoalEndpointDataMiB,
	}
}

func cloudGoalEndpointOperations(workerControlServiceName string) cloudquote.ServiceOperationScopeV1 {
	return cloudquote.ServiceOperationScopeV1{PrivateEndpoints: []cloudquote.PrivateEndpointOperationSpecV1{
		{
			OperationKey: cloudGoalS3EndpointKey,
			Service:      cloudquote.PrivateEndpointServiceS3,
			EndpointType: cloudquote.PrivateEndpointTypeGateway,
		},
		{
			OperationKey:        cloudGoalSecretsEndpointKey,
			Service:             cloudquote.PrivateEndpointServiceSecretsManager,
			EndpointType:        cloudquote.PrivateEndpointTypeInterface,
			SecurityGroupSource: cloudquote.EndpointSecurityGroupEndpointDedicatedFromWorker,
			PrivateDNSEnabled:   true,
			MonthlyHours:        cloudGoalRuntimeHours,
			DataMiBPerMonth:     cloudGoalEndpointDataMiB,
		},
		{
			OperationKey: cloudGoalWorkerControlEndpointKey, Service: cloudquote.PrivateEndpointServiceWorkerControl,
			ServiceName: workerControlServiceName, EndpointType: cloudquote.PrivateEndpointTypeInterface,
			SecurityGroupSource: cloudquote.EndpointSecurityGroupEndpointDedicatedFromWorker,
			PrivateDNSEnabled:   true, MonthlyHours: cloudGoalRuntimeHours, DataMiBPerMonth: cloudGoalEndpointDataMiB,
		},
	}}
}

func sameCloudGoalEndpointOperations(actual cloudquote.ServiceOperationScopeV1, workerControlServiceName string) bool {
	expected := cloudGoalEndpointOperations(workerControlServiceName)
	expected = *cloudquote.NormalizeServiceOperations(&expected)
	return slices.Equal(actual.PrivateEndpoints, expected.PrivateEndpoints) && len(actual.Snapshots) == 0
}

func validateCloudGoalProviderPlan(
	connection cloudapp.Connection,
	request planning.ProviderPlanMaterializationRequest,
	quoted cloudquote.QuoteV1,
	expected cloudapproval.PlanV1,
	actual cloudapproval.PlanV1,
	now time.Time,
) error {
	if actual.PlanID != request.PlanID || actual.OwnerID != connection.OwnerID || actual.ConnectionID != connection.ConnectionID ||
		actual.Status != cloudapproval.PlanReadyForConfirmation || actual.Revision != 1 || actual.Validate() != nil || actual.ValidateQuote(quoted, now) != nil {
		return cloudapp.ErrInvalid
	}
	expectedHash, expectedErr := expected.Hash()
	actualHash, actualErr := actual.Hash()
	if expectedErr != nil || actualErr != nil || expectedHash != actualHash {
		return cloudapp.ErrInvalid
	}
	return nil
}

func (materializer *cloudGoalProviderPlanMaterializer) resolveSecretScope(ctx context.Context, callerClientID string, request planning.ProviderPlanMaterializationRequest) ([]cloudquote.SecretScopeV1, error) {
	if len(request.Draft.Recipe.SecretSlots) == 0 {
		return nil, nil
	}
	result := make([]cloudquote.SecretScopeV1, 0, len(request.Draft.Recipe.SecretSlots))
	seenPurposes := make(map[string]struct{}, len(request.Draft.Recipe.SecretSlots))
	for _, slot := range request.Draft.Recipe.SecretSlots {
		if _, duplicate := seenPurposes[slot.Purpose]; duplicate {
			return nil, cloudapp.ErrInvalid
		}
		seenPurposes[slot.Purpose] = struct{}{}
		binding := secretbootstrap.BindingV1{
			AgentInstanceID: materializer.agentInstanceID, OwnerID: request.Stage.Binding.OwnerID,
			Purpose: slot.Purpose, TargetID: request.Draft.Digest,
		}
		session, err := materializer.secrets.FindUploaded(ctx, callerClientID, binding)
		parsed, parseErr := uuid.Parse(session.SessionID)
		if err != nil || parseErr != nil || parsed == uuid.Nil || parsed.String() != session.SessionID ||
			session.Binding() != binding || session.Status != secretbootstrap.StatusUploaded {
			return nil, ErrCloudGoalSecretsNotReady
		}
		result = append(result, cloudquote.SecretScopeV1{
			SecretRef: "secret_ref:bootstrap/" + session.SessionID, Purpose: slot.Purpose, Delivery: slot.Delivery,
		})
	}
	slices.SortFunc(result, func(left, right cloudquote.SecretScopeV1) int {
		return strings.Compare(left.SecretRef, right.SecretRef)
	})
	return result, nil
}

func cloudGoalRetention(value task.RetentionPolicy) cloudquote.RetentionScopeV1 {
	switch value {
	case task.RetentionEphemeralAutoDestroy:
		return cloudquote.RetentionScopeV1{Class: cloudquote.RetentionEphemeral, AutoDestroy: true, GracePeriodSeconds: cloudGoalDestroyGrace, MaxLifetimeSeconds: cloudGoalMaximumLifetime}
	case task.RetentionManaged:
		return cloudquote.RetentionScopeV1{Class: cloudquote.RetentionManaged}
	default:
		return cloudquote.RetentionScopeV1{}
	}
}

func cloudGoalQuoteProfiles() []cloudquote.CandidateProfile {
	return []cloudquote.CandidateProfile{cloudquote.CandidateEconomic, cloudquote.CandidateRecommended, cloudquote.CandidatePerformance}
}

func cloudGoalCandidateForProfile(candidates []planning.ResourceCandidateV1, profile cloudquote.CandidateProfile) (planning.ResourceCandidateV1, bool) {
	wanted := planning.TierEconomy
	switch profile {
	case cloudquote.CandidateEconomic:
	case cloudquote.CandidateRecommended:
		wanted = planning.TierRecommended
	case cloudquote.CandidatePerformance:
		wanted = planning.TierPerformance
	default:
		return planning.ResourceCandidateV1{}, false
	}
	for _, candidate := range candidates {
		if candidate.Tier == wanted {
			return candidate, true
		}
	}
	return planning.ResourceCandidateV1{}, false
}

func sameCloudGoalQuote(left, right cloudquote.QuoteV1) bool {
	leftDigest, leftErr := left.Digest()
	rightDigest, rightErr := right.Digest()
	return leftErr == nil && rightErr == nil && leftDigest == rightDigest
}

func ceilCloudGoal(value, divisor uint64) uint64 {
	return value/divisor + boolCloudGoal(value%divisor != 0)
}

func boolCloudGoal(value bool) uint64 {
	if value {
		return 1
	}
	return 0
}
