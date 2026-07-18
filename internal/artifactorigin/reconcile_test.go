package artifactorigin

import (
	"context"
	"reflect"
	"testing"
	"time"

	assets "github.com/YingSuiAI/dirextalk-agent/deploy/awsartifactorigin"
)

type fakeStackDriver struct {
	region  string
	states  map[string]StackSnapshot
	applied []StackRequest
}

func (driver *fakeStackDriver) Read(_ context.Context, name string) (StackSnapshot, bool, error) {
	state, ok := driver.states[name]
	return state, ok, nil
}

func (driver *fakeStackDriver) Apply(_ context.Context, request StackRequest) (StackSnapshot, error) {
	driver.applied = append(driver.applied, request)
	state := StackSnapshot{
		Name: request.Name, ID: stackARN(driver.region, request.Name), Region: driver.region,
		Status: "UPDATE_COMPLETE", Parameters: cloneMap(request.Parameters), Tags: cloneMap(request.Tags), Outputs: map[string]string{},
	}
	if request.Name == StorageStackName {
		state.Outputs = validStorageOutputs(request.Parameters["EdgeDistributionArn"])
	} else {
		state.Outputs = validEdgeOutputs()
	}
	driver.states[request.Name] = state
	return state, nil
}

func TestPrepareFreshOriginUsesStorageEdgeStoragePhases(t *testing.T) {
	storage := &fakeStackDriver{region: StorageRegion, states: map[string]StackSnapshot{}}
	edge := &fakeStackDriver{region: EdgeRegion, states: map[string]StackSnapshot{}}
	now := time.Date(2026, 7, 19, 1, 2, 3, 0, time.UTC)
	receipt, err := Prepare(context.Background(), validPrepareOptions(), storage, edge, assets.StorageTemplate(), assets.EdgeTemplate(), func() time.Time { return now })
	if err != nil {
		t.Fatalf("Prepare() error = %v", err)
	}
	if len(storage.applied) != 2 || len(edge.applied) != 1 {
		t.Fatalf("apply counts storage=%d edge=%d, want 2/1", len(storage.applied), len(edge.applied))
	}
	if storage.applied[0].Parameters["EdgeDistributionArn"] != "" {
		t.Fatal("initial storage phase granted an edge distribution before it existed")
	}
	wantARN := validEdgeOutputs()["DistributionArn"]
	if storage.applied[1].Parameters["EdgeDistributionArn"] != wantARN || receipt.DistributionARN != wantARN || receipt.PreparedAt != now {
		t.Fatalf("final binding/receipt = %#v", receipt)
	}
}

func TestPrepareRecoveryNeverTemporarilyUnbindsExistingStorage(t *testing.T) {
	distributionARN := validEdgeOutputs()["DistributionArn"]
	storageState := StackSnapshot{
		Name: StorageStackName, ID: stackARN(StorageRegion, StorageStackName), Region: StorageRegion, Status: "UPDATE_COMPLETE",
		Parameters: map[string]string{"EdgeDistributionArn": distributionARN}, Tags: stackTags("artifact-origin-storage"), Outputs: validStorageOutputs(distributionARN),
	}
	edgeState := StackSnapshot{
		Name: EdgeStackName, ID: stackARN(EdgeRegion, EdgeStackName), Region: EdgeRegion, Status: "CREATE_COMPLETE",
		Parameters: map[string]string{"DomainName": DomainName, "HostedZoneId": "Z123456789", "OriginBucketName": bucketName(), "OriginBucketRegionalDomainName": bucketDomain()},
		Tags:       stackTags("artifact-origin-edge"), Outputs: validEdgeOutputs(),
	}
	storage := &fakeStackDriver{region: StorageRegion, states: map[string]StackSnapshot{StorageStackName: storageState}}
	edge := &fakeStackDriver{region: EdgeRegion, states: map[string]StackSnapshot{EdgeStackName: edgeState}}
	if _, err := Prepare(context.Background(), validPrepareOptions(), storage, edge, assets.StorageTemplate(), assets.EdgeTemplate(), time.Now); err != nil {
		t.Fatalf("Prepare() recovery error = %v", err)
	}
	if len(storage.applied) != 1 || storage.applied[0].Parameters["EdgeDistributionArn"] != distributionARN {
		t.Fatalf("recovery storage applies = %#v", storage.applied)
	}
}

func TestPrepareRejectsUnownedExistingStackBeforeMutation(t *testing.T) {
	state := StackSnapshot{
		Name: StorageStackName, ID: stackARN(StorageRegion, StorageStackName), Region: StorageRegion, Status: "CREATE_COMPLETE",
		Parameters: map[string]string{"EdgeDistributionArn": ""}, Tags: map[string]string{"managed_by": "someone-else"}, Outputs: validStorageOutputs(""),
	}
	storage := &fakeStackDriver{region: StorageRegion, states: map[string]StackSnapshot{StorageStackName: state}}
	edge := &fakeStackDriver{region: EdgeRegion, states: map[string]StackSnapshot{}}
	if _, err := Prepare(context.Background(), validPrepareOptions(), storage, edge, assets.StorageTemplate(), assets.EdgeTemplate(), time.Now); err == nil {
		t.Fatal("Prepare adopted an unowned stack")
	}
	if len(storage.applied) != 0 || len(edge.applied) != 0 {
		t.Fatal("Prepare mutated cloud state after ownership validation failed")
	}
}

func validPrepareOptions() PrepareOptions {
	return PrepareOptions{AccountID: "123456789012", Region: StorageRegion, Domain: DomainName, HostedZoneID: "Z123456789"}
}

func stackARN(region, name string) string {
	return "arn:aws:cloudformation:" + region + ":123456789012:stack/" + name + "/11111111-2222-4333-8444-555555555555"
}

func bucketName() string   { return "dtx-y1-artifacts-123456789012-ap-northeast-3" }
func bucketDomain() string { return bucketName() + ".s3.ap-northeast-3.amazonaws.com" }

func validStorageOutputs(distributionARN string) map[string]string {
	outputs := map[string]string{
		"BucketName": bucketName(), "BucketRegionalDomainName": bucketDomain(),
		"KMSKeyArn": "arn:aws:kms:ap-northeast-3:123456789012:key/11111111-2222-4333-8444-555555555555",
	}
	if distributionARN != "" {
		outputs["EdgeDistributionArn"] = distributionARN
	}
	return outputs
}

func validEdgeOutputs() map[string]string {
	return map[string]string{
		"DistributionId": "E1234567890ABC", "DistributionArn": "arn:aws:cloudfront::123456789012:distribution/E1234567890ABC",
		"DistributionDomainName": "d111111abcdef8.cloudfront.net", "AliasDomainName": DomainName, "OriginBucketName": bucketName(),
	}
}

func TestStackTagShapeIsExact(t *testing.T) {
	if !reflect.DeepEqual(stackTags("artifact-origin-storage"), map[string]string{
		"managed_by": "dirextalk-agent", "component": "artifact-origin-storage", "retention": "managed_retained", "domain": DomainName,
	}) {
		t.Fatal("unexpected ownership tags")
	}
}
