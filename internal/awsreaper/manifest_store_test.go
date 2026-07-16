package awsreaper

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/resource"
	"github.com/YingSuiAI/dirextalk-agent/internal/task"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	dynamodbtypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/google/uuid"
)

type fakeDynamoDB struct {
	items map[string]map[string]dynamodbtypes.AttributeValue
}

func newFakeDynamoDB() *fakeDynamoDB {
	return &fakeDynamoDB{items: make(map[string]map[string]dynamodbtypes.AttributeValue)}
}

func (fake *fakeDynamoDB) Query(_ context.Context, input *dynamodb.QueryInput, _ ...func(*dynamodb.Options)) (*dynamodb.QueryOutput, error) {
	result := &dynamodb.QueryOutput{}
	partition, _ := stringAttribute(input.ExpressionAttributeValues[":pk"])
	for _, item := range fake.items {
		pk, _ := stringAttribute(item["pk"])
		if pk == partition {
			result.Items = append(result.Items, cloneItem(item))
		}
	}
	return result, nil
}

func (fake *fakeDynamoDB) UpdateItem(_ context.Context, input *dynamodb.UpdateItemInput, _ ...func(*dynamodb.Options)) (*dynamodb.UpdateItemOutput, error) {
	sk, _ := stringAttribute(input.Key["sk"])
	current := fake.items[sk]
	newRevision, _ := strconv.ParseInt(input.ExpressionAttributeValues[":revision"].(*dynamodbtypes.AttributeValueMemberN).Value, 10, 64)
	newDigest, _ := stringAttribute(input.ExpressionAttributeValues[":digest"])
	if current != nil {
		currentRevision, _ := strconv.ParseInt(current["revision"].(*dynamodbtypes.AttributeValueMemberN).Value, 10, 64)
		currentDigest, _ := stringAttribute(current["payload_digest"])
		if expectedValue, conditional := input.ExpressionAttributeValues[":expected"]; conditional {
			expected, _ := strconv.ParseInt(expectedValue.(*dynamodbtypes.AttributeValueMemberN).Value, 10, 64)
			expectedDigest, _ := stringAttribute(input.ExpressionAttributeValues[":expected_digest"])
			if (currentRevision != expected || currentDigest != expectedDigest) && (currentRevision != newRevision || currentDigest != newDigest) {
				return nil, &dynamodbtypes.ConditionalCheckFailedException{}
			}
		} else if claimed, _ := boolAttribute(current["reaper_claimed"]); (claimed && (currentRevision != newRevision || currentDigest != newDigest)) || currentRevision > newRevision || (currentRevision == newRevision && currentDigest != newDigest) {
			return nil, &dynamodbtypes.ConditionalCheckFailedException{}
		}
	}
	item := cloneItem(input.Key)
	for expressionName, attributeName := range input.ExpressionAttributeNames {
		valueName := ":" + expressionName[1:]
		if value, ok := input.ExpressionAttributeValues[valueName]; ok {
			item[attributeName] = value
		}
	}
	fake.items[sk] = item
	return &dynamodb.UpdateItemOutput{}, nil
}

func TestDynamoManifestStoreBlocksManagedOverwriteOfActiveReaperClaim(t *testing.T) {
	now := time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC)
	agentID := uuid.NewString()
	fake := newFakeDynamoDB()
	store, _ := NewDynamoManifestStore(fake, "dtx-agent-resources", agentID)
	manifest := reaperManifest(agentID, now.Add(-time.Minute), false)
	if err := store.Put(context.Background(), manifest); err != nil {
		t.Fatal(err)
	}
	claimed := manifest
	claimed.Revision++
	claimed.UpdatedAt = now
	claimed.Resources[0].State = resource.StateDestroying
	if err := store.PutIfRevision(context.Background(), claimed, manifest.Revision); err != nil {
		t.Fatal(err)
	}
	managed := claimed
	managed.Revision++
	managed.Managed = true
	managed.Retention = task.RetentionManaged
	managed.DestroyDeadline = time.Time{}
	managed.AutoDestroyApproved = false
	managed.AutoDestroyApprovalID = ""
	managed.Resources[0].Retention = task.RetentionManaged
	managed.Resources[0].DestroyDeadline = time.Time{}
	managed.Resources[0].AutoDestroyApproved = false
	managed.Resources[0].State = resource.StateRetainedManaged
	managed.Resources[0].Tags[resource.TagRetention] = string(task.RetentionManaged)
	managed.Resources[0].Tags[resource.TagDestroyDeadline] = "managed"
	if err := store.Put(context.Background(), managed); !errors.Is(err, resource.ErrRevisionConflict) {
		t.Fatalf("managed overwrite error = %v", err)
	}
}

func TestDynamoManifestStoreListsOnlyExpiredEphemeralAndFencesRevision(t *testing.T) {
	now := time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC)
	agentID := uuid.NewString()
	fake := newFakeDynamoDB()
	store, err := NewDynamoManifestStore(fake, "dtx-agent-resources", agentID)
	if err != nil {
		t.Fatal(err)
	}

	ephemeral := reaperManifest(agentID, now.Add(-time.Minute), false)
	if err := store.Put(context.Background(), ephemeral); err != nil {
		t.Fatal(err)
	}
	managed := reaperManifest(agentID, time.Time{}, true)
	if err := store.Put(context.Background(), managed); err != nil {
		t.Fatal(err)
	}
	manifests, err := store.ListExpired(context.Background(), now)
	if err != nil {
		t.Fatal(err)
	}
	if len(manifests) != 1 || manifests[0].DeploymentID != ephemeral.DeploymentID {
		t.Fatalf("expired manifests = %+v", manifests)
	}

	updated := ephemeral
	updated.Revision++
	updated.UpdatedAt = now.Add(time.Second)
	if err := store.PutIfRevision(context.Background(), updated, ephemeral.Revision-1); !errors.Is(err, resource.ErrRevisionConflict) {
		t.Fatalf("stale CAS error = %v", err)
	}
	if err := store.PutIfRevision(context.Background(), updated, ephemeral.Revision); err != nil {
		t.Fatalf("valid CAS: %v", err)
	}
}

func TestDynamoManifestStoreRejectsMetadataTampering(t *testing.T) {
	now := time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC)
	agentID := uuid.NewString()
	fake := newFakeDynamoDB()
	store, _ := NewDynamoManifestStore(fake, "dtx-agent-resources", agentID)
	manifest := reaperManifest(agentID, now.Add(-time.Minute), false)
	if err := store.Put(context.Background(), manifest); err != nil {
		t.Fatal(err)
	}
	item := fake.items[manifestSortKey(manifest.DeploymentID)]
	item["managed"] = &dynamodbtypes.AttributeValueMemberBOOL{Value: true}
	if _, err := store.ListExpired(context.Background(), now); !errors.Is(err, ErrManifestStore) {
		t.Fatalf("tampered item error = %v", err)
	}
}

func TestDynamoManifestStoreRejectsResourceApprovalScopeTampering(t *testing.T) {
	now := time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC)
	agentID := uuid.NewString()
	tests := map[string]func(*resource.Manifest){
		"plan hash": func(value *resource.Manifest) {
			value.Resources[0].ApprovedPlanHash = "sha256:" + strings.Repeat("b", 64)
		},
		"approval id":  func(value *resource.Manifest) { value.Resources[0].ApprovalID = uuid.NewString() },
		"resource tag": func(value *resource.Manifest) { delete(value.Resources[0].Tags, resource.TagResourceID) },
		"deadline tag": func(value *resource.Manifest) {
			value.Resources[0].Tags[resource.TagDestroyDeadline] = now.Add(time.Hour).Format(time.RFC3339)
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			store, err := NewDynamoManifestStore(newFakeDynamoDB(), "dtx-agent-resources", agentID)
			if err != nil {
				t.Fatal(err)
			}
			manifest := reaperManifest(agentID, now.Add(-time.Minute), false)
			mutate(&manifest)
			if err := store.Put(context.Background(), manifest); !errors.Is(err, resource.ErrInvalid) {
				t.Fatalf("tampered manifest error = %v", err)
			}
		})
	}
}

func reaperManifest(agentID string, deadline time.Time, managed bool) resource.Manifest {
	now := time.Date(2026, 7, 16, 11, 0, 0, 0, time.UTC)
	deploymentID, taskID, resourceID, approvalID := uuid.NewString(), uuid.NewString(), uuid.NewString(), uuid.NewString()
	retention := task.RetentionEphemeralAutoDestroy
	state := resource.StateActive
	autoApproved := true
	approval := approvalID
	if managed {
		retention, state, autoApproved, approval = task.RetentionManaged, resource.StateRetainedManaged, false, ""
	}
	tags := map[string]string{
		resource.TagAgentInstanceID: agentID, resource.TagOwnerID: "owner-1", resource.TagTaskID: taskID,
		resource.TagDeploymentID: deploymentID, resource.TagResourceID: resourceID, resource.TagRetention: string(retention),
		resource.TagDestroyDeadline: deadline.UTC().Format(time.RFC3339),
	}
	if managed {
		tags[resource.TagDestroyDeadline] = "managed"
	}
	item := resource.ResourceV1{
		ResourceID: resourceID, AgentInstanceID: agentID, OwnerID: "owner-1", TaskID: taskID, DeploymentID: deploymentID,
		Type: resource.TypeEC2, LogicalName: "worker", Region: "us-west-2", SpecDigest: digestFixture(), ApprovedPlanHash: digestFixture(),
		ApprovalID: approvalID, ProviderID: "i-0123456789abcdef0", Retention: retention, DestroyDeadline: deadline,
		AutoDestroyApproved: autoApproved, Tags: tags, State: state, Revision: 2, CreatedAt: now, UpdatedAt: now,
	}
	return resource.Manifest{
		ManifestID: deploymentID, AgentInstanceID: agentID, OwnerID: "owner-1", TaskID: taskID, DeploymentID: deploymentID,
		Retention: retention, DestroyDeadline: deadline, AutoDestroyApproved: autoApproved, AutoDestroyApprovalID: approval,
		ApprovedPlanHash: digestFixture(), Managed: managed, Resources: []resource.ResourceV1{item}, Revision: 2, UpdatedAt: now,
	}
}

func digestFixture() string {
	return "sha256:" + "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
}

func cloneItem(input map[string]dynamodbtypes.AttributeValue) map[string]dynamodbtypes.AttributeValue {
	result := make(map[string]dynamodbtypes.AttributeValue, len(input))
	for key, value := range input {
		result[key] = value
	}
	return result
}
