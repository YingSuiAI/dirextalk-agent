package awsreaper

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/resource"
	"github.com/YingSuiAI/dirextalk-agent/internal/task"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	dynamodbtypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/google/uuid"
)

const (
	manifestSchemaVersion = 1
	maxManifestBytes      = 300 * 1024
	maxManifestResources  = 256
)

var ErrManifestStore = errors.New("AWS resource manifest store failed")

type DynamoDBAPI interface {
	GetItem(context.Context, *dynamodb.GetItemInput, ...func(*dynamodb.Options)) (*dynamodb.GetItemOutput, error)
	Query(context.Context, *dynamodb.QueryInput, ...func(*dynamodb.Options)) (*dynamodb.QueryOutput, error)
	UpdateItem(context.Context, *dynamodb.UpdateItemInput, ...func(*dynamodb.Options)) (*dynamodb.UpdateItemOutput, error)
}

var _ resource.ManifestReadBack = (*DynamoManifestStore)(nil)

type DynamoManifestStore struct {
	client          DynamoDBAPI
	table           string
	agentInstanceID string
	mu              sync.Mutex
	observed        map[string]observedManifest
}

type observedManifest struct {
	revision int64
	digest   string
}

func NewDynamoManifestStore(client DynamoDBAPI, table, agentInstanceID string) (*DynamoManifestStore, error) {
	config := Config{AgentInstanceID: strings.TrimSpace(agentInstanceID), Region: "us-east-1", ManifestTable: strings.TrimSpace(table)}
	if client == nil || config.Validate() != nil {
		return nil, ErrInvalidConfig
	}
	return &DynamoManifestStore{client: client, table: config.ManifestTable, agentInstanceID: config.AgentInstanceID, observed: make(map[string]observedManifest)}, nil
}

func (store *DynamoManifestStore) Put(ctx context.Context, manifest resource.Manifest) error {
	return store.put(ctx, manifest, nil, "")
}

func (store *DynamoManifestStore) PutIfRevision(ctx context.Context, manifest resource.Manifest, expectedRevision int64) error {
	if expectedRevision < 1 || manifest.Revision != expectedRevision+1 {
		return resource.ErrRevisionConflict
	}
	store.mu.Lock()
	observed, ok := store.observed[manifest.DeploymentID]
	store.mu.Unlock()
	if !ok || observed.revision != expectedRevision {
		return resource.ErrRevisionConflict
	}
	return store.put(ctx, manifest, &expectedRevision, observed.digest)
}

func (store *DynamoManifestStore) Get(ctx context.Context, deploymentID string) (resource.Manifest, error) {
	parsed, err := uuid.Parse(strings.TrimSpace(deploymentID))
	if err != nil || parsed == uuid.Nil || parsed.String() != deploymentID {
		return resource.Manifest{}, resource.ErrInvalid
	}
	output, err := store.client.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: &store.table,
		Key: map[string]dynamodbtypes.AttributeValue{
			"pk": &dynamodbtypes.AttributeValueMemberS{Value: manifestPartition(store.agentInstanceID)},
			"sk": &dynamodbtypes.AttributeValueMemberS{Value: manifestSortKey(deploymentID)},
		},
		ConsistentRead: awsBool(true),
	})
	if err != nil || output == nil || len(output.Item) == 0 {
		return resource.Manifest{}, ErrManifestStore
	}
	manifest, err := store.decode(output.Item)
	if err != nil || manifest.DeploymentID != deploymentID {
		return resource.Manifest{}, ErrManifestStore
	}
	_, digest, _, err := store.encode(manifest)
	if err != nil {
		return resource.Manifest{}, err
	}
	store.remember(manifest.DeploymentID, manifest.Revision, digest)
	if err := resource.NormalizeLegacyApprovalBindings(&manifest); err != nil {
		return resource.Manifest{}, ErrManifestStore
	}
	return manifest, nil
}

func (store *DynamoManifestStore) put(ctx context.Context, manifest resource.Manifest, expectedRevision *int64, expectedDigest string) error {
	if err := resource.NormalizeLegacyApprovalBindings(&manifest); err != nil {
		return err
	}
	encoded, digest, deadline, err := store.encode(manifest)
	if err != nil {
		return err
	}
	values := map[string]dynamodbtypes.AttributeValue{
		":schema":    &dynamodbtypes.AttributeValueMemberN{Value: strconv.Itoa(manifestSchemaVersion)},
		":manifest":  &dynamodbtypes.AttributeValueMemberB{Value: encoded},
		":digest":    &dynamodbtypes.AttributeValueMemberS{Value: digest},
		":revision":  &dynamodbtypes.AttributeValueMemberN{Value: strconv.FormatInt(manifest.Revision, 10)},
		":updated":   &dynamodbtypes.AttributeValueMemberS{Value: manifest.UpdatedAt.UTC().Format(time.RFC3339Nano)},
		":retention": &dynamodbtypes.AttributeValueMemberS{Value: string(manifest.Retention)},
		":deadline":  &dynamodbtypes.AttributeValueMemberN{Value: strconv.FormatInt(deadline, 10)},
		":managed":   &dynamodbtypes.AttributeValueMemberBOOL{Value: manifest.Managed},
		":approved":  &dynamodbtypes.AttributeValueMemberBOOL{Value: manifest.AutoDestroyApproved},
		":claimed":   &dynamodbtypes.AttributeValueMemberBOOL{Value: manifestDestroying(manifest)},
		":false":     &dynamodbtypes.AttributeValueMemberBOOL{Value: false},
	}
	condition := "attribute_not_exists(#revision) OR ((attribute_not_exists(#claimed) OR #claimed = :false) AND #revision < :revision) OR (#revision = :revision AND #digest = :digest)"
	if expectedRevision != nil {
		values[":expected"] = &dynamodbtypes.AttributeValueMemberN{Value: strconv.FormatInt(*expectedRevision, 10)}
		values[":expected_digest"] = &dynamodbtypes.AttributeValueMemberS{Value: expectedDigest}
		condition = "(#revision = :expected AND #digest = :expected_digest) OR (#revision = :revision AND #digest = :digest)"
	}
	_, err = store.client.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName: &store.table,
		Key: map[string]dynamodbtypes.AttributeValue{
			"pk": &dynamodbtypes.AttributeValueMemberS{Value: manifestPartition(store.agentInstanceID)},
			"sk": &dynamodbtypes.AttributeValueMemberS{Value: manifestSortKey(manifest.DeploymentID)},
		},
		ExpressionAttributeNames: map[string]string{
			"#schema": "schema_version", "#manifest": "manifest_json", "#digest": "payload_digest", "#revision": "revision",
			"#updated": "updated_at", "#retention": "retention", "#deadline": "destroy_deadline_epoch",
			"#managed": "managed", "#approved": "auto_destroy_approved",
			"#claimed": "reaper_claimed",
		},
		ExpressionAttributeValues: values,
		UpdateExpression:          awsString("SET #schema=:schema,#manifest=:manifest,#digest=:digest,#revision=:revision,#updated=:updated,#retention=:retention,#deadline=:deadline,#managed=:managed,#approved=:approved,#claimed=:claimed"),
		ConditionExpression:       &condition,
	})
	if err == nil {
		store.remember(manifest.DeploymentID, manifest.Revision, digest)
		return nil
	}
	var conflict *dynamodbtypes.ConditionalCheckFailedException
	if errors.As(err, &conflict) {
		return resource.ErrRevisionConflict
	}
	return ErrManifestStore
}

func (store *DynamoManifestStore) ListExpired(ctx context.Context, before time.Time) ([]resource.Manifest, error) {
	if before.IsZero() {
		return nil, ErrManifestStore
	}
	partition := manifestPartition(store.agentInstanceID)
	values := map[string]dynamodbtypes.AttributeValue{":pk": &dynamodbtypes.AttributeValueMemberS{Value: partition}}
	var cursor map[string]dynamodbtypes.AttributeValue
	result := make([]resource.Manifest, 0)
	for {
		output, err := store.client.Query(ctx, &dynamodb.QueryInput{
			TableName: &store.table, ConsistentRead: awsBool(true), ExclusiveStartKey: cursor,
			KeyConditionExpression:   awsString("#pk = :pk"),
			ExpressionAttributeNames: map[string]string{"#pk": "pk"}, ExpressionAttributeValues: values,
		})
		if err != nil {
			return nil, ErrManifestStore
		}
		if output == nil {
			return nil, ErrManifestStore
		}
		for _, item := range output.Items {
			manifest, err := store.decode(item)
			if err != nil {
				return nil, err
			}
			if manifest.Retention == task.RetentionEphemeralAutoDestroy && !manifest.DestroyDeadline.After(before.UTC()) {
				_, digest, _, encodeErr := store.encode(manifest)
				if encodeErr != nil {
					return nil, encodeErr
				}
				store.remember(manifest.DeploymentID, manifest.Revision, digest)
				if err := resource.NormalizeLegacyApprovalBindings(&manifest); err != nil {
					return nil, ErrManifestStore
				}
				result = append(result, manifest)
			}
		}
		if len(output.LastEvaluatedKey) == 0 {
			break
		}
		cursor = output.LastEvaluatedKey
	}
	return result, nil
}

func (store *DynamoManifestStore) remember(deploymentID string, revision int64, digest string) {
	store.mu.Lock()
	store.observed[deploymentID] = observedManifest{revision: revision, digest: digest}
	store.mu.Unlock()
}

func (store *DynamoManifestStore) encode(manifest resource.Manifest) ([]byte, string, int64, error) {
	if err := validateManifest(manifest, store.agentInstanceID); err != nil {
		return nil, "", 0, err
	}
	encoded, err := json.Marshal(manifestEnvelope{SchemaVersion: manifestSchemaVersion, Manifest: manifest})
	if err != nil || len(encoded) > maxManifestBytes {
		return nil, "", 0, ErrManifestStore
	}
	digest := sha256.Sum256(encoded)
	deadline := int64(0)
	if !manifest.DestroyDeadline.IsZero() {
		deadline = manifest.DestroyDeadline.UTC().Unix()
	}
	return encoded, "sha256:" + hex.EncodeToString(digest[:]), deadline, nil
}

func (store *DynamoManifestStore) decode(item map[string]dynamodbtypes.AttributeValue) (resource.Manifest, error) {
	pk, ok := stringAttribute(item["pk"])
	if !ok || pk != manifestPartition(store.agentInstanceID) {
		return resource.Manifest{}, ErrManifestStore
	}
	sk, ok := stringAttribute(item["sk"])
	if !ok || !strings.HasPrefix(sk, "MANIFEST#") {
		return resource.Manifest{}, ErrManifestStore
	}
	raw, ok := binaryAttribute(item["manifest_json"])
	if !ok || len(raw) == 0 || len(raw) > maxManifestBytes {
		return resource.Manifest{}, ErrManifestStore
	}
	var envelope manifestEnvelope
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&envelope); err != nil || envelope.SchemaVersion != manifestSchemaVersion || ensureJSONEOF(decoder) != nil {
		return resource.Manifest{}, ErrManifestStore
	}
	if err := validateManifest(envelope.Manifest, store.agentInstanceID); err != nil {
		return resource.Manifest{}, err
	}
	encoded, digest, deadline, err := store.encode(envelope.Manifest)
	if err != nil || !bytes.Equal(encoded, raw) {
		return resource.Manifest{}, ErrManifestStore
	}
	want := map[string]string{
		"payload_digest":         digest,
		"revision":               strconv.FormatInt(envelope.Manifest.Revision, 10),
		"retention":              string(envelope.Manifest.Retention),
		"destroy_deadline_epoch": strconv.FormatInt(deadline, 10),
	}
	for key, expected := range want {
		actual, ok := stringOrNumberAttribute(item[key])
		if !ok || actual != expected {
			return resource.Manifest{}, ErrManifestStore
		}
	}
	schema, ok := numberAttribute(item["schema_version"])
	if !ok || schema != manifestSchemaVersion || sk != manifestSortKey(envelope.Manifest.DeploymentID) {
		return resource.Manifest{}, ErrManifestStore
	}
	managed, managedOK := boolAttribute(item["managed"])
	approved, approvedOK := boolAttribute(item["auto_destroy_approved"])
	claimed, claimedOK := boolAttribute(item["reaper_claimed"])
	if !managedOK || !approvedOK || !claimedOK || managed != envelope.Manifest.Managed || approved != envelope.Manifest.AutoDestroyApproved || claimed != manifestDestroying(envelope.Manifest) {
		return resource.Manifest{}, ErrManifestStore
	}
	return envelope.Manifest, nil
}

func manifestDestroying(manifest resource.Manifest) bool {
	for _, item := range manifest.Resources {
		if item.State == resource.StateDestroying {
			return true
		}
	}
	return false
}

type manifestEnvelope struct {
	SchemaVersion int               `json:"schema_version"`
	Manifest      resource.Manifest `json:"manifest"`
}

func validateManifest(manifest resource.Manifest, agentInstanceID string) error {
	canonical := manifest
	if err := resource.NormalizeLegacyApprovalBindings(&canonical); err != nil {
		return resource.ErrInvalid
	}
	manifest = canonical
	for _, value := range []string{manifest.ManifestID, manifest.AgentInstanceID, manifest.TaskID, manifest.DeploymentID} {
		parsed, err := uuid.Parse(strings.TrimSpace(value))
		if err != nil || parsed == uuid.Nil {
			return resource.ErrInvalid
		}
	}
	if manifest.AgentInstanceID != agentInstanceID || manifest.ManifestID != manifest.DeploymentID || strings.TrimSpace(manifest.OwnerID) == "" ||
		manifest.Revision < 1 || manifest.UpdatedAt.IsZero() || len(manifest.Resources) == 0 || len(manifest.Resources) > maxManifestResources {
		return resource.ErrInvalid
	}
	if err := manifest.ValidateResourceApprovalScope(); err != nil {
		return resource.ErrInvalid
	}
	for _, item := range manifest.Resources {
		if manifest.Managed && item.State != resource.StateRetainedManaged {
			return resource.ErrInvalid
		}
	}
	return nil
}

func manifestPartition(agentInstanceID string) string { return "AGENT#" + agentInstanceID }
func manifestSortKey(deploymentID string) string      { return "MANIFEST#" + deploymentID }
func awsString(value string) *string                  { return &value }
func awsBool(value bool) *bool                        { return &value }

func stringAttribute(value dynamodbtypes.AttributeValue) (string, bool) {
	typed, ok := value.(*dynamodbtypes.AttributeValueMemberS)
	return func() string {
		if typed == nil {
			return ""
		}
		return typed.Value
	}(), ok
}

func binaryAttribute(value dynamodbtypes.AttributeValue) ([]byte, bool) {
	typed, ok := value.(*dynamodbtypes.AttributeValueMemberB)
	if !ok || typed == nil {
		return nil, false
	}
	return typed.Value, true
}

func numberAttribute(value dynamodbtypes.AttributeValue) (int, bool) {
	typed, ok := value.(*dynamodbtypes.AttributeValueMemberN)
	if !ok || typed == nil {
		return 0, false
	}
	parsed, err := strconv.Atoi(typed.Value)
	return parsed, err == nil
}

func stringOrNumberAttribute(value dynamodbtypes.AttributeValue) (string, bool) {
	if text, ok := stringAttribute(value); ok {
		return text, true
	}
	typed, ok := value.(*dynamodbtypes.AttributeValueMemberN)
	if !ok || typed == nil {
		return "", false
	}
	return typed.Value, true
}

func boolAttribute(value dynamodbtypes.AttributeValue) (bool, bool) {
	typed, ok := value.(*dynamodbtypes.AttributeValueMemberBOOL)
	if !ok || typed == nil {
		return false, false
	}
	return typed.Value, true
}

func ensureJSONEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return fmt.Errorf("unexpected trailing JSON: %w", err)
	}
	return nil
}
