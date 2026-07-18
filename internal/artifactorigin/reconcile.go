package artifactorigin

import (
	"context"
	"regexp"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/google/uuid"
)

type StackSnapshot struct {
	Name       string
	ID         string
	Region     string
	Status     string
	UpdatedAt  time.Time
	Parameters map[string]string
	Outputs    map[string]string
	Tags       map[string]string
}

type StackRequest struct {
	Name       string
	Template   []byte
	Parameters map[string]string
	Tags       map[string]string
}

type StackDriver interface {
	Read(context.Context, string) (StackSnapshot, bool, error)
	Apply(context.Context, StackRequest) (StackSnapshot, error)
}

var (
	kmsKeyARNPattern          = regexp.MustCompile(`^arn:aws:kms:ap-northeast-3:[0-9]{12}:key/[0-9a-f-]{36}$`)
	distributionIDPattern     = regexp.MustCompile(`^[A-Z0-9]{8,32}$`)
	distributionDomainPattern = regexp.MustCompile(`^[a-z0-9-]{8,64}\.cloudfront\.net$`)
)

func Prepare(
	ctx context.Context,
	options PrepareOptions,
	storage, edge StackDriver,
	storageTemplate, edgeTemplate []byte,
	now func() time.Time,
) (OriginReceipt, error) {
	if ctx == nil || storage == nil || edge == nil || now == nil || validatePrepareOptions(options) != nil ||
		ValidateStorageTemplate(storageTemplate) != nil || ValidateEdgeTemplate(edgeTemplate) != nil {
		return OriginReceipt{}, ErrInvalid
	}
	storageState, storageExists, err := storage.Read(ctx, StorageStackName)
	if err != nil {
		return OriginReceipt{}, ErrCloudOperation
	}
	if storageExists {
		if err := validateStackIdentity(storageState, options.AccountID, StorageRegion, StorageStackName, stackTags("artifact-origin-storage")); err != nil ||
			validateStorageState(storageState, options.AccountID, "") != nil {
			return OriginReceipt{}, ErrCloudState
		}
	} else {
		storageState, err = storage.Apply(ctx, StackRequest{
			Name: StorageStackName, Template: append([]byte(nil), storageTemplate...),
			Parameters: map[string]string{"EdgeDistributionArn": ""}, Tags: stackTags("artifact-origin-storage"),
		})
		if err != nil || validateStackIdentity(storageState, options.AccountID, StorageRegion, StorageStackName, stackTags("artifact-origin-storage")) != nil ||
			validateStorageState(storageState, options.AccountID, "") != nil {
			return OriginReceipt{}, ErrCloudOperation
		}
	}

	edgeParameters := map[string]string{
		"DomainName": options.Domain, "HostedZoneId": options.HostedZoneID,
		"OriginBucketName": storageState.Outputs["BucketName"], "OriginBucketRegionalDomainName": storageState.Outputs["BucketRegionalDomainName"],
	}
	edgeState, edgeExists, err := edge.Read(ctx, EdgeStackName)
	if err != nil {
		return OriginReceipt{}, ErrCloudOperation
	}
	if edgeExists {
		if err := validateStackIdentity(edgeState, options.AccountID, EdgeRegion, EdgeStackName, stackTags("artifact-origin-edge")); err != nil ||
			validateEdgeState(edgeState, options.AccountID, edgeParameters) != nil {
			return OriginReceipt{}, ErrCloudState
		}
	}
	edgeState, err = edge.Apply(ctx, StackRequest{
		Name: EdgeStackName, Template: append([]byte(nil), edgeTemplate...), Parameters: edgeParameters, Tags: stackTags("artifact-origin-edge"),
	})
	if err != nil || validateStackIdentity(edgeState, options.AccountID, EdgeRegion, EdgeStackName, stackTags("artifact-origin-edge")) != nil ||
		validateEdgeState(edgeState, options.AccountID, edgeParameters) != nil {
		return OriginReceipt{}, ErrCloudOperation
	}

	distributionARN := edgeState.Outputs["DistributionArn"]
	storageState, err = storage.Apply(ctx, StackRequest{
		Name: StorageStackName, Template: append([]byte(nil), storageTemplate...),
		Parameters: map[string]string{"EdgeDistributionArn": distributionARN}, Tags: stackTags("artifact-origin-storage"),
	})
	if err != nil || validateStackIdentity(storageState, options.AccountID, StorageRegion, StorageStackName, stackTags("artifact-origin-storage")) != nil ||
		validateStorageState(storageState, options.AccountID, distributionARN) != nil {
		return OriginReceipt{}, ErrCloudOperation
	}

	preparedAt := now().UTC()
	if preparedAt.IsZero() {
		return OriginReceipt{}, ErrInvalid
	}
	return OriginReceipt{
		SchemaVersion: OriginReceiptSchemaV1, AccountID: options.AccountID, StorageRegion: StorageRegion, Domain: DomainName,
		StorageStackID: storageState.ID, EdgeStackID: edgeState.ID,
		BucketName: storageState.Outputs["BucketName"], KMSKeyARN: storageState.Outputs["KMSKeyArn"],
		DistributionID: edgeState.Outputs["DistributionId"], DistributionARN: distributionARN,
		DistributionDomainName: edgeState.Outputs["DistributionDomainName"],
		StorageTemplateSHA256:  templateDigest(storageTemplate), EdgeTemplateSHA256: templateDigest(edgeTemplate), PreparedAt: preparedAt,
	}, nil
}

func validatePrepareOptions(options PrepareOptions) error {
	if !accountIDPattern.MatchString(options.AccountID) || options.Region != StorageRegion || options.Domain != DomainName ||
		!hostedZonePattern.MatchString(options.HostedZoneID) {
		return ErrInvalid
	}
	return nil
}

func validateStackIdentity(snapshot StackSnapshot, accountID, region, name string, expectedTags map[string]string) error {
	parsed, err := arn.Parse(snapshot.ID)
	if err != nil || snapshot.Name != name || snapshot.Region != region || snapshot.Status == "" ||
		parsed.Partition != "aws" || parsed.Service != "cloudformation" || parsed.Region != region || parsed.AccountID != accountID ||
		!validStackResource(parsed.Resource, name) || !stableStackStatus(snapshot.Status) || !sameMap(snapshot.Tags, expectedTags) {
		return ErrCloudState
	}
	return nil
}

func stableStackStatus(status string) bool {
	switch status {
	case "CREATE_COMPLETE", "UPDATE_COMPLETE", "UPDATE_ROLLBACK_COMPLETE":
		return true
	default:
		return false
	}
}

func validateStorageState(snapshot StackSnapshot, accountID, expectedDistributionARN string) error {
	wantBucket := "dtx-y1-artifacts-" + accountID + "-" + StorageRegion
	wantDomain := wantBucket + ".s3." + StorageRegion + ".amazonaws.com"
	parameterARN := snapshot.Parameters["EdgeDistributionArn"]
	distributionARN, hasDistributionOutput := snapshot.Outputs["EdgeDistributionArn"]
	wantOutputCount := 3
	if parameterARN != "" {
		wantOutputCount = 4
	}
	if len(snapshot.Parameters) != 1 || len(snapshot.Outputs) != wantOutputCount || snapshot.Outputs["BucketName"] != wantBucket || snapshot.Outputs["BucketRegionalDomainName"] != wantDomain ||
		!kmsKeyARNPattern.MatchString(snapshot.Outputs["KMSKeyArn"]) || !strings.Contains(snapshot.Outputs["KMSKeyArn"], ":"+accountID+":") ||
		(parameterARN == "" && hasDistributionOutput) || (parameterARN != "" && (!hasDistributionOutput || parameterARN != distributionARN)) {
		return ErrCloudState
	}
	if expectedDistributionARN != "" && distributionARN != expectedDistributionARN {
		return ErrCloudState
	}
	if distributionARN != "" && !validDistributionARN(distributionARN, accountID, "") {
		return ErrCloudState
	}
	return nil
}

func validateEdgeState(snapshot StackSnapshot, accountID string, expectedParameters map[string]string) error {
	distributionID := snapshot.Outputs["DistributionId"]
	if len(snapshot.Outputs) != 5 || !sameMap(snapshot.Parameters, expectedParameters) || !distributionIDPattern.MatchString(distributionID) ||
		!validDistributionARN(snapshot.Outputs["DistributionArn"], accountID, distributionID) ||
		!distributionDomainPattern.MatchString(snapshot.Outputs["DistributionDomainName"]) ||
		snapshot.Outputs["AliasDomainName"] != DomainName || snapshot.Outputs["OriginBucketName"] != expectedParameters["OriginBucketName"] {
		return ErrCloudState
	}
	return nil
}

func validDistributionARN(value, accountID, distributionID string) bool {
	prefix := "arn:aws:cloudfront::" + accountID + ":distribution/"
	if !strings.HasPrefix(value, prefix) {
		return false
	}
	id := strings.TrimPrefix(value, prefix)
	return distributionIDPattern.MatchString(id) && (distributionID == "" || id == distributionID)
}

func stackTags(component string) map[string]string {
	return map[string]string{"managed_by": "dirextalk-agent", "component": component, "retention": "managed_retained", "domain": DomainName}
}

func sameMap(left, right map[string]string) bool {
	if len(left) != len(right) {
		return false
	}
	for key, value := range left {
		if right[key] != value {
			return false
		}
	}
	return true
}

func cloneMap(source map[string]string) map[string]string {
	result := make(map[string]string, len(source))
	for key, value := range source {
		result[key] = value
	}
	return result
}

func (receipt OriginReceipt) Validate() error {
	if receipt.SchemaVersion != OriginReceiptSchemaV1 || !accountIDPattern.MatchString(receipt.AccountID) || receipt.StorageRegion != StorageRegion ||
		receipt.Domain != DomainName || receipt.PreparedAt.IsZero() || !sha256Pattern.MatchString(receipt.StorageTemplateSHA256) ||
		!sha256Pattern.MatchString(receipt.EdgeTemplateSHA256) || receipt.BucketName != "dtx-y1-artifacts-"+receipt.AccountID+"-"+StorageRegion ||
		!kmsKeyARNPattern.MatchString(receipt.KMSKeyARN) || !strings.Contains(receipt.KMSKeyARN, ":"+receipt.AccountID+":") ||
		!distributionIDPattern.MatchString(receipt.DistributionID) || !validDistributionARN(receipt.DistributionARN, receipt.AccountID, receipt.DistributionID) ||
		!distributionDomainPattern.MatchString(receipt.DistributionDomainName) ||
		validateReceiptStackARN(receipt.StorageStackID, receipt.AccountID, StorageRegion, StorageStackName) != nil ||
		validateReceiptStackARN(receipt.EdgeStackID, receipt.AccountID, EdgeRegion, EdgeStackName) != nil {
		return ErrInvalid
	}
	return nil
}

func validateReceiptStackARN(value, accountID, region, name string) error {
	parsed, err := arn.Parse(value)
	if err != nil || parsed.Partition != "aws" || parsed.Service != "cloudformation" || parsed.Region != region || parsed.AccountID != accountID ||
		!validStackResource(parsed.Resource, name) {
		return ErrInvalid
	}
	return nil
}

func validStackResource(resource, name string) bool {
	parts := strings.Split(resource, "/")
	if len(parts) != 3 || parts[0] != "stack" || parts[1] != name {
		return false
	}
	parsed, err := uuid.Parse(parts[2])
	return err == nil && parsed != uuid.Nil && parsed.String() == parts[2]
}
