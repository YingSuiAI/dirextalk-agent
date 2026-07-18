// Package artifactorigin owns the closed release path for Dirextalk's
// first-party, SHA-addressed public artifacts. It is an operator surface, not
// part of the Agent runtime or Worker credential boundary.
package artifactorigin

import (
	"errors"
	"regexp"
	"time"
)

const (
	StorageRegion = "ap-northeast-3"
	EdgeRegion    = "us-east-1"
	DomainName    = "artifacts.y1.dirextalk.ai"

	StorageStackName = "dtx-y1-artifact-origin-storage"
	EdgeStackName    = "dtx-y1-artifact-origin-edge"

	CatalogSchemaV1         = "dirextalk.artifact-origin.catalog/v1"
	OriginReceiptSchemaV1   = "dirextalk.artifact-origin.receipt/v1"
	ArtifactReceiptSchemaV1 = "dirextalk.artifact-origin.publication/v1"
	ImmutableCacheControl   = "public,max-age=31536000,immutable"
)

var (
	ErrInvalid             = errors.New("invalid artifact-origin input")
	ErrTemplate            = errors.New("invalid artifact-origin template")
	ErrCloudState          = errors.New("artifact-origin cloud state is invalid")
	ErrCloudOperation      = errors.New("artifact-origin cloud operation failed")
	ErrImmutableConflict   = errors.New("immutable artifact already exists")
	ErrS3Verification      = errors.New("artifact S3 verification failed")
	ErrEdgeVerification    = errors.New("artifact edge verification failed")
	ErrArtifactUnavailable = errors.New("artifact publication unavailable")
)

var (
	accountIDPattern    = regexp.MustCompile(`^[0-9]{12}$`)
	hostedZonePattern   = regexp.MustCompile(`^Z[A-Z0-9]{6,31}$`)
	artifactIDPattern   = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)
	artifactNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	sha256Pattern       = regexp.MustCompile(`^[0-9a-f]{64}$`)
	mediaTypePattern    = regexp.MustCompile(`^[a-z0-9][a-z0-9.+-]{0,63}/[A-Za-z0-9][A-Za-z0-9.+_-]{0,63}$`)
	licensePattern      = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.+-]{0,63}$`)
)

type PrepareOptions struct {
	AccountID    string
	Region       string
	Domain       string
	HostedZoneID string
}

type OriginReceipt struct {
	SchemaVersion          string    `json:"schema_version"`
	AccountID              string    `json:"account_id"`
	StorageRegion          string    `json:"storage_region"`
	Domain                 string    `json:"domain"`
	StorageStackID         string    `json:"storage_stack_id"`
	EdgeStackID            string    `json:"edge_stack_id"`
	BucketName             string    `json:"bucket_name"`
	KMSKeyARN              string    `json:"kms_key_arn"`
	DistributionID         string    `json:"distribution_id"`
	DistributionARN        string    `json:"distribution_arn"`
	DistributionDomainName string    `json:"distribution_domain_name"`
	StorageTemplateSHA256  string    `json:"storage_template_sha256"`
	EdgeTemplateSHA256     string    `json:"edge_template_sha256"`
	PreparedAt             time.Time `json:"prepared_at"`
}

type Artifact struct {
	ID             string `json:"id"`
	Name           string `json:"name"`
	SHA256         string `json:"sha256"`
	SizeBytes      int64  `json:"size_bytes"`
	MediaType      string `json:"media_type"`
	SourceURL      string `json:"source_url"`
	SourceRevision string `json:"source_revision"`
	License        string `json:"license"`
}

type Catalog struct {
	SchemaVersion string     `json:"schema_version"`
	Artifacts     []Artifact `json:"artifacts"`
}

type ArtifactReceipt struct {
	SchemaVersion string    `json:"schema_version"`
	AccountID     string    `json:"account_id"`
	Region        string    `json:"region"`
	Domain        string    `json:"domain"`
	ArtifactID    string    `json:"artifact_id"`
	Name          string    `json:"name"`
	SHA256        string    `json:"sha256"`
	SizeBytes     int64     `json:"size_bytes"`
	S3Bucket      string    `json:"s3_bucket"`
	S3Key         string    `json:"s3_key"`
	S3VersionID   string    `json:"s3_version_id"`
	URL           string    `json:"url"`
	VerifiedAt    time.Time `json:"verified_at"`
}
