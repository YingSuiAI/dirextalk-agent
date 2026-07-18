package artifactorigin

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"

	"gopkg.in/yaml.v3"
)

const maxTemplateBytes = 128 << 10

func ValidateStorageTemplate(raw []byte) error {
	if err := validateSingleYAML(raw); err != nil {
		return err
	}
	required := []string{
		"Type: AWS::KMS::Key", "Type: AWS::KMS::Alias", "Type: AWS::S3::Bucket", "Type: AWS::S3::BucketPolicy",
		"DeletionPolicy: Retain", "UpdateReplacePolicy: Retain", "EnableKeyRotation: true",
		"Status: Enabled", "SSEAlgorithm: aws:kms", "KMSMasterKeyID: !GetAtt ArtifactKey.Arn", "BucketKeyEnabled: true",
		"ObjectOwnership: BucketOwnerEnforced", "BlockPublicAcls: true", "BlockPublicPolicy: true", "IgnorePublicAcls: true", "RestrictPublicBuckets: true",
		"s3:x-amz-server-side-encryption: aws:kms", "s3:x-amz-server-side-encryption-aws-kms-key-id: !GetAtt ArtifactKey.Arn",
		"Sid: DenyArtifactDeletion", "- s3:DeleteObject", "- s3:DeleteObjectVersion",
		"Service: cloudfront.amazonaws.com", "Action: s3:GetObject", "AWS:SourceArn: !Ref EdgeDistributionArn",
		"Action:\n                - kms:Decrypt\n                - kms:DescribeKey", "HasEdgeDistribution",
	}
	for _, fragment := range required {
		if !bytes.Contains(raw, []byte(fragment)) {
			return ErrTemplate
		}
	}
	if bytes.Count(raw, []byte("AWS:SourceArn: !Ref EdgeDistributionArn")) != 2 ||
		bytes.Count(raw, []byte("DeletionPolicy: Retain")) != 2 || bytes.Count(raw, []byte("UpdateReplacePolicy: Retain")) != 2 {
		return ErrTemplate
	}
	for _, forbidden := range []string{"ObjectLock", "AccessControl: Public", "Principal: cloudfront.amazonaws.com", "Action: s3:PutObject*"} {
		if bytes.Contains(raw, []byte(forbidden)) {
			return ErrTemplate
		}
	}
	return nil
}

func ValidateEdgeTemplate(raw []byte) error {
	if err := validateSingleYAML(raw); err != nil {
		return err
	}
	required := []string{
		"Type: AWS::CertificateManager::Certificate", "ValidationMethod: DNS", "Type: AWS::CloudFront::OriginAccessControl",
		"OriginAccessControlOriginType: s3", "SigningBehavior: always", "SigningProtocol: sigv4",
		"Type: AWS::CloudFront::CachePolicy", "EnableAcceptEncodingBrotli: false", "EnableAcceptEncodingGzip: false",
		"QueryStringBehavior: none", "CookieBehavior: none", "HeaderBehavior: none",
		"Type: AWS::CloudFront::Distribution", "Compress: false", "ViewerProtocolPolicy: https-only",
		"OriginAccessControlId: !GetAtt ArtifactOriginAccessControl.Id", "MinimumProtocolVersion: TLSv1.2_2021",
		"Type: AWS::Route53::RecordSet", "HostedZoneId: Z2FDTNDATAQYW2",
	}
	for _, fragment := range required {
		if !bytes.Contains(raw, []byte(fragment)) {
			return ErrTemplate
		}
	}
	allowedMethods := "AllowedMethods:\n            - GET\n            - HEAD\n          CachedMethods:\n            - GET\n            - HEAD"
	if !bytes.Contains(raw, []byte(allowedMethods)) || bytes.Count(raw, []byte("Type: AWS::Route53::RecordSet")) != 2 {
		return ErrTemplate
	}
	for _, forbidden := range []string{
		"redirect-to-https", "QueryStringBehavior: all", "Compress: true", "ForwardedValues:", "CustomOriginConfig:",
		"LambdaFunctionAssociations:", "FunctionAssociations:", "WebACLId:", "- POST", "- PUT", "- PATCH", "- DELETE", "- OPTIONS",
	} {
		if bytes.Contains(raw, []byte(forbidden)) {
			return ErrTemplate
		}
	}
	return nil
}

func validateSingleYAML(raw []byte) error {
	if len(raw) == 0 || len(raw) > maxTemplateBytes {
		return ErrTemplate
	}
	decoder := yaml.NewDecoder(bytes.NewReader(raw))
	var root yaml.Node
	if err := decoder.Decode(&root); err != nil || len(root.Content) == 0 {
		return ErrTemplate
	}
	var extra yaml.Node
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return ErrTemplate
	}
	return nil
}

func templateDigest(raw []byte) string {
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:])
}
