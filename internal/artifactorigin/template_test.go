package artifactorigin

import (
	"bytes"
	"testing"

	assets "github.com/YingSuiAI/dirextalk-agent/deploy/awsartifactorigin"
)

func TestReviewedTemplatesEnforceOriginBoundary(t *testing.T) {
	if err := ValidateStorageTemplate(assets.StorageTemplate()); err != nil {
		t.Fatalf("ValidateStorageTemplate() error = %v", err)
	}
	if err := ValidateEdgeTemplate(assets.EdgeTemplate()); err != nil {
		t.Fatalf("ValidateEdgeTemplate() error = %v", err)
	}
}

func TestStorageTemplateRejectsWeakenedVersioningPolicyAndObjectLock(t *testing.T) {
	base := assets.StorageTemplate()
	mutations := [][]byte{
		bytes.Replace(base, []byte("Status: Enabled"), []byte("Status: Suspended"), 1),
		bytes.Replace(base, []byte("AWS:SourceArn: !Ref EdgeDistributionArn"), []byte("AWS:SourceAccount: !Ref AWS::AccountId"), 1),
		bytes.Replace(base, []byte("      VersioningConfiguration:"), []byte("      ObjectLockEnabled: Enabled\n      VersioningConfiguration:"), 1),
		bytes.Replace(base, []byte("SSEAlgorithm: aws:kms"), []byte("SSEAlgorithm: AES256"), 1),
		bytes.Replace(base, []byte("- s3:DeleteObjectVersion"), []byte("- s3:GetObjectVersion"), 1),
	}
	for _, mutated := range mutations {
		if err := ValidateStorageTemplate(mutated); err == nil {
			t.Fatal("ValidateStorageTemplate accepted a weakened storage boundary")
		}
	}
}

func TestEdgeTemplateRejectsMethodsQueriesCompressionAndRedirects(t *testing.T) {
	base := assets.EdgeTemplate()
	mutations := [][]byte{
		bytes.Replace(base, []byte("            - HEAD\n          CachedMethods:"), []byte("            - HEAD\n            - POST\n          CachedMethods:"), 1),
		bytes.Replace(base, []byte("QueryStringBehavior: none"), []byte("QueryStringBehavior: all"), 1),
		bytes.Replace(base, []byte("          Compress: false"), []byte("          Compress: true"), 1),
		bytes.Replace(base, []byte("ViewerProtocolPolicy: https-only"), []byte("ViewerProtocolPolicy: redirect-to-https"), 1),
	}
	for _, mutated := range mutations {
		if err := ValidateEdgeTemplate(mutated); err == nil {
			t.Fatal("ValidateEdgeTemplate accepted a weakened edge boundary")
		}
	}
}
