package main

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	workaws "github.com/YingSuiAI/dirextalk-agent/internal/awscredential"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreaws"
	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

type cloudWorkerCredentialResolverFake struct {
	handle          workaws.CredentialHandle
	views           []coreaws.CredentialView
	revisions       []uint64
	revisionCalls   int
	credentialCalls int
	exactCalls      int
	exactRevision   uint64
	exactErr        error
}

const fixtureCloudWorkerHostRegion = "ap-northeast-2"
const fixtureCloudWorkerRegion = "ap-northeast-1"

func (resolver *cloudWorkerCredentialResolverFake) ResolveCredentialRevision(_ context.Context, _ string, revision uint64) (workaws.CredentialHandle, error) {
	resolver.exactCalls++
	if resolver.exactErr != nil || revision != resolver.exactRevision {
		if resolver.exactErr == nil {
			return workaws.CredentialHandle{}, workaws.ErrPrecondition
		}
		return workaws.CredentialHandle{}, resolver.exactErr
	}
	return resolver.handle, nil
}

func (resolver *cloudWorkerCredentialResolverFake) ResolveCredential(context.Context, string) (workaws.CredentialHandle, error) {
	resolver.credentialCalls++
	return resolver.handle, nil
}

func (resolver *cloudWorkerCredentialResolverFake) CredentialRevision(context.Context, string) (uint64, error) {
	if len(resolver.revisions) == 0 {
		return 0, errors.New("revision unavailable")
	}
	index := resolver.revisionCalls
	resolver.revisionCalls++
	if index >= len(resolver.revisions) {
		index = len(resolver.revisions) - 1
	}
	return resolver.revisions[index], nil
}

func cloudWorkerCredentialAuthorityFixture(t *testing.T) (*cloudWorkerCredentialAuthority, *cloudWorkerCredentialResolverFake) {
	t.Helper()
	binding := cloudworker.AWSBinding{AccountID: "123456789012", Region: "us-east-1", CredentialID: "11111111-1111-4111-8111-111111111111", CredentialRevision: 3}
	resolver := &cloudWorkerCredentialResolverFake{
		handle: workaws.CredentialHandle{
			ReferenceID: binding.CredentialID, Region: binding.Region, AccountID: binding.AccountID,
			PrincipalARN: "arn:aws:iam::123456789012:role/cloud-worker", AccessKeyID: "access", SecretAccessKey: "secret",
		},
		exactRevision: binding.CredentialRevision,
		revisions:     []uint64{binding.CredentialRevision, binding.CredentialRevision},
	}
	resolver.views = []coreaws.CredentialView{{
		ID: binding.CredentialID, Region: binding.Region, AccountID: binding.AccountID,
		Revision: int64(binding.CredentialRevision), VerifiedRevision: int64(binding.CredentialRevision), TestedAt: time.Now().UTC(),
	}}
	authority, err := newCloudWorkerCredentialAuthority(resolver, resolver, resolver, fixtureCloudWorkerHostRegion, func(context.Context, int, string) (coreaws.CredentialPage, error) {
		return coreaws.CredentialPage{Items: resolver.views}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	authority.placement.probe = unavailableCloudWorkerEndpoint
	return authority, resolver
}

func TestCloudWorkerCredentialAuthorityDoubleFencesRevisionAndIdentity(t *testing.T) {
	authority, resolver := cloudWorkerCredentialAuthorityFixture(t)
	binding, err := authority.ResolveCurrentAWSBinding(context.Background())
	if err != nil || binding.CredentialID != resolver.handle.ReferenceID || binding.Region != fixtureCloudWorkerRegion ||
		resolver.revisionCalls != 2 || resolver.credentialCalls != 1 {
		t.Fatalf("exact authority binding=%+v revision_calls=%d credential_calls=%d err=%v",
			binding, resolver.revisionCalls, resolver.credentialCalls, err)
	}

	authority, resolver = cloudWorkerCredentialAuthorityFixture(t)
	resolver.revisions = []uint64{3, 4}
	if _, err = authority.ResolveCurrentAWSBinding(context.Background()); !errors.Is(err, cloudworker.ErrStaleAuthorization) {
		t.Fatalf("mid-read rotation err=%v", err)
	}

	authority, resolver = cloudWorkerCredentialAuthorityFixture(t)
	resolver.handle.AccountID = "999999999999"
	if _, err = authority.ResolveCurrentAWSBinding(context.Background()); !errors.Is(err, cloudworker.ErrStaleAuthorization) {
		t.Fatalf("account drift err=%v", err)
	}

	authority, resolver = cloudWorkerCredentialAuthorityFixture(t)
	resolver.handle.Region = "us-west-2"
	if _, err = authority.ResolveCurrentAWSBinding(context.Background()); !errors.Is(err, cloudworker.ErrStaleAuthorization) {
		t.Fatalf("region drift err=%v", err)
	}
}

func TestCloudWorkerCredentialAuthorityRejectsMalformedHostAndEmptyWorkerRegion(t *testing.T) {
	_, resolver := cloudWorkerCredentialAuthorityFixture(t)
	for _, region := range []string{" us-east-1", "local-1"} {
		if _, err := newCloudWorkerCredentialAuthority(resolver, resolver, resolver, region, func(context.Context, int, string) (coreaws.CredentialPage, error) {
			return coreaws.CredentialPage{Items: resolver.views}, nil
		}); !errors.Is(err, cloudworker.ErrInvalid) {
			t.Fatalf("host region %q returned %v", region, err)
		}
	}
	authority, _ := cloudWorkerCredentialAuthorityFixture(t)
	expected, err := authority.ResolveCurrentAWSBinding(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	expected.Region = ""
	if _, err = authority.ResolveExactAWSBinding(context.Background(), expected); !errors.Is(err, cloudworker.ErrInvalid) {
		t.Fatalf("empty Worker region returned %v", err)
	}
}

func TestCloudWorkerCredentialReadinessTracksCurrentVerifiedView(t *testing.T) {
	authority, resolver := cloudWorkerCredentialAuthorityFixture(t)
	if !authority.HasCurrentVerifiedAWSBinding(context.Background()) {
		t.Fatal("verified credential was not ready")
	}
	resolver.views[0].VerifiedRevision = 0
	if authority.HasCurrentVerifiedAWSBinding(context.Background()) {
		t.Fatal("unverified credential remained ready")
	}
	resolver.views = nil
	if authority.HasCurrentVerifiedAWSBinding(context.Background()) {
		t.Fatal("deleted credential remained ready")
	}
}

func TestCloudWorkerCredentialPlacementIsLazyVerifiedAndIndependentOfUploadedRegion(t *testing.T) {
	_, resolver := cloudWorkerCredentialAuthorityFixture(t)
	for _, host := range []string{"", "zz-unknown-1"} {
		authority, err := newCloudWorkerCredentialAuthority(resolver, resolver, resolver, host, func(context.Context, int, string) (coreaws.CredentialPage, error) {
			return coreaws.CredentialPage{Items: resolver.views}, nil
		})
		if err != nil {
			t.Fatal(err)
		}
		var probes atomic.Int32
		authority.placement.probe = func(ctx context.Context, region string) (time.Duration, error) {
			probes.Add(1)
			return unavailableCloudWorkerEndpoint(ctx, region)
		}
		authority.placement.random = func(int) int { return 2 }
		resolver.views[0].VerifiedRevision = 0
		if _, err := authority.ResolveCurrentAWSBinding(context.Background()); !errors.Is(err, cloudworker.ErrStaleAuthorization) || probes.Load() != 0 {
			t.Fatalf("unverified authority probed: err=%v probes=%d", err, probes.Load())
		}
		resolver.views[0].VerifiedRevision = resolver.views[0].Revision
		first, err := authority.ResolveCurrentAWSBinding(context.Background())
		if err != nil || first.Region != "eu-west-3" || first.Region == resolver.handle.Region {
			t.Fatalf("binding=%+v uploaded_region=%q err=%v", first, resolver.handle.Region, err)
		}
		second, err := authority.ResolveCurrentAWSBinding(context.Background())
		if err != nil || second != first || probes.Load() != 3 {
			t.Fatalf("proposal revalidation changed placement: first=%+v second=%+v probes=%d err=%v", first, second, probes.Load(), err)
		}
	}
}

func TestCloudWorkerCredentialPlacementRevalidatesAfterProbeTimeRotationOrDeletion(t *testing.T) {
	for _, change := range []string{"verified_rotation", "unverified_rotation", "deleted"} {
		t.Run(change, func(t *testing.T) {
			authority, resolver := cloudWorkerCredentialAuthorityFixture(t)
			authority.placement.probe = func(_ context.Context, region string) (time.Duration, error) {
				if region == "ap-northeast-1" {
					switch change {
					case "verified_rotation":
						resolver.revisions = []uint64{4, 4}
						resolver.views[0].Revision, resolver.views[0].VerifiedRevision = 4, 4
					case "unverified_rotation":
						resolver.views[0].Revision = 4
					case "deleted":
						resolver.views = nil
					}
				}
				return time.Millisecond, nil
			}
			binding, err := authority.ResolveCurrentAWSBinding(context.Background())
			if change == "verified_rotation" {
				if err != nil || binding.CredentialRevision != 4 {
					t.Fatalf("stale pre-probe binding=%+v err=%v", binding, err)
				}
			} else if !errors.Is(err, cloudworker.ErrStaleAuthorization) || binding != (cloudworker.AWSBinding{}) {
				t.Fatalf("changed authority escaped: binding=%+v err=%v", binding, err)
			}
		})
	}
}

func TestCloudWorkerCredentialAuthorityKeepsExactRevisionAfterRotateAndDisable(t *testing.T) {
	authority, resolver := cloudWorkerCredentialAuthorityFixture(t)
	expected := cloudworker.AWSBinding{AccountID: resolver.handle.AccountID, Region: fixtureCloudWorkerRegion, CredentialID: resolver.handle.ReferenceID, CredentialRevision: resolver.exactRevision}
	resolver.revisions = []uint64{4, 4}
	resolver.views[0].Revision, resolver.views[0].VerifiedRevision = 4, 4
	if current, err := authority.ResolveCurrentAWSBinding(context.Background()); err != nil || current.CredentialRevision != 4 {
		t.Fatalf("rotated current binding=%+v err=%v", current, err)
	}
	if exact, err := authority.ResolveExactAWSBinding(context.Background(), expected); err != nil || exact != expected {
		t.Fatalf("old exact binding=%+v err=%v", exact, err)
	}
	resolver.revisions = nil
	if _, err := authority.ResolveCurrentAWSBinding(context.Background()); !errors.Is(err, cloudworker.ErrStaleAuthorization) {
		t.Fatalf("disabled current accepted: %v", err)
	}
	if _, err := authority.ResolveExactAWSBinding(context.Background(), expected); err != nil {
		t.Fatalf("disabled credential cut off old exact revision: %v", err)
	}
}

type cloudWorkerCredentialHTTPClient struct{ calls int }

func (client *cloudWorkerCredentialHTTPClient) Do(*http.Request) (*http.Response, error) {
	client.calls++
	body := `<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">` +
		`<GetCallerIdentityResult><Arn>arn:aws:iam::123456789012:role/cloud-worker</Arn>` +
		`<UserId>cloud-worker</UserId><Account>123456789012</Account></GetCallerIdentityResult>` +
		`<ResponseMetadata><RequestId>11111111-1111-4111-8111-111111111111</RequestId>` +
		`</ResponseMetadata></GetCallerIdentityResponse>`
	return &http.Response{
		StatusCode: http.StatusOK, Header: http.Header{"Content-Type": []string{"text/xml"}},
		Body: io.NopCloser(strings.NewReader(body)),
	}, nil
}

func TestCloudWorkerAWSCredentialsProviderRevalidatesBeforeEverySDKRequest(t *testing.T) {
	authority, resolver := cloudWorkerCredentialAuthorityFixture(t)
	binding, err := authority.ResolveCurrentAWSBinding(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	provider, err := newCloudWorkerAWSCredentialsProvider(authority, binding)
	if err != nil {
		t.Fatal(err)
	}
	httpClient := &cloudWorkerCredentialHTTPClient{}
	sdkConfig := awssdk.Config{
		Region: binding.Region, Credentials: provider, HTTPClient: httpClient,
		Retryer: func() awssdk.Retryer { return awssdk.NopRetryer{} },
	}
	client := sts.NewFromConfig(sdkConfig)
	if _, err = client.GetCallerIdentity(context.Background(), &sts.GetCallerIdentityInput{}); err != nil {
		t.Fatalf("first signed request: %v", err)
	}
	if _, err = client.GetCallerIdentity(context.Background(), &sts.GetCallerIdentityInput{}); err != nil {
		t.Fatalf("second exact signed request: %v", err)
	}
	if resolver.exactCalls != 2 || resolver.credentialCalls != 1 || httpClient.calls != 2 {
		t.Fatalf("exact_calls=%d credential_calls=%d http_calls=%d",
			resolver.exactCalls, resolver.credentialCalls, httpClient.calls)
	}
}
