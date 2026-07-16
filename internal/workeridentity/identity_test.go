package workeridentity

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/awsfoundation"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/google/uuid"
)

const testInstanceID = "i-0123456789abcdef0"

type staticCredentialsProvider struct {
	credentials aws.Credentials
	err         error
}

func (provider staticCredentialsProvider) Retrieve(context.Context) (aws.Credentials, error) {
	return provider.credentials, provider.err
}

type fakeSTSDoer struct {
	t           *testing.T
	accountID   string
	roleName    string
	instanceID  string
	partition   string
	responseErr error
	calls       int
}

func (fake *fakeSTSDoer) Do(request *http.Request) (*http.Response, error) {
	fake.t.Helper()
	fake.calls++
	if fake.responseErr != nil {
		return nil, fake.responseErr
	}
	if request.Method != http.MethodPost || request.URL.String() != "https://sts.us-west-2.amazonaws.com/" || request.Host != "sts.us-west-2.amazonaws.com" {
		fake.t.Fatalf("unexpected forwarded target: method=%s url=%s host=%s", request.Method, request.URL, request.Host)
	}
	allowed := map[string]struct{}{
		"Authorization": {}, "Content-Type": {}, "X-Amz-Content-Sha256": {}, "X-Amz-Date": {},
		"X-Amz-Security-Token": {}, challengeHeader: {},
	}
	for key := range request.Header {
		if _, ok := allowed[key]; !ok {
			fake.t.Fatalf("unexpected forwarded header: %s", key)
		}
	}
	body, err := io.ReadAll(request.Body)
	if err != nil || string(body) != stsBody || request.Header.Get("Authorization") == "" || request.Header.Get("X-Amz-Security-Token") == "" {
		fake.t.Fatalf("invalid forwarded STS request: body=%q err=%v", body, err)
	}
	partition := fake.partition
	if partition == "" {
		partition = "aws"
	}
	xmlBody := fmt.Sprintf(`<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><GetCallerIdentityResult><Arn>arn:%s:sts::%s:assumed-role/%s/%s</Arn><UserId>AROATESTROLEIDENTIFIER:%s</UserId><Account>%s</Account></GetCallerIdentityResult><ResponseMetadata><RequestId>request-id</RequestId></ResponseMetadata></GetCallerIdentityResponse>`,
		partition, fake.accountID, fake.roleName, fake.instanceID, fake.instanceID, fake.accountID)
	return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(xmlBody)), Header: make(http.Header)}, nil
}

type fakeDeploymentAuthorizer struct {
	now       time.Time
	mutate    func(*DeploymentEvidence)
	err       error
	calls     int
	lastClaim DeploymentClaim
}

func (authorizer *fakeDeploymentAuthorizer) AuthorizeDeployment(_ context.Context, claim DeploymentClaim) (DeploymentEvidence, error) {
	authorizer.calls++
	authorizer.lastClaim = claim
	if authorizer.err != nil {
		return DeploymentEvidence{}, authorizer.err
	}
	evidence := DeploymentEvidence{
		Authorized: true, Exists: true, TagsVerified: true,
		AgentInstanceID: claim.AgentInstanceID, OwnerID: claim.OwnerID, DeploymentID: claim.DeploymentID,
		AccountID: claim.AccountID, Region: claim.Region, WorkerRoleName: claim.WorkerRoleName,
		InstanceID: claim.InstanceID, TagDigest: "sha256:" + strings.Repeat("a", 64), ObservedAt: authorizer.now,
	}
	if authorizer.mutate != nil {
		authorizer.mutate(&evidence)
	}
	return evidence, nil
}

func TestSigV4ProofVerifiesFixedWorkerRoleAndIndependentDeploymentReadBack(t *testing.T) {
	fixture := identityFixture(t)
	proof, err := fixture.generator.Generate(context.Background(), GenerateRequest{Region: fixture.request.Region, ChallengeID: fixture.request.ChallengeID})
	if err != nil {
		t.Fatal(err)
	}
	if text := fmt.Sprintf("%v %#v", proof, proof); strings.Contains(text, string(proof.Authorization)) || !strings.Contains(text, "redacted") {
		t.Fatalf("proof formatting exposed authorization: %s", text)
	}
	if _, err := json.Marshal(proof); !errors.Is(err, ErrSensitiveProofJSON) {
		t.Fatalf("proof JSON error=%v", err)
	}
	authorizationBacking := proof.Authorization[:cap(proof.Authorization)]
	sessionBacking := proof.SessionToken[:cap(proof.SessionToken)]
	fixture.request.Proof = &proof
	verified, err := fixture.verifier.Verify(context.Background(), fixture.request)
	if err != nil {
		t.Fatal(err)
	}
	if verified.InstanceID != testInstanceID || verified.WorkerRoleName != fixture.roleName || verified.Trust != TrustSTSAndEC2ReadBack ||
		verified.PrincipalID != "AROATESTROLEIDENTIFIER:"+testInstanceID || fixture.authorizer.lastClaim.PrincipalID != verified.PrincipalID ||
		verified.OwnerID != fixture.request.OwnerID || verified.DeploymentID != fixture.request.DeploymentID || fixture.doer.calls != 1 || fixture.authorizer.calls != 1 {
		t.Fatalf("unexpected verified identity: %+v claim=%+v", verified, fixture.authorizer.lastClaim)
	}
	assertProofDestroyed(t, proof)
	if !allZero(authorizationBacking) || !allZero(sessionBacking) {
		t.Fatal("proof backing memory was not zeroed")
	}
}

func TestProofShapeTamperingAndExpiryFailBeforeSTS(t *testing.T) {
	tests := map[string]struct {
		mutate    func(*ProofV1, *VerificationRequest)
		wantError error
	}{
		"endpoint":  {mutate: func(proof *ProofV1, _ *VerificationRequest) { proof.Endpoint = "https://example.invalid/" }, wantError: ErrInvalidProof},
		"method":    {mutate: func(proof *ProofV1, _ *VerificationRequest) { proof.Method = http.MethodGet }, wantError: ErrInvalidProof},
		"body":      {mutate: func(proof *ProofV1, _ *VerificationRequest) { proof.Body[0] ^= 1 }, wantError: ErrInvalidProof},
		"challenge": {mutate: func(_ *ProofV1, request *VerificationRequest) { request.ChallengeID = uuid.NewString() }, wantError: ErrInvalidProof},
		"authorization": {mutate: func(proof *ProofV1, _ *VerificationRequest) {
			text := strings.Replace(string(proof.Authorization), requiredSignedHeaders, "content-type;host;x-amz-date", 1)
			copy(proof.Authorization, text)
			proof.Authorization = proof.Authorization[:len(text)]
		}, wantError: ErrInvalidProof},
		"header injection": {mutate: func(proof *ProofV1, _ *VerificationRequest) {
			proof.SessionToken = append(proof.SessionToken, '\r', '\n')
		}, wantError: ErrInvalidProof},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			fixture := identityFixture(t)
			proof, err := fixture.generator.Generate(context.Background(), GenerateRequest{Region: fixture.request.Region, ChallengeID: fixture.request.ChallengeID})
			if err != nil {
				t.Fatal(err)
			}
			fixture.request.Proof = &proof
			test.mutate(&proof, &fixture.request)
			if _, err := fixture.verifier.Verify(context.Background(), fixture.request); !errors.Is(err, test.wantError) {
				t.Fatalf("error=%v want=%v", err, test.wantError)
			}
			if fixture.doer.calls != 0 || fixture.authorizer.calls != 0 {
				t.Fatalf("tampered proof reached STS/authorizer: sts=%d auth=%d", fixture.doer.calls, fixture.authorizer.calls)
			}
			assertProofDestroyed(t, proof)
		})
	}

	t.Run("expired", func(t *testing.T) {
		fixture := identityFixture(t)
		generator, _ := NewGenerator(testTemporaryCredentials(fixture.now), func() time.Time { return fixture.now.Add(-2 * time.Minute) })
		proof, err := generator.Generate(context.Background(), GenerateRequest{Region: fixture.request.Region, ChallengeID: fixture.request.ChallengeID})
		if err != nil {
			t.Fatal(err)
		}
		fixture.request.Proof = &proof
		if _, err := fixture.verifier.Verify(context.Background(), fixture.request); !errors.Is(err, ErrProofExpired) {
			t.Fatalf("expired error=%v", err)
		}
		if fixture.doer.calls != 0 {
			t.Fatal("expired proof reached STS")
		}
		assertProofDestroyed(t, proof)
	})
}

func TestGeneratorRejectsStaticOrIncompleteCredentials(t *testing.T) {
	now := time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC)
	tests := map[string]aws.Credentials{
		"static":           {AccessKeyID: "AKIAABCDEFGHIJKLMNOP", SecretAccessKey: strings.Repeat("x", 40)},
		"no session token": {AccessKeyID: "ASIAABCDEFGHIJKLMNOP", SecretAccessKey: strings.Repeat("x", 40), CanExpire: true, Expires: now.Add(time.Hour)},
		"expiring":         {AccessKeyID: "ASIAABCDEFGHIJKLMNOP", SecretAccessKey: strings.Repeat("x", 40), SessionToken: "temporary-session", CanExpire: true, Expires: now.Add(time.Second)},
	}
	for name, credentials := range tests {
		t.Run(name, func(t *testing.T) {
			generator, _ := NewGenerator(staticCredentialsProvider{credentials: credentials}, func() time.Time { return now })
			if _, err := generator.Generate(context.Background(), GenerateRequest{Region: "us-west-2", ChallengeID: uuid.NewString()}); !errors.Is(err, ErrInvalidProof) {
				t.Fatalf("error=%v", err)
			}
		})
	}
}

func TestSTSIdentityAndEC2EvidenceMustMatchEveryDeploymentBoundary(t *testing.T) {
	t.Run("wrong assumed role", func(t *testing.T) {
		fixture := identityFixture(t)
		fixture.doer.roleName = "Administrator"
		proof, _ := fixture.generator.Generate(context.Background(), GenerateRequest{Region: fixture.request.Region, ChallengeID: fixture.request.ChallengeID})
		fixture.request.Proof = &proof
		if _, err := fixture.verifier.Verify(context.Background(), fixture.request); !errors.Is(err, ErrIdentityRejected) {
			t.Fatalf("error=%v", err)
		}
		if fixture.authorizer.calls != 0 {
			t.Fatal("wrong role reached deployment authorizer")
		}
		assertProofDestroyed(t, proof)
	})

	for name, mutate := range map[string]func(*DeploymentEvidence){
		"owner":      func(value *DeploymentEvidence) { value.OwnerID = "other-owner" },
		"deployment": func(value *DeploymentEvidence) { value.DeploymentID = uuid.NewString() },
		"account":    func(value *DeploymentEvidence) { value.AccountID = "210987654321" },
		"region":     func(value *DeploymentEvidence) { value.Region = "us-east-1" },
		"role":       func(value *DeploymentEvidence) { value.WorkerRoleName = "other-role" },
		"instance":   func(value *DeploymentEvidence) { value.InstanceID = "i-0abcdef0123456789" },
		"missing":    func(value *DeploymentEvidence) { value.Exists = false },
		"tags":       func(value *DeploymentEvidence) { value.TagsVerified = false },
		"tag digest": func(value *DeploymentEvidence) { value.TagDigest = "" },
		"stale":      func(value *DeploymentEvidence) { value.ObservedAt = value.ObservedAt.Add(-3 * time.Minute) },
	} {
		t.Run("evidence "+name, func(t *testing.T) {
			fixture := identityFixture(t)
			fixture.authorizer.mutate = mutate
			proof, _ := fixture.generator.Generate(context.Background(), GenerateRequest{Region: fixture.request.Region, ChallengeID: fixture.request.ChallengeID})
			fixture.request.Proof = &proof
			if _, err := fixture.verifier.Verify(context.Background(), fixture.request); !errors.Is(err, ErrIdentityRejected) {
				t.Fatalf("error=%v", err)
			}
			assertProofDestroyed(t, proof)
		})
	}
}

func TestSTSRegionalEndpointAllowlistSupportsOnlyFoundationPartitions(t *testing.T) {
	tests := map[string]struct {
		endpoint  string
		partition string
		valid     bool
	}{
		"us-west-2":      {endpoint: "https://sts.us-west-2.amazonaws.com/", partition: "aws", valid: true},
		"cn-north-1":     {endpoint: "https://sts.cn-north-1.amazonaws.com.cn/", partition: "aws-cn", valid: true},
		"us-gov-west-1":  {endpoint: "https://sts.us-gov-west-1.amazonaws.com/", partition: "aws-us-gov", valid: true},
		"us-iso-east-1":  {valid: false},
		"eu-isoe-west-1": {valid: false},
	}
	for region, test := range tests {
		t.Run(region, func(t *testing.T) {
			endpoint, partition, err := stsEndpoint(region)
			if test.valid && (err != nil || endpoint != test.endpoint || partition != test.partition) {
				t.Fatalf("endpoint=%s partition=%s err=%v", endpoint, partition, err)
			}
			if !test.valid && !errors.Is(err, ErrInvalidProof) {
				t.Fatalf("invalid partition error=%v", err)
			}
		})
	}
}

func TestSTSErrorsAreBoundedAndDoNotLeakProof(t *testing.T) {
	fixture := identityFixture(t)
	fixture.doer.responseErr = errors.New("upstream exposed Authorization and sk-abcdefghijklmnopqrstuvwxyz012345")
	proof, _ := fixture.generator.Generate(context.Background(), GenerateRequest{Region: fixture.request.Region, ChallengeID: fixture.request.ChallengeID})
	fixture.request.Proof = &proof
	_, err := fixture.verifier.Verify(context.Background(), fixture.request)
	if !errors.Is(err, ErrSTSUnavailable) || strings.Contains(err.Error(), "sk-") || strings.Contains(err.Error(), "Authorization") {
		t.Fatalf("unsafe error=%v", err)
	}
	assertProofDestroyed(t, proof)
}

type identityTestFixture struct {
	now        time.Time
	roleName   string
	generator  *Generator
	verifier   *Verifier
	doer       *fakeSTSDoer
	authorizer *fakeDeploymentAuthorizer
	request    VerificationRequest
}

func identityFixture(t *testing.T) identityTestFixture {
	t.Helper()
	now := time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC)
	agentID := uuid.NewString()
	spec, err := awsfoundation.BuildSpec(awsfoundation.SpecInput{AgentInstanceID: agentID, Partition: "aws", AccountID: "123456789012", Region: "us-west-2"})
	if err != nil {
		t.Fatal(err)
	}
	generator, err := NewGenerator(testTemporaryCredentials(now), func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	doer := &fakeSTSDoer{t: t, accountID: "123456789012", roleName: spec.WorkerRoleName, instanceID: testInstanceID}
	authorizer := &fakeDeploymentAuthorizer{now: now}
	verifier, err := NewVerifier(agentID, doer, authorizer, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	return identityTestFixture{
		now: now, roleName: spec.WorkerRoleName, generator: generator, verifier: verifier, doer: doer, authorizer: authorizer,
		request: VerificationRequest{ChallengeID: uuid.NewString(), AccountID: "123456789012", Region: "us-west-2", OwnerID: "owner-1", DeploymentID: uuid.NewString()},
	}
}

func testTemporaryCredentials(now time.Time) aws.CredentialsProvider {
	return staticCredentialsProvider{credentials: aws.Credentials{
		AccessKeyID: "ASIAABCDEFGHIJKLMNOP", SecretAccessKey: strings.Repeat("x", 40),
		SessionToken: "temporary-instance-role-session-token", CanExpire: true, Expires: now.Add(time.Hour), Source: "EC2RoleProvider",
	}}
}

func assertProofDestroyed(t *testing.T, proof ProofV1) {
	t.Helper()
	if proof.SchemaVersion != 0 || proof.Region != "" || proof.Endpoint != "" || proof.Method != "" || proof.Host != "" ||
		proof.ContentType != "" || proof.ContentSHA256 != "" || proof.AmzDate != "" || proof.ChallengeID != "" ||
		proof.Body != nil || proof.Authorization != nil || proof.SessionToken != nil {
		t.Fatalf("proof was not destroyed: %v", proof)
	}
}

func allZero(value []byte) bool {
	for _, item := range value {
		if item != 0 {
			return false
		}
	}
	return true
}
