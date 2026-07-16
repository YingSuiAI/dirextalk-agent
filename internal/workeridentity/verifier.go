package workeridentity

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/awsfoundation"
	"github.com/YingSuiAI/dirextalk-agent/internal/security"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/google/uuid"
)

const (
	maxAuthorizationBytes = 4096
	maxSessionTokenBytes  = 8192
	maxSTSResponseBytes   = 32 << 10
	evidenceMaxAge        = 2 * time.Minute

	requiredSignedHeaders = "content-length;content-type;host;x-amz-content-sha256;x-amz-date;x-amz-security-token;x-dirextalk-enrollment-challenge"
)

var (
	accountPattern        = regexp.MustCompile(`^[0-9]{12}$`)
	instancePattern       = regexp.MustCompile(`^i-[0-9a-f]{8,17}$`)
	signaturePattern      = regexp.MustCompile(`^[a-f0-9]{64}$`)
	credentialDatePattern = regexp.MustCompile(`^[0-9]{8}$`)
	tagDigestPattern      = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)
)

type HTTPDoer interface {
	Do(*http.Request) (*http.Response, error)
}

type Verifier struct {
	agentInstanceID string
	http            HTTPDoer
	authorizer      DeploymentResourceAuthorizer
	now             func() time.Time
}

func NewVerifier(agentInstanceID string, client HTTPDoer, authorizer DeploymentResourceAuthorizer, now func() time.Time) (*Verifier, error) {
	instance, err := uuid.Parse(strings.TrimSpace(agentInstanceID))
	if err != nil || instance == uuid.Nil || client == nil || authorizer == nil || now == nil {
		return nil, ErrInvalidProof
	}
	return &Verifier{agentInstanceID: instance.String(), http: client, authorizer: authorizer, now: now}, nil
}

func NewDefaultVerifier(agentInstanceID string, authorizer DeploymentResourceAuthorizer, now func() time.Time) (*Verifier, error) {
	baseTransport, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return nil, ErrInvalidProof
	}
	transport := baseTransport.Clone()
	transport.Proxy = nil
	transport.DisableCompression = true
	if transport.TLSClientConfig == nil {
		transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	} else {
		transport.TLSClientConfig = transport.TLSClientConfig.Clone()
		if transport.TLSClientConfig.MinVersion < tls.VersionTLS12 {
			transport.TLSClientConfig.MinVersion = tls.VersionTLS12
		}
	}
	client := &http.Client{
		Transport: transport, Timeout: 10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	return NewVerifier(agentInstanceID, client, authorizer, now)
}

func (verifier *Verifier) Verify(ctx context.Context, request VerificationRequest) (VerifiedIdentity, error) {
	if request.Proof == nil {
		return VerifiedIdentity{}, ErrInvalidProof
	}
	proof := request.Proof
	defer proof.Destroy()
	now := verifier.now().UTC()
	if err := validateVerificationRequest(request); err != nil {
		return VerifiedIdentity{}, err
	}
	if err := validateProofShape(proof, request.ChallengeID, request.Region, now); err != nil {
		return VerifiedIdentity{}, err
	}
	httpRequest, err := forwardedSTSRequest(ctx, proof)
	if err != nil {
		return VerifiedIdentity{}, ErrInvalidProof
	}
	response, err := verifier.http.Do(httpRequest)
	httpRequest.Header.Del("Authorization")
	httpRequest.Header.Del("X-Amz-Security-Token")
	if err != nil || response == nil {
		return VerifiedIdentity{}, ErrSTSUnavailable
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return VerifiedIdentity{}, ErrIdentityRejected
	}
	identity, err := decodeSTSIdentity(response.Body)
	if err != nil || identity.Result.Account != request.AccountID {
		return VerifiedIdentity{}, ErrIdentityRejected
	}
	claim, err := verifier.claimFromIdentity(identity, request)
	if err != nil {
		return VerifiedIdentity{}, err
	}
	evidence, err := verifier.authorizer.AuthorizeDeployment(ctx, claim)
	if err != nil || !validEvidence(evidence, claim, now) {
		return VerifiedIdentity{}, ErrIdentityRejected
	}
	return VerifiedIdentity{
		Partition: claim.Partition, AccountID: claim.AccountID, Region: claim.Region,
		WorkerRoleName: claim.WorkerRoleName, InstanceID: claim.InstanceID, PrincipalID: claim.PrincipalID,
		DeploymentID: claim.DeploymentID, OwnerID: claim.OwnerID,
		Trust: TrustSTSAndEC2ReadBack, VerifiedAt: now,
	}, nil
}

func validateVerificationRequest(request VerificationRequest) error {
	challenge, challengeErr := uuid.Parse(strings.TrimSpace(request.ChallengeID))
	deployment, deploymentErr := uuid.Parse(strings.TrimSpace(request.DeploymentID))
	if challengeErr != nil || challenge == uuid.Nil || deploymentErr != nil || deployment == uuid.Nil ||
		!accountPattern.MatchString(request.AccountID) || !regionPattern.MatchString(request.Region) ||
		request.OwnerID == "" || len(request.OwnerID) > 255 || security.ContainsLikelySecret(request.OwnerID) {
		return ErrInvalidProof
	}
	return nil
}

func validateProofShape(proof *ProofV1, expectedChallenge, expectedRegion string, now time.Time) error {
	if proof == nil || proof.SchemaVersion != 1 || proof.Method != http.MethodPost || proof.Region != expectedRegion ||
		proof.ContentType != stsContentType || proof.ChallengeID != expectedChallenge || len(proof.Body) != len(stsBody) || !bytes.Equal(proof.Body, []byte(stsBody)) ||
		len(proof.Authorization) == 0 || len(proof.Authorization) > maxAuthorizationBytes || len(proof.SessionToken) == 0 || len(proof.SessionToken) > maxSessionTokenBytes ||
		strings.ContainsAny(proof.Endpoint+proof.Host+proof.ContentType+proof.ContentSHA256+proof.AmzDate+proof.ChallengeID, "\r\n\x00") {
		return ErrInvalidProof
	}
	endpoint, _, err := stsEndpoint(expectedRegion)
	if err != nil || proof.Endpoint != endpoint || proof.Host != strings.TrimPrefix(strings.TrimSuffix(endpoint, "/"), "https://") {
		return ErrInvalidProof
	}
	digest := sha256.Sum256([]byte(stsBody))
	if proof.ContentSHA256 != hex.EncodeToString(digest[:]) {
		return ErrInvalidProof
	}
	signedAt, err := time.Parse("20060102T150405Z", proof.AmzDate)
	if err != nil || signedAt.After(now.Add(30*time.Second)) {
		return ErrInvalidProof
	}
	if now.Sub(signedAt) > proofMaxAge {
		return ErrProofExpired
	}
	return validateAuthorization(proof, signedAt)
}

func validateAuthorization(proof *ProofV1, signedAt time.Time) error {
	authorization := string(proof.Authorization)
	if strings.ContainsAny(authorization+string(proof.SessionToken), "\r\n\x00") || !strings.HasPrefix(authorization, "AWS4-HMAC-SHA256 ") {
		return ErrInvalidProof
	}
	parts := strings.Split(strings.TrimPrefix(authorization, "AWS4-HMAC-SHA256 "), ", ")
	if len(parts) != 3 || !strings.HasPrefix(parts[0], "Credential=") || !strings.HasPrefix(parts[1], "SignedHeaders=") || !strings.HasPrefix(parts[2], "Signature=") {
		return ErrInvalidProof
	}
	credential := strings.Split(strings.TrimPrefix(parts[0], "Credential="), "/")
	if len(credential) != 5 || !temporaryAccessKeyPattern.MatchString(credential[0]) || !credentialDatePattern.MatchString(credential[1]) ||
		credential[1] != signedAt.UTC().Format("20060102") || credential[2] != proof.Region || credential[3] != "sts" || credential[4] != "aws4_request" ||
		strings.TrimPrefix(parts[1], "SignedHeaders=") != requiredSignedHeaders || !signaturePattern.MatchString(strings.TrimPrefix(parts[2], "Signature=")) {
		return ErrInvalidProof
	}
	return nil
}

func forwardedSTSRequest(ctx context.Context, proof *ProofV1) (*http.Request, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, proof.Endpoint, bytes.NewReader([]byte(stsBody)))
	if err != nil {
		return nil, err
	}
	request.Host = proof.Host
	request.Header.Set("Content-Type", stsContentType)
	request.Header.Set("X-Amz-Content-Sha256", proof.ContentSHA256)
	request.Header.Set("X-Amz-Date", proof.AmzDate)
	request.Header.Set(challengeHeader, proof.ChallengeID)
	request.Header.Set("Authorization", string(proof.Authorization))
	request.Header.Set("X-Amz-Security-Token", string(proof.SessionToken))
	return request, nil
}

type stsIdentityResponse struct {
	Result struct {
		Arn     string `xml:"Arn"`
		UserID  string `xml:"UserId"`
		Account string `xml:"Account"`
	} `xml:"GetCallerIdentityResult"`
}

func decodeSTSIdentity(body io.Reader) (stsIdentityResponse, error) {
	limited := io.LimitReader(body, maxSTSResponseBytes+1)
	raw, err := io.ReadAll(limited)
	if err != nil || len(raw) == 0 || len(raw) > maxSTSResponseBytes {
		clear(raw)
		return stsIdentityResponse{}, ErrIdentityRejected
	}
	defer clear(raw)
	decoder := xml.NewDecoder(bytes.NewReader(raw))
	decoder.Strict = true
	var response stsIdentityResponse
	if err := decoder.Decode(&response); err != nil {
		return stsIdentityResponse{}, ErrIdentityRejected
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return stsIdentityResponse{}, ErrIdentityRejected
	}
	if !accountPattern.MatchString(response.Result.Account) || response.Result.Arn == "" || response.Result.UserID == "" {
		return stsIdentityResponse{}, ErrIdentityRejected
	}
	return response, nil
}

func (verifier *Verifier) claimFromIdentity(identity stsIdentityResponse, request VerificationRequest) (DeploymentClaim, error) {
	parsed, err := arn.Parse(identity.Result.Arn)
	if err != nil || parsed.Service != "sts" || parsed.AccountID != identity.Result.Account {
		return DeploymentClaim{}, ErrIdentityRejected
	}
	_, partition, endpointErr := stsEndpoint(request.Region)
	if endpointErr != nil || parsed.Partition != partition {
		return DeploymentClaim{}, ErrIdentityRejected
	}
	resourceParts := strings.Split(parsed.Resource, "/")
	userParts := strings.Split(identity.Result.UserID, ":")
	if len(resourceParts) != 3 || resourceParts[0] != "assumed-role" || !instancePattern.MatchString(resourceParts[2]) ||
		len(userParts) != 2 || len(userParts[0]) < 16 || len(userParts[0]) > 128 || userParts[1] != resourceParts[2] ||
		strings.IndexFunc(userParts[0], func(value rune) bool { return !(value >= 'A' && value <= 'Z') && !(value >= '0' && value <= '9') }) >= 0 {
		return DeploymentClaim{}, ErrIdentityRejected
	}
	spec, err := awsfoundation.BuildSpec(awsfoundation.SpecInput{
		AgentInstanceID: verifier.agentInstanceID, Partition: partition,
		AccountID: request.AccountID, Region: request.Region,
	})
	if err != nil || resourceParts[1] != spec.WorkerRoleName {
		return DeploymentClaim{}, ErrIdentityRejected
	}
	return DeploymentClaim{
		AgentInstanceID: verifier.agentInstanceID, OwnerID: request.OwnerID, DeploymentID: request.DeploymentID,
		Partition: partition, AccountID: request.AccountID, Region: request.Region,
		WorkerRoleName: spec.WorkerRoleName, InstanceID: resourceParts[2], PrincipalID: identity.Result.UserID,
	}, nil
}

func validEvidence(evidence DeploymentEvidence, claim DeploymentClaim, now time.Time) bool {
	return evidence.Authorized && evidence.Exists && evidence.TagsVerified &&
		evidence.AgentInstanceID == claim.AgentInstanceID && evidence.OwnerID == claim.OwnerID && evidence.DeploymentID == claim.DeploymentID &&
		evidence.AccountID == claim.AccountID && evidence.Region == claim.Region && evidence.WorkerRoleName == claim.WorkerRoleName && evidence.InstanceID == claim.InstanceID &&
		tagDigestPattern.MatchString(evidence.TagDigest) &&
		!evidence.ObservedAt.IsZero() && !evidence.ObservedAt.After(now.Add(30*time.Second)) && now.Sub(evidence.ObservedAt) <= evidenceMaxAge
}
