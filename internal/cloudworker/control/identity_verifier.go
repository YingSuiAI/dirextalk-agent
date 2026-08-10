package control

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/identitywire"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
)

const (
	stsIdentityBody        = "Action=GetCallerIdentity&Version=2011-06-15"
	stsIdentityContentType = "application/x-www-form-urlencoded; charset=utf-8"
	workerChallengeHeader  = "X-Dirextalk-Worker-Challenge"
	identityProofMaxAge    = 90 * time.Second
	maximumSTSBodyBytes    = 32 << 10
	requiredSignedHeaders  = "content-length;content-type;host;x-amz-content-sha256;x-amz-date;x-amz-security-token;x-dirextalk-worker-challenge"
)

var (
	temporaryAccessKeyPattern = regexp.MustCompile(`^ASIA[A-Z0-9]{16}$`)
	signaturePattern          = regexp.MustCompile(`^[a-f0-9]{64}$`)
	credentialDatePattern     = regexp.MustCompile(`^[0-9]{8}$`)
)

type identityHTTPDoer interface {
	Do(*http.Request) (*http.Response, error)
}

type STSSigV4IdentityVerifier struct {
	http     identityHTTPDoer
	iid      *PKCS7IIDVerifier
	evidence IdentityEvidenceReader
	now      func() time.Time
}

func NewSTSSigV4IdentityVerifier(
	iid *PKCS7IIDVerifier,
	evidence IdentityEvidenceReader,
	now func() time.Time,
) (*STSSigV4IdentityVerifier, error) {
	baseTransport, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return nil, ErrInvalid
	}
	transport := baseTransport.Clone()
	transport.Proxy = nil
	transport.DisableCompression = true
	if transport.TLSClientConfig == nil {
		transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	} else {
		transport.TLSClientConfig = transport.TLSClientConfig.Clone()
		transport.TLSClientConfig.MinVersion = tls.VersionTLS12
	}
	client := &http.Client{
		Transport: transport, Timeout: 10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return ErrIdentityRejected },
	}
	return newSTSSigV4IdentityVerifier(client, iid, evidence, now)
}

func newSTSSigV4IdentityVerifier(
	httpClient identityHTTPDoer,
	iid *PKCS7IIDVerifier,
	evidence IdentityEvidenceReader,
	now func() time.Time,
) (*STSSigV4IdentityVerifier, error) {
	if httpClient == nil || iid == nil || evidence == nil || now == nil {
		return nil, ErrInvalid
	}
	return &STSSigV4IdentityVerifier{
		http: httpClient, iid: iid, evidence: evidence, now: now,
	}, nil
}

func (verifier *STSSigV4IdentityVerifier) Verify(
	ctx context.Context,
	nonce string,
	proof IdentityProof,
) (IdentityClaims, error) {
	defer clear(proof.Payload)
	if verifier == nil || ctx == nil || proof.Method != identitywire.MethodSTSSigV4IMDSPKCS7V1 ||
		len(proof.Payload) == 0 || len(proof.Payload) > maximumProofBytes ||
		nonce == "" || nonce != strings.TrimSpace(nonce) || len(nonce) < 32 ||
		len(nonce) > 1024 || strings.ContainsAny(nonce, "\r\n\x00") {
		logIdentityVerificationRejected("request")
		return IdentityClaims{}, ErrIdentityRejected
	}
	payload, err := identitywire.Decode(proof.Payload)
	if err != nil {
		logIdentityVerificationRejected("payload_decode")
		return IdentityClaims{}, ErrIdentityRejected
	}
	defer payload.Destroy()
	document, err := verifier.verifyPayload(payload, nonce)
	if err != nil {
		logIdentityVerificationRejected("payload_verify")
		return IdentityClaims{}, ErrIdentityRejected
	}
	stsIdentity, err := verifier.replaySTS(ctx, payload)
	if err != nil || stsIdentity.Account != document.AccountID {
		logIdentityVerificationRejected("sts_replay")
		return IdentityClaims{}, ErrIdentityRejected
	}
	roleARN, roleID, err := parseSTSRole(stsIdentity, document)
	if err != nil {
		logIdentityVerificationRejected("sts_role")
		return IdentityClaims{}, ErrIdentityRejected
	}
	claims, err := verifier.evidence.ReadIdentityEvidence(ctx, AttestedInstance{
		AccountID: document.AccountID, Region: document.Region,
		InstanceID: document.InstanceID, RoleARN: roleARN,
		RoleID: roleID, PendingTime: document.PendingTime,
	})
	if err != nil {
		logIdentityVerificationRejected("identity_evidence")
		return IdentityClaims{}, ErrIdentityRejected
	}
	return claims, nil
}

func logIdentityVerificationRejected(stage string) {
	slog.Warn("[cloud-worker.identity] verification_rejected", "stage", stage)
}

type instanceIdentityDocument struct {
	AccountID   string    `json:"accountId"`
	Region      string    `json:"region"`
	InstanceID  string    `json:"instanceId"`
	PendingTime time.Time `json:"pendingTime"`
}

func (verifier *STSSigV4IdentityVerifier) verifyPayload(
	payload identitywire.Payload,
	nonce string,
) (instanceIdentityDocument, error) {
	var document instanceIdentityDocument
	if len(payload.IMDSDocument) == 0 || len(payload.IMDSDocument) > maximumProofBytes ||
		json.Unmarshal(payload.IMDSDocument, &document) != nil ||
		!accountPattern.MatchString(document.AccountID) ||
		!regionPattern.MatchString(document.Region) ||
		!instancePattern.MatchString(document.InstanceID) || document.PendingTime.IsZero() {
		return instanceIdentityDocument{}, ErrIdentityRejected
	}
	if err := verifier.iid.Verify(payload.IMDSDocument, payload.IMDSPKCS7, document.Region); err != nil {
		return instanceIdentityDocument{}, ErrIdentityRejected
	}
	endpoint, err := regionalSTSEndpoint(document.Region)
	if err != nil || payload.Region != document.Region || payload.Endpoint != endpoint ||
		payload.Method != http.MethodPost || payload.Host != strings.TrimPrefix(strings.TrimSuffix(endpoint, "/"), "https://") ||
		payload.ContentType != stsIdentityContentType || payload.Challenge != nonce ||
		!bytes.Equal(payload.Body, []byte(stsIdentityBody)) ||
		len(payload.Authorization) == 0 || len(payload.Authorization) > 4096 ||
		len(payload.SessionToken) == 0 || len(payload.SessionToken) > 16<<10 ||
		strings.ContainsAny(payload.Endpoint+payload.Host+payload.ContentType+payload.ContentSHA256+payload.AmzDate+payload.Challenge, "\r\n\x00") {
		return instanceIdentityDocument{}, ErrIdentityRejected
	}
	digest := sha256.Sum256([]byte(stsIdentityBody))
	if payload.ContentSHA256 != hex.EncodeToString(digest[:]) {
		return instanceIdentityDocument{}, ErrIdentityRejected
	}
	signedAt, err := time.Parse("20060102T150405Z", payload.AmzDate)
	now := verifier.now().UTC()
	if err != nil || signedAt.After(now.Add(30*time.Second)) || now.Sub(signedAt) > identityProofMaxAge ||
		validateAuthorization(payload, signedAt) != nil {
		return instanceIdentityDocument{}, ErrIdentityRejected
	}
	return document, nil
}

func validateAuthorization(payload identitywire.Payload, signedAt time.Time) error {
	authorization := string(payload.Authorization)
	if strings.ContainsAny(authorization+string(payload.SessionToken), "\r\n\x00") ||
		!strings.HasPrefix(authorization, "AWS4-HMAC-SHA256 ") {
		return ErrIdentityRejected
	}
	parts := strings.Split(strings.TrimPrefix(authorization, "AWS4-HMAC-SHA256 "), ", ")
	if len(parts) != 3 || !strings.HasPrefix(parts[0], "Credential=") ||
		!strings.HasPrefix(parts[1], "SignedHeaders=") ||
		!strings.HasPrefix(parts[2], "Signature=") {
		return ErrIdentityRejected
	}
	credential := strings.Split(strings.TrimPrefix(parts[0], "Credential="), "/")
	if len(credential) != 5 || !temporaryAccessKeyPattern.MatchString(credential[0]) ||
		!credentialDatePattern.MatchString(credential[1]) ||
		credential[1] != signedAt.UTC().Format("20060102") ||
		credential[2] != payload.Region || credential[3] != "sts" ||
		credential[4] != "aws4_request" ||
		strings.TrimPrefix(parts[1], "SignedHeaders=") != requiredSignedHeaders ||
		!signaturePattern.MatchString(strings.TrimPrefix(parts[2], "Signature=")) {
		return ErrIdentityRejected
	}
	return nil
}

func (verifier *STSSigV4IdentityVerifier) replaySTS(
	ctx context.Context,
	payload identitywire.Payload,
) (stsIdentityResponse, error) {
	request, err := http.NewRequestWithContext(
		ctx, http.MethodPost, payload.Endpoint, bytes.NewReader([]byte(stsIdentityBody)),
	)
	if err != nil {
		return stsIdentityResponse{}, ErrIdentityRejected
	}
	request.Host = payload.Host
	request.Header.Set("Content-Type", payload.ContentType)
	request.Header.Set("X-Amz-Content-Sha256", payload.ContentSHA256)
	request.Header.Set("X-Amz-Date", payload.AmzDate)
	request.Header.Set(workerChallengeHeader, payload.Challenge)
	request.Header.Set("Authorization", string(payload.Authorization))
	request.Header.Set("X-Amz-Security-Token", string(payload.SessionToken))
	response, err := verifier.http.Do(request)
	request.Header.Del("Authorization")
	request.Header.Del("X-Amz-Security-Token")
	if err != nil || response == nil || response.Body == nil {
		return stsIdentityResponse{}, ErrIdentityRejected
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return stsIdentityResponse{}, ErrIdentityRejected
	}
	limited := io.LimitReader(response.Body, maximumSTSBodyBytes+1)
	raw, err := io.ReadAll(limited)
	if err != nil || len(raw) == 0 || len(raw) > maximumSTSBodyBytes {
		clear(raw)
		return stsIdentityResponse{}, ErrIdentityRejected
	}
	defer clear(raw)
	decoder := xml.NewDecoder(bytes.NewReader(raw))
	decoder.Strict = true
	var decoded stsIdentityResponse
	if decoder.Decode(&decoded) != nil {
		return stsIdentityResponse{}, ErrIdentityRejected
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) ||
		!accountPattern.MatchString(decoded.Account) || decoded.ARN == "" || decoded.UserID == "" {
		return stsIdentityResponse{}, ErrIdentityRejected
	}
	return decoded, nil
}

type stsIdentityResponse struct {
	ARN     string `xml:"GetCallerIdentityResult>Arn"`
	UserID  string `xml:"GetCallerIdentityResult>UserId"`
	Account string `xml:"GetCallerIdentityResult>Account"`
}

func parseSTSRole(
	identity stsIdentityResponse,
	document instanceIdentityDocument,
) (string, string, error) {
	parsed, err := arn.Parse(identity.ARN)
	if err != nil || parsed.Service != "sts" || parsed.AccountID != document.AccountID {
		return "", "", ErrIdentityRejected
	}
	partition, err := partitionForRegion(document.Region)
	if err != nil || parsed.Partition != partition {
		return "", "", ErrIdentityRejected
	}
	resource := strings.Split(parsed.Resource, "/")
	user := strings.Split(identity.UserID, ":")
	if len(resource) != 3 || resource[0] != "assumed-role" || resource[1] == "" ||
		resource[2] != document.InstanceID || len(user) != 2 || user[1] != document.InstanceID ||
		!iamIDPattern.MatchString(user[0]) {
		return "", "", ErrIdentityRejected
	}
	return "arn:" + partition + ":iam::" + document.AccountID + ":role/" + resource[1],
		user[0], nil
}

func regionalSTSEndpoint(region string) (string, error) {
	partition, err := partitionForRegion(region)
	if err != nil {
		return "", err
	}
	suffix := "amazonaws.com"
	if partition == "aws-cn" {
		suffix = "amazonaws.com.cn"
	}
	return "https://sts." + region + "." + suffix + "/", nil
}

func partitionForRegion(region string) (string, error) {
	if !regionPattern.MatchString(region) || strings.HasPrefix(region, "us-iso-") ||
		strings.HasPrefix(region, "us-isob-") || strings.HasPrefix(region, "us-isof-") ||
		strings.HasPrefix(region, "eu-isoe-") {
		return "", ErrIdentityRejected
	}
	if strings.HasPrefix(region, "cn-") {
		return "aws-cn", nil
	}
	if strings.HasPrefix(region, "us-gov-") {
		return "aws-us-gov", nil
	}
	return "aws", nil
}

var _ IdentityVerifier = (*STSSigV4IdentityVerifier)(nil)
