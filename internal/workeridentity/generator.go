package workeridentity

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/google/uuid"
)

const (
	stsBody         = "Action=GetCallerIdentity&Version=2011-06-15"
	stsContentType  = "application/x-www-form-urlencoded; charset=utf-8"
	challengeHeader = "X-Dirextalk-Enrollment-Challenge"
	proofMaxAge     = 90 * time.Second
)

var (
	regionPattern             = regexp.MustCompile(`^[a-z]{2}(?:-[a-z0-9]+)+-[0-9]+$`)
	temporaryAccessKeyPattern = regexp.MustCompile(`^ASIA[A-Z0-9]{16}$`)
)

type HTTPSigner interface {
	SignHTTP(context.Context, aws.Credentials, *http.Request, string, string, string, time.Time, ...func(*v4.SignerOptions)) error
}

type Generator struct {
	credentials aws.CredentialsProvider
	signer      HTTPSigner
	now         func() time.Time
}

func NewGenerator(credentials aws.CredentialsProvider, now func() time.Time) (*Generator, error) {
	return NewGeneratorWithSigner(credentials, v4.NewSigner(), now)
}

func NewGeneratorWithSigner(credentials aws.CredentialsProvider, signer HTTPSigner, now func() time.Time) (*Generator, error) {
	if credentials == nil || signer == nil || now == nil {
		return nil, ErrInvalidProof
	}
	return &Generator{credentials: credentials, signer: signer, now: now}, nil
}

func (generator *Generator) Generate(ctx context.Context, request GenerateRequest) (ProofV1, error) {
	region := strings.TrimSpace(request.Region)
	challenge, err := uuid.Parse(strings.TrimSpace(request.ChallengeID))
	if err != nil || challenge == uuid.Nil || !regionPattern.MatchString(region) {
		return ProofV1{}, ErrInvalidProof
	}
	endpoint, _, err := stsEndpoint(region)
	if err != nil {
		return ProofV1{}, err
	}
	now := generator.now().UTC()
	credentials, err := generator.credentials.Retrieve(ctx)
	if err != nil || !credentials.CanExpire || credentials.Expires.Before(now.Add(proofMaxAge)) ||
		!temporaryAccessKeyPattern.MatchString(credentials.AccessKeyID) || credentials.SecretAccessKey == "" || credentials.SessionToken == "" {
		credentials = aws.Credentials{}
		return ProofV1{}, ErrInvalidProof
	}
	body := []byte(stsBody)
	digest := sha256.Sum256(body)
	digestText := hex.EncodeToString(digest[:])
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		credentials = aws.Credentials{}
		clear(body)
		return ProofV1{}, ErrInvalidProof
	}
	httpRequest.Header.Set("Content-Type", stsContentType)
	httpRequest.Header.Set("X-Amz-Content-Sha256", digestText)
	httpRequest.Header.Set(challengeHeader, challenge.String())
	if err := generator.signer.SignHTTP(ctx, credentials, httpRequest, digestText, "sts", region, now); err != nil {
		credentials = aws.Credentials{}
		clear(body)
		return ProofV1{}, ErrInvalidProof
	}
	credentials = aws.Credentials{}
	authorization := []byte(httpRequest.Header.Get("Authorization"))
	sessionToken := []byte(httpRequest.Header.Get("X-Amz-Security-Token"))
	proof := ProofV1{
		SchemaVersion: 1, Region: region, Endpoint: endpoint, Method: http.MethodPost, Host: httpRequest.URL.Host,
		ContentType: stsContentType, ContentSHA256: digestText, AmzDate: httpRequest.Header.Get("X-Amz-Date"),
		ChallengeID: challenge.String(), Body: body, Authorization: authorization, SessionToken: sessionToken,
	}
	httpRequest.Header.Del("Authorization")
	httpRequest.Header.Del("X-Amz-Security-Token")
	if err := validateProofShape(&proof, challenge.String(), region, now); err != nil {
		proof.Destroy()
		return ProofV1{}, err
	}
	return proof, nil
}

func stsEndpoint(region string) (string, string, error) {
	if !regionPattern.MatchString(region) || strings.HasPrefix(region, "us-iso-") || strings.HasPrefix(region, "us-isob-") ||
		strings.HasPrefix(region, "us-isof-") || strings.HasPrefix(region, "eu-isoe-") {
		return "", "", ErrInvalidProof
	}
	partition, suffix := "aws", "amazonaws.com"
	if strings.HasPrefix(region, "cn-") {
		partition, suffix = "aws-cn", "amazonaws.com.cn"
	} else if strings.HasPrefix(region, "us-gov-") {
		partition = "aws-us-gov"
	}
	return "https://sts." + region + "." + suffix + "/", partition, nil
}
