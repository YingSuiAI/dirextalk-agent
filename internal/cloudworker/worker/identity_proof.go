package worker

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
)

const (
	stsBody               = "Action=GetCallerIdentity&Version=2011-06-15"
	stsContentType        = "application/x-www-form-urlencoded; charset=utf-8"
	workerChallengeHeader = "X-Dirextalk-Worker-Challenge"
	minimumProofLifetime  = 90 * time.Second
)

var temporaryAccessKeyPattern = regexp.MustCompile(`^ASIA[A-Z0-9]{16}$`)

type HTTPSigner interface {
	SignHTTP(context.Context, aws.Credentials, *http.Request, string, string, string, time.Time, ...func(*v4.SignerOptions)) error
}

type SigV4ProofGenerator struct {
	credentials aws.CredentialsProvider
	signer      HTTPSigner
	now         func() time.Time
}

func NewSigV4ProofGenerator(
	credentials aws.CredentialsProvider,
	now func() time.Time,
) (*SigV4ProofGenerator, error) {
	return newSigV4ProofGenerator(credentials, v4.NewSigner(), now)
}

func newSigV4ProofGenerator(
	credentials aws.CredentialsProvider,
	signer HTTPSigner,
	now func() time.Time,
) (*SigV4ProofGenerator, error) {
	if credentials == nil || signer == nil || now == nil {
		return nil, ErrInvalid
	}
	return &SigV4ProofGenerator{credentials: credentials, signer: signer, now: now}, nil
}

func (generator *SigV4ProofGenerator) Generate(
	ctx context.Context,
	challenge string,
	binding Binding,
	identity InstanceIdentity,
) (IdentityProof, error) {
	if generator == nil || ctx == nil || binding.Validate() != nil ||
		challenge == "" || challenge != strings.TrimSpace(challenge) ||
		len(challenge) < 32 || len(challenge) > 1024 ||
		strings.ContainsAny(challenge, "\r\n\x00") ||
		identity.AccountID != binding.AccountID || identity.Region != binding.Region ||
		identity.InstanceID != binding.InstanceID || len(identity.Document) == 0 ||
		len(identity.PKCS7) == 0 {
		return IdentityProof{}, ErrInvalid
	}
	endpoint, err := regionalSTSEndpoint(binding.Region)
	if err != nil {
		return IdentityProof{}, err
	}
	now := generator.now().UTC()
	credentials, err := generator.credentials.Retrieve(ctx)
	if err != nil || !credentials.CanExpire ||
		!credentials.Expires.After(now.Add(minimumProofLifetime)) ||
		!temporaryAccessKeyPattern.MatchString(credentials.AccessKeyID) ||
		credentials.SecretAccessKey == "" || credentials.SessionToken == "" {
		credentials = aws.Credentials{}
		return IdentityProof{}, ErrIdentityChanged
	}
	body := []byte(stsBody)
	digest := sha256.Sum256(body)
	digestText := hex.EncodeToString(digest[:])
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		credentials = aws.Credentials{}
		clear(body)
		return IdentityProof{}, ErrInvalid
	}
	request.Header.Set("Content-Type", stsContentType)
	request.Header.Set("X-Amz-Content-Sha256", digestText)
	request.Header.Set(workerChallengeHeader, challenge)
	if err := generator.signer.SignHTTP(
		ctx, credentials, request, digestText, "sts", binding.Region, now,
	); err != nil {
		credentials = aws.Credentials{}
		clear(body)
		return IdentityProof{}, ErrIdentityChanged
	}
	credentials = aws.Credentials{}
	proof := IdentityProof{
		Region: binding.Region, Endpoint: endpoint, Method: http.MethodPost,
		Host: request.URL.Host, ContentType: stsContentType,
		ContentSHA256: digestText, AmzDate: request.Header.Get("X-Amz-Date"),
		Challenge: challenge, Body: body,
		Authorization: []byte(request.Header.Get("Authorization")),
		SessionToken:  []byte(request.Header.Get("X-Amz-Security-Token")),
		IMDSDocument:  bytes.Clone(identity.Document),
		IMDSPKCS7:     bytes.Clone(identity.PKCS7),
	}
	request.Header.Del("Authorization")
	request.Header.Del("X-Amz-Security-Token")
	if proof.Authorization == nil || len(proof.Authorization) == 0 ||
		proof.SessionToken == nil || len(proof.SessionToken) == 0 || proof.AmzDate == "" {
		proof.Destroy()
		return IdentityProof{}, ErrIdentityChanged
	}
	return proof, nil
}

func regionalSTSEndpoint(region string) (string, error) {
	if !regionPattern.MatchString(region) || strings.HasPrefix(region, "us-iso-") ||
		strings.HasPrefix(region, "us-isob-") || strings.HasPrefix(region, "us-isof-") ||
		strings.HasPrefix(region, "eu-isoe-") {
		return "", ErrInvalid
	}
	suffix := "amazonaws.com"
	if strings.HasPrefix(region, "cn-") {
		suffix = "amazonaws.com.cn"
	}
	return "https://sts." + region + "." + suffix + "/", nil
}
