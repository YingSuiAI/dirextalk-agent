package worker

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
)

const (
	imdsEndpoint       = "http://169.254.169.254"
	imdsTokenPath      = "/latest/api/token"
	imdsDocumentPath   = "/latest/dynamic/instance-identity/document"
	imdsPKCS7Path      = "/latest/dynamic/instance-identity/pkcs7"
	imdsInstanceIDPath = "/latest/meta-data/instance-id"
	imdsRolePath       = "/latest/meta-data/iam/security-credentials/"
	imdsUserDataPath   = "/latest/user-data"
	imdsTokenTTL       = "60"
)

var roleNamePattern = regexp.MustCompile(`^[A-Za-z0-9+=,.@_-]{1,64}$`)

type httpDoer interface {
	Do(*http.Request) (*http.Response, error)
}

func (client *IMDSClient) ReadUserData(ctx context.Context) ([]byte, error) {
	if client == nil || ctx == nil {
		return nil, ErrInvalid
	}
	token, err := client.token(ctx)
	if err != nil {
		return nil, err
	}
	defer clear(token)
	return client.get(ctx, imdsUserDataPath, token, MaxBootstrapBytes)
}

type IMDSClient struct {
	http     httpDoer
	endpoint string
}

func NewIMDSClient() *IMDSClient {
	dialer := &net.Dialer{Timeout: 2 * time.Second, KeepAlive: 30 * time.Second}
	client := &http.Client{
		Timeout: 3 * time.Second,
		Transport: &http.Transport{
			Proxy: nil, DialContext: dialer.DialContext,
			MaxIdleConns: 2, MaxIdleConnsPerHost: 2, IdleConnTimeout: 30 * time.Second,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return ErrUnavailable },
	}
	return &IMDSClient{http: client, endpoint: imdsEndpoint}
}

func newIMDSClient(doer httpDoer, endpoint string) (*IMDSClient, error) {
	parsed, err := url.Parse(endpoint)
	if err != nil || doer == nil || parsed.Scheme != "http" || parsed.User != nil ||
		parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Path != "" ||
		parsed.Hostname() != "127.0.0.1" || parsed.Port() == "" {
		return nil, ErrInvalid
	}
	return &IMDSClient{http: doer, endpoint: endpoint}, nil
}

func (client *IMDSClient) ReadIdentity(ctx context.Context) (InstanceIdentity, error) {
	if client == nil || ctx == nil {
		return InstanceIdentity{}, ErrInvalid
	}
	token, err := client.token(ctx)
	if err != nil {
		return InstanceIdentity{}, err
	}
	defer clear(token)
	document, err := client.get(ctx, imdsDocumentPath, token, 64<<10)
	if err != nil {
		return InstanceIdentity{}, err
	}
	var parsed struct {
		AccountID  string `json:"accountId"`
		Region     string `json:"region"`
		InstanceID string `json:"instanceId"`
	}
	if json.Unmarshal(document, &parsed) != nil ||
		!accountPattern.MatchString(parsed.AccountID) ||
		!regionPattern.MatchString(parsed.Region) ||
		!instancePattern.MatchString(parsed.InstanceID) {
		clear(document)
		return InstanceIdentity{}, ErrIdentityChanged
	}
	pkcs7Value, err := client.get(ctx, imdsPKCS7Path, token, 64<<10)
	if err != nil {
		clear(document)
		return InstanceIdentity{}, err
	}
	pkcs7Value = bytes.TrimSpace(pkcs7Value)
	decodedPKCS7, decodeErr := base64.StdEncoding.DecodeString(
		strings.Map(func(character rune) rune {
			if character == '\r' || character == '\n' || character == '\t' || character == ' ' {
				return -1
			}
			return character
		}, string(pkcs7Value)),
	)
	clear(decodedPKCS7)
	if decodeErr != nil || len(pkcs7Value) == 0 {
		clear(document)
		clear(pkcs7Value)
		return InstanceIdentity{}, ErrIdentityChanged
	}
	instanceID, err := client.get(ctx, imdsInstanceIDPath, token, 128)
	if err != nil || string(bytes.TrimSpace(instanceID)) != parsed.InstanceID {
		clear(document)
		clear(pkcs7Value)
		clear(instanceID)
		return InstanceIdentity{}, ErrIdentityChanged
	}
	clear(instanceID)
	return InstanceIdentity{
		AccountID: parsed.AccountID, Region: parsed.Region, InstanceID: parsed.InstanceID,
		Document: document, PKCS7: pkcs7Value,
	}, nil
}

// Retrieve obtains only the temporary EC2 role session used to sign one STS
// proof or one S3 request. No value is persisted by this adapter.
func (client *IMDSClient) Retrieve(ctx context.Context) (aws.Credentials, error) {
	if client == nil || ctx == nil {
		return aws.Credentials{}, ErrInvalid
	}
	token, err := client.token(ctx)
	if err != nil {
		return aws.Credentials{}, err
	}
	defer clear(token)
	roleRaw, err := client.get(ctx, imdsRolePath, token, 1024)
	if err != nil {
		return aws.Credentials{}, err
	}
	role := string(bytes.TrimSpace(roleRaw))
	clear(roleRaw)
	if !roleNamePattern.MatchString(role) {
		return aws.Credentials{}, ErrIdentityChanged
	}
	credentialRaw, err := client.get(
		ctx, imdsRolePath+url.PathEscape(role), token, 64<<10,
	)
	if err != nil {
		return aws.Credentials{}, err
	}
	defer clear(credentialRaw)
	var document struct {
		Code            string    `json:"Code"`
		AccessKeyID     string    `json:"AccessKeyId"`
		SecretAccessKey string    `json:"SecretAccessKey"`
		Token           string    `json:"Token"`
		Expiration      time.Time `json:"Expiration"`
	}
	if json.Unmarshal(credentialRaw, &document) != nil || document.Code != "Success" ||
		!temporaryAccessKeyPattern.MatchString(document.AccessKeyID) ||
		len(document.SecretAccessKey) < 32 || len(document.SecretAccessKey) > 256 ||
		len(document.Token) < 16 || len(document.Token) > 16<<10 ||
		!document.Expiration.After(time.Now().UTC().Add(minimumProofLifetime)) {
		return aws.Credentials{}, ErrIdentityChanged
	}
	return aws.Credentials{
		AccessKeyID: document.AccessKeyID, SecretAccessKey: document.SecretAccessKey,
		SessionToken: document.Token, CanExpire: true,
		Expires: document.Expiration.UTC(), Source: "EC2RoleIMDSv2",
	}, nil
}

func (client *IMDSClient) token(ctx context.Context) ([]byte, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodPut, client.endpoint+imdsTokenPath, nil)
	if err != nil {
		return nil, ErrInvalid
	}
	request.Header.Set("X-aws-ec2-metadata-token-ttl-seconds", imdsTokenTTL)
	token, err := client.do(request, 4096)
	if err != nil {
		return nil, err
	}
	if len(token) < 16 || !bytes.Equal(token, bytes.TrimSpace(token)) ||
		bytes.IndexAny(token, "\r\n\x00") >= 0 {
		clear(token)
		return nil, ErrUnavailable
	}
	return token, nil
}

func (client *IMDSClient) get(
	ctx context.Context,
	path string,
	token []byte,
	maximum int64,
) ([]byte, error) {
	if len(token) < 16 || strings.ContainsAny(path, "\r\n\x00") {
		return nil, ErrInvalid
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, client.endpoint+path, nil)
	if err != nil {
		return nil, ErrInvalid
	}
	request.Header.Set("X-aws-ec2-metadata-token", string(token))
	return client.do(request, maximum)
}

func (client *IMDSClient) do(request *http.Request, maximum int64) ([]byte, error) {
	response, err := client.http.Do(request)
	if err != nil {
		return nil, ErrUnavailable
	}
	if response == nil || response.Body == nil {
		return nil, ErrUnavailable
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || maximum < 1 {
		return nil, ErrUnavailable
	}
	content, err := io.ReadAll(io.LimitReader(response.Body, maximum+1))
	if err != nil || len(content) == 0 || int64(len(content)) > maximum {
		clear(content)
		return nil, ErrUnavailable
	}
	return content, nil
}

var _ aws.CredentialsProvider = (*IMDSClient)(nil)
