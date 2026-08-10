package modelrelay

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
)

type HTTPBackend struct{ client *http.Client }

func NewHTTPBackend(client *http.Client) (*HTTPBackend, error) {
	if client == nil {
		return nil, ErrInvalid
	}
	copy := *client
	copy.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return &HTTPBackend{client: &copy}, nil
}

func (backend *HTTPBackend) Invoke(
	ctx context.Context,
	request ProviderRequest,
	credential []byte,
) (ProviderResponse, error) {
	if backend == nil || backend.client == nil || ctx == nil || request.Binding.Validate() != nil ||
		request.Path != request.Binding.Reference.Path() || len(request.Body) == 0 ||
		int64(len(request.Body)) > MaximumRequestBytes || len(credential) == 0 ||
		len(credential) > MaximumCredentialBytes || bytes.IndexAny(credential, "\r\n\x00") >= 0 ||
		bytes.Contains(request.Body, credential) {
		return ProviderResponse{Outcome: ProviderNotSent}, ErrInvalid
	}
	target, err := providerTarget(request.Binding.BaseURL, request.Path)
	if err != nil {
		return ProviderResponse{Outcome: ProviderNotSent}, ErrInvalid
	}
	providerRequest, err := http.NewRequestWithContext(
		ctx, http.MethodPost, target, bytes.NewReader(request.Body),
	)
	if err != nil {
		return ProviderResponse{Outcome: ProviderNotSent}, ErrInvalid
	}
	providerRequest.Header.Set("Content-Type", "application/json")
	if request.Streaming {
		providerRequest.Header.Set("Accept", "text/event-stream")
	} else {
		providerRequest.Header.Set("Accept", "application/json")
	}
	authorization := make([]byte, len("Bearer ")+len(credential))
	copy(authorization, "Bearer ")
	copy(authorization[len("Bearer "):], credential)
	providerRequest.Header.Set("Authorization", string(authorization))
	response, err := backend.client.Do(providerRequest)
	providerRequest.Header.Del("Authorization")
	clear(authorization)
	if err != nil {
		return ProviderResponse{Outcome: ProviderUncertain}, ErrProviderUnavailable
	}
	defer response.Body.Close()
	body, readErr := io.ReadAll(io.LimitReader(response.Body, MaximumResponseBytes+1))
	if readErr != nil || int64(len(body)) > MaximumResponseBytes {
		clear(body)
		return ProviderResponse{Outcome: ProviderAccepted}, ErrProviderUnavailable
	}
	contentType := response.Header.Get("Content-Type")
	if providerCredentialInHeaders(response.Header, credential) || bytes.Contains(body, credential) {
		clear(body)
		return ProviderResponse{Outcome: ProviderAccepted}, ErrProviderProtocol
	}
	return ProviderResponse{
		StatusCode: response.StatusCode, ContentType: contentType,
		Body: body, Outcome: ProviderAccepted,
	}, nil
}

func providerTarget(baseURL, path string) (string, error) {
	if !validProviderBaseURL(baseURL) || !validPath(path) {
		return "", ErrInvalid
	}
	base, err := url.Parse(baseURL)
	if err != nil {
		return "", ErrInvalid
	}
	basePath := strings.TrimSuffix(base.Path, "/")
	endpointPath := path
	if strings.HasSuffix(basePath, "/v1") {
		endpointPath = strings.TrimPrefix(path, "/v1")
	}
	targetPath := basePath + endpointPath
	base.Path = targetPath
	if base.RawPath != "" || base.RawQuery != "" || base.Fragment != "" {
		return "", ErrInvalid
	}
	return base.String(), nil
}

func providerCredentialInHeaders(headers http.Header, credential []byte) bool {
	for name, values := range headers {
		if bytes.Contains([]byte(name), credential) {
			return true
		}
		for _, value := range values {
			if bytes.Contains([]byte(value), credential) {
				return true
			}
		}
	}
	return false
}

func safeProviderError(err error) error {
	if errors.Is(err, ErrProviderProtocol) {
		return ErrProviderProtocol
	}
	return ErrProviderUnavailable
}

var _ ProviderBackend = (*HTTPBackend)(nil)
