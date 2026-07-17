package bootstrap

import (
	"context"
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/sts"
)

type STSIdentityAPI interface {
	GetCallerIdentity(context.Context, *sts.GetCallerIdentityInput, ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error)
}

type STSPrincipalIdentity struct{ client STSIdentityAPI }

func NewSTSPrincipalIdentity(client STSIdentityAPI) (*STSPrincipalIdentity, error) {
	if client == nil {
		return nil, ErrInvalidInput
	}
	return &STSPrincipalIdentity{client: client}, nil
}

func (i *STSPrincipalIdentity) CurrentPrincipal(ctx context.Context) (string, error) {
	if i == nil || i.client == nil || ctx == nil {
		return "", ErrInvalidInput
	}
	output, err := i.client.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil || output == nil || output.UserId == nil {
		return "", ErrArtifactSource
	}
	value := strings.TrimSpace(*output.UserId)
	if value == "" || value != *output.UserId {
		return "", ErrArtifactSource
	}
	return value, nil
}
