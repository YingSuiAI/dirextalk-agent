package bootstrap

import (
	"context"
	"errors"
	"io"

	"github.com/aws/aws-sdk-go-v2/feature/ec2/imds"
)

type metadataAPI interface {
	GetUserData(context.Context, *imds.GetUserDataInput, ...func(*imds.Options)) (*imds.GetUserDataOutput, error)
	GetInstanceIdentityDocument(context.Context, *imds.GetInstanceIdentityDocumentInput, ...func(*imds.Options)) (*imds.GetInstanceIdentityDocumentOutput, error)
}

type IMDSSource struct{ client metadataAPI }

func NewIMDSSource(client metadataAPI) (*IMDSSource, error) {
	if client == nil {
		return nil, ErrInvalidInput
	}
	return &IMDSSource{client: client}, nil
}

func (source *IMDSSource) Read(ctx context.Context) ([]byte, InstanceIdentityV1, error) {
	if source == nil || source.client == nil || ctx == nil {
		return nil, InstanceIdentityV1{}, ErrInvalidInput
	}
	identityOutput, err := source.client.GetInstanceIdentityDocument(ctx, nil)
	if err != nil || identityOutput == nil {
		return nil, InstanceIdentityV1{}, ErrInvalidInput
	}
	identity := InstanceIdentityV1{
		AccountID: identityOutput.AccountID, Region: identityOutput.Region, InstanceID: identityOutput.InstanceID,
	}
	if !validIdentity(identity) {
		return nil, InstanceIdentityV1{}, ErrInvalidInput
	}
	output, err := source.client.GetUserData(ctx, nil)
	if err != nil || output == nil || output.Content == nil {
		return nil, InstanceIdentityV1{}, ErrInvalidInput
	}
	defer output.Content.Close()
	raw, err := io.ReadAll(io.LimitReader(output.Content, MaxUserDataBytes+1))
	if err != nil || len(raw) == 0 || len(raw) > MaxUserDataBytes {
		clear(raw)
		return nil, InstanceIdentityV1{}, ErrInvalidInput
	}
	var trailing [1]byte
	if count, trailingErr := output.Content.Read(trailing[:]); count != 0 || (trailingErr != nil && !errors.Is(trailingErr, io.EOF)) {
		clear(raw)
		return nil, InstanceIdentityV1{}, ErrInvalidInput
	}
	return raw, identity, nil
}
