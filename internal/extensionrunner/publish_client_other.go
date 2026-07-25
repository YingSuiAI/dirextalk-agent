//go:build !linux

package extensionrunner

import (
	"context"
	"errors"
)

func (*Client) Publish(context.Context, []ManifestEntry, []PublishFile) (PublishResponse, error) {
	return PublishResponse{}, errors.New("publication unavailable")
}

func (*Client) Remove(context.Context, string) error {
	return ErrUnavailable
}

func (*Client) ReadSkill(context.Context, string, string) ([]byte, error) {
	return nil, ErrUnavailable
}
