//go:build !linux

package extensionrunner

import (
	"context"
	"os"
)

type Client struct{}

func NewClient(string, uint32) (*Client, error) { return nil, ErrUnavailable }
func (*Client) RunV2(context.Context, RequestV2, []*os.File) (StatusV1, error) {
	return StatusV1{}, ErrUnavailable
}
