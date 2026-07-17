//go:build !linux

package roothelper

import "context"

type RootOwnedSigningKeyFile struct{}

func NewRootOwnedSigningKeyFile() *RootOwnedSigningKeyFile { return &RootOwnedSigningKeyFile{} }

func (*RootOwnedSigningKeyFile) ReplaceRootHelperSigningKey(context.Context, []byte) error {
	return ErrUnavailable
}

func (*RootOwnedSigningKeyFile) ReadRootHelperSigningKey(context.Context) ([]byte, error) {
	return nil, ErrUnavailable
}
