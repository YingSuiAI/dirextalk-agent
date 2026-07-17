//go:build !linux

package roothelper

import (
	"context"

	"github.com/YingSuiAI/dirextalk-agent/internal/installer"
)

func (*RootOwnedInstalledStateInspector) VerifySecret(context.Context, installer.SecretV1) error {
	return ErrUnavailable
}
