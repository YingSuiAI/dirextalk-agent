//go:build !linux

package extensionrunner

import "context"

type Server struct{ Runner Runner }

func (Server) ServeV2(context.Context) error { return ErrUnavailable }
