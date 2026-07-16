//go:build !linux

package main

import (
	"runtime"

	"github.com/YingSuiAI/dirextalk-agent/internal/installer"
)

func run() error {
	_ = runtime.GOOS
	return installer.Error(installer.CodeInvalidRequest)
}
