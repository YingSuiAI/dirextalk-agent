//go:build !linux

package main

import "github.com/YingSuiAI/dirextalk-agent/internal/pisandbox"

func launch(_ pisandbox.Policy, _ string, _ []string) error { return errLaunch }
