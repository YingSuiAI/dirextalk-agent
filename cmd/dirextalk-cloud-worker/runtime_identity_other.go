//go:build !unix

package main

import "github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/worker"

func currentEffectiveUID() uint32 { return 0 }

func validatePrivateDirectory(string, uint32, uint32) error { return worker.ErrInvalid }
