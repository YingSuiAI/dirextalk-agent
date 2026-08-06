//go:build !linux

package main

func protectControlProcess() error { return errConfig }
