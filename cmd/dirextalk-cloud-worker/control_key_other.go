//go:build !linux

package main

func readControlPrivateKey(_ string, _ uint32) ([]byte, error) { return nil, errControl }
