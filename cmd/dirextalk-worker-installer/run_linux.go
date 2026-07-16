//go:build linux

package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"github.com/YingSuiAI/dirextalk-agent/internal/installer"
)

const (
	defaultPublicKeyFile = "/etc/dirextalk-installer/approval-public-key"
	defaultBindingFile   = "/etc/dirextalk-installer/binding.cbor"
	defaultJournalFile   = "/var/lib/dirextalk-installer/execution.journal"
)

func run() error {
	if os.Geteuid() != 0 {
		return installer.Error(installer.CodeInvalidRequest)
	}
	publicKeyContent, err := installer.ReadRootOwnedFile(environmentOrDefault("DIREXTALK_INSTALLER_APPROVAL_PUBLIC_KEY_FILE", defaultPublicKeyFile), 4096)
	if err != nil {
		return err
	}
	publicKey, err := parsePublicKey(publicKeyContent)
	if err != nil {
		return installer.Error(installer.CodeInvalidSignature)
	}
	configContent, err := installer.ReadRootOwnedFile(environmentOrDefault("DIREXTALK_INSTALLER_BINDING_FILE", defaultBindingFile), 64<<10)
	if err != nil {
		return err
	}
	var config installer.DaemonConfigV1
	if err := installer.DecodeCanonical(configContent, &config); err != nil || config.SchemaVersion != installer.DaemonConfigSchema {
		return installer.Error(installer.CodeInvalidRequest)
	}
	inspector, err := installer.NewRootOwnedArtifactInspector(config.TargetRoot)
	if err != nil {
		return err
	}
	journal, err := installer.OpenRootOwnedExecutionJournal(defaultJournalFile)
	if err != nil {
		return err
	}
	verifier, err := installer.NewVerifier(installer.VerifierConfig{
		PublicKey: publicKey, ExpectedBinding: config.Binding, TargetRoot: config.TargetRoot, Inspector: inspector,
		Runner: installer.OSCommandRunner{}, Journal: journal,
	})
	if err != nil {
		return err
	}
	listener, err := systemdListener()
	if err != nil {
		return installer.Error(installer.CodeInvalidRequest)
	}
	defer listener.Close()
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()
	return installer.NewServer(verifier, installer.ServerConfig{}).Serve(ctx, listener)
}

func parsePublicKey(content []byte) (ed25519.PublicKey, error) {
	if len(content) == ed25519.PublicKeySize {
		return append(ed25519.PublicKey(nil), content...), nil
	}
	trimmed := bytes.TrimSpace(content)
	for _, encoding := range []*base64.Encoding{base64.RawURLEncoding, base64.URLEncoding, base64.RawStdEncoding, base64.StdEncoding} {
		decoded, err := encoding.DecodeString(string(trimmed))
		if err == nil && len(decoded) == ed25519.PublicKeySize {
			return ed25519.PublicKey(decoded), nil
		}
	}
	return nil, fmt.Errorf("invalid Ed25519 public key")
}

func systemdListener() (net.Listener, error) {
	pid, pidErr := strconv.Atoi(os.Getenv("LISTEN_PID"))
	fds, fdsErr := strconv.Atoi(os.Getenv("LISTEN_FDS"))
	if pidErr != nil || fdsErr != nil || pid != os.Getpid() || fds != 1 {
		return nil, fmt.Errorf("exactly one systemd socket is required")
	}
	file := os.NewFile(uintptr(3), "dirextalk-worker-installer.socket")
	if file == nil {
		return nil, fmt.Errorf("systemd listener fd is unavailable")
	}
	defer file.Close()
	listener, err := net.FileListener(file)
	if err != nil {
		return nil, err
	}
	if _, ok := listener.(*net.UnixListener); !ok {
		_ = listener.Close()
		return nil, fmt.Errorf("systemd listener is not a Unix socket")
	}
	return listener, nil
}

func environmentOrDefault(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}
