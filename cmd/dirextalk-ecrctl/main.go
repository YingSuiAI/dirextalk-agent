// dirextalk-ecrctl prepares the fixed release repositories, authenticates a
// private publisher session, and independently verifies their retained Managed
// state. AWS credentials are resolved only by the SDK default credential chain;
// HOME is never modified.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"io"
	"os"

	"github.com/YingSuiAI/dirextalk-agent/internal/releaseartifact"
	"github.com/YingSuiAI/dirextalk-agent/internal/releaseecr"
)

const (
	usageMessage        = "ecr preparation usage error\n"
	prepareMessage      = "ecr preparation failed\n"
	outputMessage       = "ecr preparation output failed\n"
	cleanupMessage      = "ecr session cleanup failed\n"
	verifyMessage       = "ecr managed verification failed\n"
	verifyOutputMessage = "ecr managed verification output failed\n"
)

var (
	prepareECR            = releaseecr.PrepareDefault
	writeECRSession       = releaseecr.WriteSessionFile
	cleanupECRSession     = releaseecr.CleanupSession
	cleanupECRSessionFile = releaseecr.CleanupSessionFile
	verifyManagedECR      = releaseecr.VerifyManagedDefault
	writeManagedReceipt   = writeNewManagedReceipt
)

func main() {
	os.Exit(run(context.Background(), os.Args[1:], os.Stdout, os.Stderr))
}

func run(ctx context.Context, arguments []string, stdout, stderr io.Writer) int {
	if len(arguments) == 0 {
		_, _ = io.WriteString(stderr, usageMessage)
		return 2
	}
	if arguments[0] == "cleanup" {
		return runCleanup(arguments[1:], stderr)
	}
	if arguments[0] == "verify-managed" {
		return runVerifyManaged(ctx, arguments[1:], stdout, stderr)
	}
	if arguments[0] != "prepare" {
		_, _ = io.WriteString(stderr, usageMessage)
		return 2
	}
	flags := flag.NewFlagSet("prepare", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	options := releaseecr.Options{}
	sessionOutput := ""
	flags.StringVar(&options.Region, "region", "", "")
	flags.StringVar(&options.ExpectedAccountID, "account-id", "", "")
	flags.StringVar(&sessionOutput, "session-output", "", "")
	if err := flags.Parse(arguments[1:]); err != nil || flags.NArg() != 0 || options.Region == "" || options.ExpectedAccountID == "" || sessionOutput == "" {
		_, _ = io.WriteString(stderr, usageMessage)
		return 2
	}
	prepared, err := prepareECR(ctx, options)
	if err != nil {
		_, _ = io.WriteString(stderr, prepareMessage)
		return 1
	}
	if err := writeECRSession(sessionOutput, prepared.Session); err != nil {
		_ = cleanupECRSession(prepared.Session)
		_, _ = io.WriteString(stderr, prepareMessage)
		return 1
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(prepared.Result); err != nil {
		_ = cleanupECRSessionFile(sessionOutput)
		_, _ = io.WriteString(stderr, outputMessage)
		return 1
	}
	return 0
}

func runVerifyManaged(ctx context.Context, arguments []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("verify-managed", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	options := releaseecr.ManagedVerifyOptions{}
	manifestPath := ""
	receiptOutput := ""
	flags.StringVar(&options.Region, "region", "", "")
	flags.StringVar(&options.ExpectedAccountID, "account-id", "", "")
	flags.StringVar(&manifestPath, "release-manifest", "", "")
	flags.StringVar(&receiptOutput, "receipt-output", "", "")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 || options.Region == "" || options.ExpectedAccountID == "" || manifestPath == "" || receiptOutput == "" {
		_, _ = io.WriteString(stderr, usageMessage)
		return 2
	}
	manifest, err := readReleaseManifest(manifestPath)
	if err != nil {
		_, _ = io.WriteString(stderr, verifyMessage)
		return 1
	}
	options.ReleaseManifest = manifest
	receipt, err := verifyManagedECR(ctx, options)
	if err != nil {
		_, _ = io.WriteString(stderr, verifyMessage)
		return 1
	}
	if err := writeManagedReceipt(receiptOutput, receipt); err != nil {
		_, _ = io.WriteString(stderr, verifyOutputMessage)
		return 1
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(receipt); err != nil {
		_, _ = io.WriteString(stderr, verifyOutputMessage)
		return 1
	}
	return 0
}

func runCleanup(arguments []string, stderr io.Writer) int {
	flags := flag.NewFlagSet("cleanup", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	sessionFile := ""
	flags.StringVar(&sessionFile, "session", "", "")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 || sessionFile == "" {
		_, _ = io.WriteString(stderr, usageMessage)
		return 2
	}
	if err := cleanupECRSessionFile(sessionFile); err != nil {
		_, _ = io.WriteString(stderr, cleanupMessage)
		return 1
	}
	return 0
}

func readReleaseManifest(name string) (releaseartifact.ReleaseManifestV1, error) {
	info, err := os.Lstat(name)
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > releaseartifact.MaxJSONBytes {
		return releaseartifact.ReleaseManifestV1{}, releaseartifact.ErrInvalidManifest
	}
	file, err := os.Open(name)
	if err != nil {
		return releaseartifact.ReleaseManifestV1{}, releaseartifact.ErrInvalidManifest
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(info, opened) {
		return releaseartifact.ReleaseManifestV1{}, releaseartifact.ErrInvalidManifest
	}
	payload, err := io.ReadAll(io.LimitReader(file, releaseartifact.MaxJSONBytes+1))
	if err != nil || len(payload) == 0 || len(payload) > releaseartifact.MaxJSONBytes {
		return releaseartifact.ReleaseManifestV1{}, releaseartifact.ErrInvalidManifest
	}
	return releaseartifact.ParseJSON(payload)
}

func writeNewManagedReceipt(name string, receipt releaseecr.ManagedReceiptV1) (err error) {
	payload, err := json.Marshal(receipt)
	if err != nil {
		return err
	}
	payload = append(payload, '\n')
	file, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	complete := false
	defer func() {
		if closeErr := file.Close(); err == nil && closeErr != nil {
			err = closeErr
		}
		if !complete || err != nil {
			_ = os.Remove(name)
		}
	}()
	if err = os.Chmod(name, 0o600); err != nil {
		return err
	}
	if _, err = file.Write(payload); err != nil {
		return err
	}
	if err = file.Sync(); err != nil {
		return err
	}
	complete = true
	return nil
}
