// dirextalk-ecrctl prepares the fixed release repositories and authenticates a
// private, single-use Docker config through password-stdin. AWS credentials are
// resolved only by the SDK default credential chain; HOME is never modified.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"io"
	"os"

	"github.com/YingSuiAI/dirextalk-agent/internal/releaseecr"
)

const (
	usageMessage   = "ecr preparation usage error\n"
	prepareMessage = "ecr preparation failed\n"
	outputMessage  = "ecr preparation output failed\n"
	cleanupMessage = "ecr session cleanup failed\n"
)

var (
	prepareECR            = releaseecr.PrepareDefault
	writeECRSession       = releaseecr.WriteSessionFile
	cleanupECRSession     = releaseecr.CleanupSession
	cleanupECRSessionFile = releaseecr.CleanupSessionFile
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
