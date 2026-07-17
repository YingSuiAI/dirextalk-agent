// dirextalk-agent-imagectl prepares and publishes only the private Agent OCI
// image. It never builds or publishes Worker/Reaper/rootfs artifacts and never
// creates an AMI, so its receipt is not P4 or managed-deployment acceptance.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"io"
	"os"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/releaseecr"
	"github.com/YingSuiAI/dirextalk-agent/internal/releasepublish"
)

const (
	usageMessage   = "agent image release usage error\n"
	prepareMessage = "agent image preparation failed\n"
	publishMessage = "agent image publication failed\n"
	outputMessage  = "agent image release output failed\n"
	sessionMessage = "agent image release session failed\n"
	cleanupMessage = "agent image release session cleanup failed\n"
)

var (
	prepareAgentECR       = releaseecr.PrepareAgentDefault
	writeECRSession       = releaseecr.WriteSessionFile
	cleanupECRSession     = releaseecr.CleanupSession
	cleanupECRSessionFile = releaseecr.CleanupSessionFile
	publishAgent          = releasepublish.PublishAgent
)

type imageReleaseSession interface {
	DockerConfigDir() string
	RegistryHost() string
	Close() error
}

var claimECRSession = func(path string) (imageReleaseSession, error) {
	return releaseecr.ClaimSessionFile(path, time.Now)
}

func main() {
	os.Exit(run(context.Background(), os.Args[1:], os.Stdout, os.Stderr))
}

func run(ctx context.Context, arguments []string, stdout, stderr io.Writer) int {
	if len(arguments) == 0 {
		_, _ = io.WriteString(stderr, usageMessage)
		return 2
	}
	switch arguments[0] {
	case "prepare":
		return runPrepare(ctx, arguments[1:], stdout, stderr)
	case "publish":
		return runPublish(ctx, arguments[1:], stdout, stderr)
	case "cleanup":
		return runCleanup(arguments[1:], stderr)
	default:
		_, _ = io.WriteString(stderr, usageMessage)
		return 2
	}
}

func runPrepare(ctx context.Context, arguments []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("prepare", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	options := releaseecr.Options{}
	sessionOutput := ""
	flags.StringVar(&options.Region, "region", "", "")
	flags.StringVar(&options.ExpectedAccountID, "account-id", "", "")
	flags.StringVar(&sessionOutput, "session-output", "", "")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 || options.Region == "" || options.ExpectedAccountID == "" || sessionOutput == "" {
		_, _ = io.WriteString(stderr, usageMessage)
		return 2
	}
	prepared, err := prepareAgentECR(ctx, options)
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

func runPublish(ctx context.Context, arguments []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("publish", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	request := releasepublish.AgentRequest{}
	sessionFile := ""
	flags.StringVar(&request.ReleaseTag, "release-tag", "", "")
	flags.StringVar(&request.Architecture, "architecture", "", "")
	flags.StringVar(&sessionFile, "ecr-session", "", "")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 || request.ReleaseTag == "" || request.Architecture == "" || sessionFile == "" {
		_, _ = io.WriteString(stderr, usageMessage)
		return 2
	}
	session, err := claimECRSession(sessionFile)
	if err != nil {
		_, _ = io.WriteString(stderr, sessionMessage)
		return 1
	}
	request.DockerConfigDir = session.DockerConfigDir()
	request.RegistryHost = session.RegistryHost()
	request.AgentRepository = request.RegistryHost + "/" + releaseecr.RepositoryAgent
	result, publishErr, cleanupErr := publishWithSession(ctx, request, session)
	if cleanupErr != nil {
		_, _ = io.WriteString(stderr, sessionMessage)
		return 1
	}
	if publishErr != nil {
		_, _ = io.WriteString(stderr, publishMessage)
		return 1
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(result); err != nil {
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

func publishWithSession(ctx context.Context, request releasepublish.AgentRequest, session imageReleaseSession) (result releasepublish.AgentResult, publishErr, cleanupErr error) {
	defer func() { cleanupErr = session.Close() }()
	result, publishErr = publishAgent(ctx, request)
	return result, publishErr, nil
}
