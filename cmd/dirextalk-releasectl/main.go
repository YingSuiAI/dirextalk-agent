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
	usageMessage   = "release publish usage error\n"
	publishMessage = "release publish failed\n"
	outputMessage  = "release publish output failed\n"
	sessionMessage = "release authentication session failed\n"
)

var publishRelease = releasepublish.Publish

type releaseSession interface {
	DockerConfigDir() string
	RegistryHost() string
	Close() error
}

var claimECRSession = func(path string) (releaseSession, error) {
	return releaseecr.ClaimSessionFile(path, time.Now)
}

func main() {
	os.Exit(run(context.Background(), os.Args[1:], os.Stdout, os.Stderr))
}

func run(ctx context.Context, arguments []string, stdout, stderr io.Writer) int {
	if len(arguments) == 0 || arguments[0] != "publish" {
		_, _ = io.WriteString(stderr, usageMessage)
		return 2
	}
	flags := flag.NewFlagSet("publish", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	request := releasepublish.Request{}
	sessionFile := ""
	flags.StringVar(&request.ReleaseTag, "release-tag", "", "")
	flags.StringVar(&request.Architecture, "architecture", "", "")
	flags.StringVar(&request.AgentRepository, "agent-repository", "", "")
	flags.StringVar(&request.WorkerRepository, "worker-repository", "", "")
	flags.StringVar(&request.ReaperRepository, "reaper-repository", "", "")
	flags.StringVar(&request.ManifestOutput, "manifest-output", "", "")
	flags.StringVar(&request.RootFSOutput, "rootfs-output", "", "")
	flags.StringVar(&sessionFile, "ecr-session", "", "")
	if err := flags.Parse(arguments[1:]); err != nil || flags.NArg() != 0 || missingRequired(request) || sessionFile == "" {
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

func publishWithSession(ctx context.Context, request releasepublish.Request, session releaseSession) (result releasepublish.Result, publishErr, cleanupErr error) {
	defer func() { cleanupErr = session.Close() }()
	result, publishErr = publishRelease(ctx, request)
	return result, publishErr, nil
}

func missingRequired(request releasepublish.Request) bool {
	return request.ReleaseTag == "" || request.Architecture == "" ||
		request.AgentRepository == "" || request.WorkerRepository == "" || request.ReaperRepository == "" ||
		request.ManifestOutput == "" || request.RootFSOutput == ""
}
