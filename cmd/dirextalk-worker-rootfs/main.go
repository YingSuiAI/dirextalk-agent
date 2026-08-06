package main

import (
	"encoding/json"
	"flag"
	"io"
	"os"

	"github.com/YingSuiAI/dirextalk-agent/internal/workerrootfs"
)

const (
	usageMessage  = "worker rootfs usage error\n"
	packMessage   = "worker rootfs pack failed\n"
	outputMessage = "worker rootfs output failed\n"
)

type rootfsPublication interface {
	Manifest() workerrootfs.ManifestV1
	Commit()
	Rollback() error
}

type prepareRootfsFunc func(root, output string) (rootfsPublication, error)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(arguments []string, stdout, stderr io.Writer) int {
	return runWithPrepare(arguments, stdout, stderr, func(root, output string) (rootfsPublication, error) {
		return workerrootfs.PreparePublication(root, output)
	})
}

func runWithPrepare(arguments []string, stdout, stderr io.Writer, prepare prepareRootfsFunc) int {
	if len(arguments) == 0 || arguments[0] != "pack" {
		_, _ = io.WriteString(stderr, usageMessage)
		return 2
	}
	flags := flag.NewFlagSet("pack", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	root := flags.String("root", "", "")
	output := flags.String("output", "", "")
	if err := flags.Parse(arguments[1:]); err != nil || flags.NArg() != 0 || *root == "" || *output == "" {
		_, _ = io.WriteString(stderr, usageMessage)
		return 2
	}
	publication, err := prepare(*root, *output)
	if err != nil || publication == nil {
		_, _ = io.WriteString(stderr, packMessage)
		return 1
	}
	if err := json.NewEncoder(stdout).Encode(publication.Manifest()); err != nil {
		_ = publication.Rollback()
		_, _ = io.WriteString(stderr, outputMessage)
		return 1
	}
	publication.Commit()
	return 0
}
