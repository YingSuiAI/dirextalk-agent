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

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(arguments []string, stdout, stderr io.Writer) int {
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
	manifest, err := workerrootfs.Pack(*root, *output)
	if err != nil {
		_, _ = io.WriteString(stderr, packMessage)
		return 1
	}
	if err := json.NewEncoder(stdout).Encode(manifest); err != nil {
		_, _ = io.WriteString(stderr, outputMessage)
		return 1
	}
	return 0
}
