// dirextalk-artifactctl validates and normalizes immutable release manifests.
// It does not build, publish, authenticate to, or mutate any registry.
package main

import (
	"flag"
	"io"
	"os"

	"github.com/YingSuiAI/dirextalk-agent/internal/releaseartifact"
)

const usage = "usage: dirextalk-artifactctl <normalize|validate> --input <manifest.json>\n"

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || (args[0] != "normalize" && args[0] != "validate") {
		_, _ = io.WriteString(stderr, usage)
		return 2
	}
	command := args[0]
	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	inputPath := flags.String("input", "", "path to a release-manifest JSON file")
	if err := flags.Parse(args[1:]); err != nil || *inputPath == "" || *inputPath == "-" || flags.NArg() != 0 {
		_, _ = io.WriteString(stderr, usage)
		return 2
	}

	input, ok := readBoundedFile(*inputPath)
	if !ok {
		_, _ = io.WriteString(stderr, "artifactctl: cannot read input file\n")
		return 1
	}
	manifest, err := releaseartifact.ParseJSON(input)
	clear(input)
	if err != nil {
		_, _ = io.WriteString(stderr, "artifactctl: invalid release manifest\n")
		return 1
	}
	if command == "validate" {
		return 0
	}
	encoded, err := manifest.CanonicalJSON()
	if err != nil {
		_, _ = io.WriteString(stderr, "artifactctl: invalid release manifest\n")
		return 1
	}
	if _, err := stdout.Write(append(encoded, '\n')); err != nil {
		_, _ = io.WriteString(stderr, "artifactctl: cannot write output\n")
		return 1
	}
	return 0
}

func readBoundedFile(path string) ([]byte, bool) {
	file, err := os.Open(path)
	if err != nil {
		return nil, false
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > releaseartifact.MaxJSONBytes {
		return nil, false
	}
	input, err := io.ReadAll(io.LimitReader(file, releaseartifact.MaxJSONBytes+1))
	if err != nil || len(input) == 0 || len(input) > releaseartifact.MaxJSONBytes {
		clear(input)
		return nil, false
	}
	return input, true
}
