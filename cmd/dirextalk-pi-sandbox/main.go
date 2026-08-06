package main

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/YingSuiAI/dirextalk-agent/internal/pisandbox"
)

const officialPiExecutable = "/opt/dirextalk-worker/runtimes/pi/bin/pi"

var errLaunch = errors.New("Pi sandbox launch is invalid")

func main() {
	policy, target, arguments, err := parseLaunch(os.Args[1:])
	if err != nil || launch(policy, target, arguments) != nil {
		_, _ = os.Stderr.WriteString("Pi sandbox launch rejected\n")
		os.Exit(1)
	}
}

func parseLaunch(arguments []string) (pisandbox.Policy, string, []string, error) {
	if len(arguments) < 7 || len(arguments) > 2+2*64+1+1+128 || arguments[0] != "--landlock-abi" {
		return pisandbox.Policy{}, "", nil, errLaunch
	}
	minimumABI, err := strconv.ParseUint(arguments[1], 10, 32)
	if err != nil || minimumABI != 2 {
		return pisandbox.Policy{}, "", nil, errLaunch
	}
	policy := pisandbox.Policy{MinimumABI: uint32(minimumABI)}
	index := 2
	for index < len(arguments) && arguments[index] != "--" {
		if index+1 >= len(arguments) {
			return pisandbox.Policy{}, "", nil, errLaunch
		}
		access := pisandbox.Access(0)
		switch arguments[index] {
		case "--ro":
			access = pisandbox.ReadOnly
		case "--rw":
			access = pisandbox.ReadWrite
		case "--rx":
			access = pisandbox.ReadExecute
		case "--rwx":
			access = pisandbox.ReadWriteExecute
		default:
			return pisandbox.Policy{}, "", nil, errLaunch
		}
		policy.Paths = append(policy.Paths, pisandbox.PathRule{Path: arguments[index+1], Access: access})
		index += 2
	}
	if index >= len(arguments) || arguments[index] != "--" || index+1 >= len(arguments) ||
		arguments[index+1] != officialPiExecutable || policy.Validate() != nil {
		return pisandbox.Policy{}, "", nil, errLaunch
	}
	target := arguments[index+1]
	targetArguments := append([]string(nil), arguments[index+2:]...)
	if !filepath.IsAbs(target) || filepath.Clean(target) != target || len(targetArguments) > 128 {
		return pisandbox.Policy{}, "", nil, errLaunch
	}
	for _, argument := range targetArguments {
		if argument == "" || strings.IndexByte(argument, 0) >= 0 {
			return pisandbox.Policy{}, "", nil, errLaunch
		}
	}
	return policy, target, targetArguments, nil
}
