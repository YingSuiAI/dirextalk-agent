package main

import (
	"slices"
	"testing"

	"github.com/YingSuiAI/dirextalk-agent/internal/pisandbox"
)

func TestParseLaunchAcceptsOnlyClosedOfficialPiPolicy(t *testing.T) {
	policy, target, arguments, err := parseLaunch([]string{
		"--landlock-abi", "2",
		"--rx", "/opt/dirextalk-worker/runtimes/pi",
		"--rwx", "/var/lib/dirextalk-worker/workspaces/role",
		"--ro", "/proc/self",
		"--", officialPiExecutable, "--mode", "json",
	})
	if err != nil || target != officialPiExecutable || !slices.Equal(arguments, []string{"--mode", "json"}) ||
		policy.MinimumABI != 2 || len(policy.Paths) != 3 || policy.Paths[0].Access != pisandbox.ReadExecute ||
		policy.Paths[1].Access != pisandbox.ReadWriteExecute || policy.Paths[2].Access != pisandbox.ReadOnly {
		t.Fatalf("policy=%+v target=%q arguments=%q err=%v", policy, target, arguments, err)
	}
}

func TestParseLaunchRejectsControlPathsAndAlternateTargets(t *testing.T) {
	for name, arguments := range map[string][]string{
		"credential":       {"--landlock-abi", "2", "--ro", "/run/credentials/worker-key", "--", officialPiExecutable},
		"receipt":          {"--landlock-abi", "2", "--rw", "/var/lib/dirextalk-worker/receipts", "--", officialPiExecutable},
		"receipt ancestor": {"--landlock-abi", "2", "--rwx", "/var/lib/dirextalk-worker", "--", officialPiExecutable},
		"secret ancestor":  {"--landlock-abi", "2", "--rwx", "/run", "--", officialPiExecutable},
		"parent proc":      {"--landlock-abi", "2", "--ro", "/proc/1", "--", officialPiExecutable},
		"alternate target": {"--landlock-abi", "2", "--rx", "/usr/bin", "--", "/bin/sh"},
		"weak ABI":         {"--landlock-abi", "1", "--rx", "/opt/dirextalk-worker/runtimes/pi", "--", officialPiExecutable},
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, _, err := parseLaunch(arguments); err == nil {
				t.Fatalf("unsafe launch accepted: %q", arguments)
			}
		})
	}
}
