// dirextalk-worker-ami publishes, verifies, and removes one immutable Worker
// AMI through a closed Go AWS SDK boundary. It is release tooling, not an Agent
// RPC, Skill, or arbitrary AWS command surface.
package main

import (
	"context"
	"os"

	"github.com/YingSuiAI/dirextalk-agent/internal/workeramictl"
)

func main() {
	os.Exit(workeramictl.Run(context.Background(), os.Args[1:], os.Stdout, os.Stderr, workeramictl.DefaultDependencies()))
}
