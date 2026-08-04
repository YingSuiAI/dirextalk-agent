package coreexecutionv2

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
)

// CommandStep is the typed, reviewed representation of one workload action.
// The provider receives only the compiled command strings; the durable plan
// also keeps these typed specs and their digest so a record cannot silently
// turn a recipe label into caller-controlled shell text.
type CommandStep struct {
	Type      string `json:"type"`
	Operation string `json:"operation"`
	Service   string `json:"service"`
}

// CompiledPlan is the immutable output of the approved recipe compiler.
// Callers choose a recipe/intent, never command text.
type CompiledPlan struct {
	RecipeID           string
	Intent             string
	Purpose            string
	Steps              []CommandStep
	Commands           []string
	RecipeDigest       string
	CommandStepsDigest string
}

// CompileApprovedPlan is deliberately a small allowlist.  Expanding it is a
// code-reviewed product change; no request field is interpolated into a shell
// command.  The current Core v1 AWS target owns dirextalk-agent.service, so
// the first recipe is sufficient for the fixed EC2/SSM provisioner.
func CompileApprovedPlan(recipeID, intent, purpose string) (CompiledPlan, error) {
	recipeID = strings.TrimSpace(recipeID)
	intent = strings.TrimSpace(intent)
	purpose = strings.TrimSpace(purpose)
	if recipeID != "generic-container-service" || intent != "deploy" || purpose != "service" {
		return CompiledPlan{}, fmt.Errorf("%w: recipe/intent is not approved", ErrInvalid)
	}
	steps := []CommandStep{
		{Type: "systemd", Operation: "daemon_reload", Service: "dirextalk-agent.service"},
		{Type: "systemd", Operation: "enable_now", Service: "dirextalk-agent.service"},
	}
	commands := []string{
		"systemctl daemon-reload",
		"systemctl enable --now dirextalk-agent.service",
	}
	recipeDigest := digestJSON(struct {
		RecipeID string `json:"recipe_id"`
		Intent   string `json:"intent"`
		Purpose  string `json:"purpose"`
	}{recipeID, intent, purpose})
	commandStepsDigest := digestJSON(struct {
		RecipeDigest string        `json:"recipe_digest"`
		Steps        []CommandStep `json:"steps"`
		Commands     []string      `json:"commands"`
	}{recipeDigest, steps, commands})
	return CompiledPlan{RecipeID: recipeID, Intent: intent, Purpose: purpose, Steps: steps, Commands: commands, RecipeDigest: recipeDigest, CommandStepsDigest: commandStepsDigest}, nil
}

func digestJSON(value any) string {
	raw, _ := json.Marshal(value)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
