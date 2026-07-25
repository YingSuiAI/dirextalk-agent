package main

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/config"
	"github.com/YingSuiAI/dirextalk-agent/internal/security"
	"github.com/YingSuiAI/dirextalk-agent/internal/store/postgres"
)

const defaultConfigPath = "/etc/dirextalk-agent/config.yaml"

func main() {
	if err := run(os.Args[1:]); err != nil {
		slog.Error("dirextalk-agent stopped", "error", safeError(err))
		os.Exit(1)
	}
}

func run(arguments []string) error {
	configPath, command, serverName, err := parseArguments(arguments)
	if err != nil {
		return err
	}
	if command != "migrate" && command != "serve" && command != "healthcheck" {
		return errors.New("unknown command; expected migrate, serve, or healthcheck")
	}
	cfg, err := config.Load(configPath)
	if err != nil {
		return err
	}
	switch command {
	case "migrate":
		return migrate(cfg)
	case "serve":
		return serveCore(cfg)
	case "healthcheck":
		return runHealthcheck(cfg, serverName)
	default:
		return errors.New("unknown command; expected migrate, serve, or healthcheck")
	}
}

func parseArguments(arguments []string) (string, string, string, error) {
	serverName := strings.TrimSpace(os.Getenv("AGENT_HEALTHCHECK_SERVER_NAME"))
	if serverName == "" {
		serverName = "localhost"
	}
	if len(arguments) == 1 {
		return defaultConfigPath, arguments[0], serverName, nil
	}
	if len(arguments) == 3 && arguments[0] == "healthcheck" && arguments[1] == "--server-name" && strings.TrimSpace(arguments[2]) != "" {
		return defaultConfigPath, arguments[0], strings.TrimSpace(arguments[2]), nil
	}
	if len(arguments) == 3 && arguments[0] == "--config" && strings.TrimSpace(arguments[1]) != "" {
		return strings.TrimSpace(arguments[1]), arguments[2], serverName, nil
	}
	if len(arguments) == 2 && strings.HasPrefix(arguments[0], "--config=") && strings.TrimSpace(strings.TrimPrefix(arguments[0], "--config=")) != "" {
		return strings.TrimSpace(strings.TrimPrefix(arguments[0], "--config=")), arguments[1], serverName, nil
	}
	if len(arguments) == 5 && arguments[0] == "--config" && strings.TrimSpace(arguments[1]) != "" && arguments[2] == "healthcheck" && arguments[3] == "--server-name" && strings.TrimSpace(arguments[4]) != "" {
		return strings.TrimSpace(arguments[1]), arguments[2], strings.TrimSpace(arguments[4]), nil
	}
	return "", "", "", errors.New("usage: dirextalk-agent [--config PATH] <migrate|serve|healthcheck [--server-name NAME]>")
}

func migrate(cfg config.Config) error {
	if err := config.ValidateCommon(&cfg); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	p, err := postgres.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer p.Close()
	if err := postgres.ApplyMigrations(ctx, p, cfg.InstanceID); err != nil {
		return err
	}
	slog.Info("agent database migration complete")
	return nil
}

func safeError(err error) string {
	if err == nil {
		return ""
	}
	message := security.RedactText(err.Error())
	if len(message) > 512 {
		message = message[:512]
	}
	return message
}
