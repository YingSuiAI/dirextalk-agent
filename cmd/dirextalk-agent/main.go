package main

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/buildinfo"
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
	if err := buildinfo.Validate(); err != nil {
		return err
	}
	configPath, command, healthOptions, err := parseArguments(arguments)
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
		return runHealthcheckOptions(cfg, healthOptions)
	default:
		return errors.New("unknown command; expected migrate, serve, or healthcheck")
	}
}

type healthcheckOptions struct {
	serverName       string
	expectInstanceID string
	requiredCaps     []string
}

func parseArguments(arguments []string) (string, string, healthcheckOptions, error) {
	options := healthcheckOptions{serverName: strings.TrimSpace(os.Getenv("AGENT_HEALTHCHECK_SERVER_NAME"))}
	if options.serverName == "" {
		options.serverName = "localhost"
	}
	args := append([]string(nil), arguments...)
	configPath := defaultConfigPath
	if len(args) >= 2 && args[0] == "--config" {
		if strings.TrimSpace(args[1]) == "" {
			return "", "", options, errors.New("usage: dirextalk-agent [--config PATH] <migrate|serve|healthcheck>")
		}
		configPath = strings.TrimSpace(args[1])
		args = args[2:]
	} else if len(args) >= 1 && strings.HasPrefix(args[0], "--config=") {
		if strings.TrimSpace(strings.TrimPrefix(args[0], "--config=")) == "" {
			return "", "", options, errors.New("usage: dirextalk-agent [--config PATH] <migrate|serve|healthcheck>")
		}
		configPath = strings.TrimSpace(strings.TrimPrefix(args[0], "--config="))
		args = args[1:]
	}
	if len(args) == 0 {
		return "", "", options, errors.New("usage: dirextalk-agent [--config PATH] <migrate|serve|healthcheck>")
	}
	command := args[0]
	args = args[1:]
	if command != "healthcheck" {
		if len(args) != 0 {
			return "", "", options, errors.New("unexpected command arguments")
		}
		return configPath, command, options, nil
	}
	for len(args) > 0 {
		if len(args) < 2 || strings.TrimSpace(args[1]) == "" {
			return "", "", options, errors.New("healthcheck option requires a value")
		}
		value := strings.TrimSpace(args[1])
		if strings.ContainsAny(value, "\r\n\x00") {
			return "", "", options, errors.New("healthcheck option contains invalid characters")
		}
		switch args[0] {
		case "--server-name":
			options.serverName = value
		case "--expect-instance-id":
			options.expectInstanceID = value
		case "--require-capability":
			options.requiredCaps = append(options.requiredCaps, value)
		default:
			return "", "", options, errors.New("unknown healthcheck option")
		}
		args = args[2:]
	}
	return configPath, command, options, nil
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
