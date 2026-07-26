package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	agentv1 "github.com/YingSuiAI/dirextalk-agent/api/gen/dirextalk/agent/v1"
	"github.com/YingSuiAI/dirextalk-agent/internal/auth"
	"github.com/YingSuiAI/dirextalk-agent/internal/config"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

const healthcheckTimeout = 5 * time.Second
const coreAPIVersion = "v1"

// runHealthcheck is a readiness probe, not a gRPC health probe. It connects
// only to the process' loopback listener, authenticates with the protected
// token file, and verifies the instance, API version, and minimum Core
// capabilities exposed by AgentService.
func runHealthcheck(cfg config.Config, serverNames ...string) error {
	options := healthcheckOptions{serverName: ""}
	if len(serverNames) > 0 {
		options.serverName = serverNames[0]
	}
	return runHealthcheckOptions(cfg, options)
}

func runHealthcheckOptions(cfg config.Config, options healthcheckOptions) error {
	address, err := healthcheckAddress(cfg.ListenAddress)
	if err != nil {
		return err
	}
	token, err := auth.ReadServiceTokenFile(cfg.ServiceTokenFile)
	if err != nil {
		return fmt.Errorf("read service token for readiness: %w", err)
	}
	certificate, err := os.ReadFile(cfg.TLSCertFile)
	if err != nil {
		return errors.New("read TLS certificate for readiness")
	}
	roots, poolErr := x509.SystemCertPool()
	if poolErr != nil || roots == nil {
		roots = x509.NewCertPool()
	}
	if !roots.AppendCertsFromPEM(certificate) {
		return errors.New("TLS certificate does not contain PEM data")
	}
	serverName := strings.TrimSpace(os.Getenv("AGENT_HEALTHCHECK_SERVER_NAME"))
	if serverName == "" {
		serverName = "localhost"
	}
	if strings.TrimSpace(options.serverName) != "" {
		serverName = strings.TrimSpace(options.serverName)
	}
	if !validHealthcheckServerName(serverName) {
		return errors.New("healthcheck server name must be a DNS name or IP SAN")
	}

	ctx, cancel := context.WithTimeout(context.Background(), healthcheckTimeout)
	defer cancel()
	conn, err := grpc.DialContext(ctx, address,
		grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
			RootCAs: roots, ServerName: serverName, MinVersion: tls.VersionTLS13,
		})),
		grpc.WithPerRPCCredentials(readinessCredentials{token: token}),
		grpc.WithBlock(),
	)
	if err != nil {
		return fmt.Errorf("dial local Agent readiness endpoint: %w", err)
	}
	defer conn.Close()
	client := agentv1.NewAgentServiceClient(conn)
	info, err := client.GetInstanceInfo(ctx, &agentv1.GetInstanceInfoRequest{})
	if err != nil {
		return fmt.Errorf("read Agent instance readiness: %w", err)
	}
	expectedInstanceID := cfg.InstanceID
	if options.expectInstanceID != "" {
		expectedInstanceID = options.expectInstanceID
	}
	if info.GetInstanceId() != expectedInstanceID {
		return fmt.Errorf("Agent instance mismatch: got %q", info.GetInstanceId())
	}
	if info.GetApiVersion() != coreAPIVersion {
		return fmt.Errorf("Agent API version mismatch: got %q", info.GetApiVersion())
	}
	caps, err := client.GetCapabilities(ctx, &agentv1.GetCapabilitiesRequest{})
	if err != nil {
		return fmt.Errorf("read Agent capabilities readiness: %w", err)
	}
	if caps.GetApiVersion() != coreAPIVersion {
		return fmt.Errorf("Agent capabilities API version mismatch: got %q", caps.GetApiVersion())
	}
	enabled := make(map[string]bool, len(caps.GetCapabilities()))
	for _, capability := range caps.GetCapabilities() {
		if capability != nil && capability.GetEnabled() {
			enabled[capability.GetName()] = true
		}
	}
	requiredCapabilities := []string{"agent.info", "model.profile", "conversation"}
	requiredCapabilities = append(requiredCapabilities, options.requiredCaps...)
	seen := make(map[string]struct{}, len(requiredCapabilities))
	for _, required := range requiredCapabilities {
		if _, ok := seen[required]; ok {
			continue
		}
		seen[required] = struct{}{}
		if !enabled[required] {
			return fmt.Errorf("required Agent capability %q is not enabled", required)
		}
	}
	return nil
}

func validHealthcheckServerName(value string) bool {
	if value == "" || value != strings.TrimSpace(value) || len(value) > 253 || strings.ContainsAny(value, " \t\r\n\x00") {
		return false
	}
	if net.ParseIP(value) != nil {
		return true
	}
	for _, label := range strings.Split(value, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, character := range label {
			if !(character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || character == '-') {
				return false
			}
		}
	}
	return true
}

type readinessCredentials struct{ token string }

func (c readinessCredentials) GetRequestMetadata(context.Context, ...string) (map[string]string, error) {
	return map[string]string{"authorization": "DTX-Agent-Token " + c.token}, nil
}

func (readinessCredentials) RequireTransportSecurity() bool { return true }

func healthcheckAddress(listen string) (string, error) {
	listen = strings.TrimSpace(listen)
	if listen == "" {
		listen = ":9443"
	}
	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		return "", errors.New("grpc_listen must be a TCP host:port address")
	}
	parsedPort, err := strconv.ParseUint(port, 10, 16)
	if err != nil || parsedPort == 0 {
		return "", errors.New("grpc_listen must contain a non-zero TCP port")
	}
	if host != "" {
		parsedHost := net.ParseIP(host)
		if host != "localhost" && (parsedHost == nil || !parsedHost.IsLoopback() && !parsedHost.IsUnspecified()) {
			return "", errors.New("grpc_listen must use a loopback or unspecified host for readiness")
		}
	}
	return net.JoinHostPort("127.0.0.1", strconv.FormatUint(parsedPort, 10)), nil
}
