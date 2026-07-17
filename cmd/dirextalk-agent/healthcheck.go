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

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	healthv1 "google.golang.org/grpc/health/grpc_health_v1"
)

const healthcheckTimeout = 5 * time.Second

type healthcheckConfig struct {
	address         string
	serverName      string
	certificateFile string
}

// runHealthcheck verifies the unauthenticated standard gRPC Health service
// through the same TLS boundary as callers. It intentionally accepts only a
// loopback endpoint, so the image health probe cannot become an arbitrary
// outbound gRPC client.
func runHealthcheck() error {
	configuration, err := healthcheckConfigFromEnvironment()
	if err != nil {
		return err
	}
	rootCAs, err := healthcheckRootCAs(configuration.certificateFile)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), healthcheckTimeout)
	defer cancel()
	connection, err := grpc.DialContext(ctx, configuration.address,
		grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
			RootCAs: rootCAs, ServerName: configuration.serverName, MinVersion: tls.VersionTLS13,
		})),
		grpc.WithBlock(),
	)
	if err != nil {
		return fmt.Errorf("dial local Agent gRPC health endpoint: %w", err)
	}
	defer connection.Close()

	response, err := healthv1.NewHealthClient(connection).Check(ctx, &healthv1.HealthCheckRequest{})
	if err != nil {
		return fmt.Errorf("check local Agent gRPC health endpoint: %w", err)
	}
	if response.GetStatus() != healthv1.HealthCheckResponse_SERVING {
		return errors.New("local Agent gRPC health endpoint is not serving")
	}
	return nil
}

func healthcheckConfigFromEnvironment() (healthcheckConfig, error) {
	listenAddress := strings.TrimSpace(os.Getenv("AGENT_GRPC_LISTEN"))
	if listenAddress == "" {
		listenAddress = ":9443"
	}
	listenPort, err := healthcheckPort(listenAddress)
	if err != nil {
		return healthcheckConfig{}, fmt.Errorf("AGENT_GRPC_LISTEN must contain a non-zero TCP port for healthcheck: %w", err)
	}

	address := strings.TrimSpace(os.Getenv("AGENT_GRPC_HEALTHCHECK_ADDRESS"))
	if address == "" {
		address = net.JoinHostPort("127.0.0.1", strconv.Itoa(listenPort))
	}
	host, port, err := net.SplitHostPort(address)
	if err != nil || port == "" {
		return healthcheckConfig{}, errors.New("AGENT_GRPC_HEALTHCHECK_ADDRESS must be a loopback TCP address")
	}
	healthPort, err := healthcheckPort(address)
	if err != nil || healthPort != listenPort {
		return healthcheckConfig{}, errors.New("AGENT_GRPC_HEALTHCHECK_ADDRESS must use the AGENT_GRPC_LISTEN port")
	}
	parsedHost := net.ParseIP(host)
	if parsedHost == nil || !parsedHost.IsLoopback() {
		return healthcheckConfig{}, errors.New("AGENT_GRPC_HEALTHCHECK_ADDRESS must use an IP loopback host")
	}

	serverName := os.Getenv("AGENT_GRPC_HEALTHCHECK_SERVER_NAME")
	if !validHealthcheckServerName(serverName) {
		return healthcheckConfig{}, errors.New("AGENT_GRPC_HEALTHCHECK_SERVER_NAME must be a DNS name or IP SAN without whitespace")
	}
	certificateFile := strings.TrimSpace(os.Getenv("AGENT_TLS_CERT_FILE"))
	if certificateFile == "" {
		return healthcheckConfig{}, errors.New("AGENT_TLS_CERT_FILE is required for healthcheck")
	}
	return healthcheckConfig{address: address, serverName: serverName, certificateFile: certificateFile}, nil
}

func healthcheckPort(address string) (int, error) {
	_, port, err := net.SplitHostPort(address)
	if err != nil || port == "" {
		return 0, errors.New("invalid TCP address")
	}
	parsed, err := strconv.ParseUint(port, 10, 16)
	if err != nil || parsed == 0 {
		return 0, errors.New("invalid TCP port")
	}
	return int(parsed), nil
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

func healthcheckRootCAs(certificateFile string) (*x509.CertPool, error) {
	certificates, err := os.ReadFile(certificateFile)
	if err != nil {
		return nil, errors.New("could not read AGENT_TLS_CERT_FILE for healthcheck")
	}
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	if !pool.AppendCertsFromPEM(certificates) {
		return nil, errors.New("AGENT_TLS_CERT_FILE must contain PEM certificate data for healthcheck")
	}
	return pool, nil
}
