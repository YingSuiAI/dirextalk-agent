package config

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"

	"github.com/google/uuid"
)

type Common struct {
	InstanceID  string
	DatabaseURL string
}

type Server struct {
	Common
	ListenAddress string
	TLSCertFile   string
	TLSKeyFile    string
	PepperFile    string
}

func LoadCommon() (Common, error) {
	databaseURLFile := strings.TrimSpace(os.Getenv("AGENT_DATABASE_URL_FILE"))
	common := Common{
		InstanceID: strings.TrimSpace(os.Getenv("AGENT_INSTANCE_ID")),
	}
	if _, err := uuid.Parse(common.InstanceID); err != nil {
		return Common{}, errors.New("AGENT_INSTANCE_ID must be a UUID")
	}
	if databaseURLFile == "" {
		return Common{}, errors.New("AGENT_DATABASE_URL_FILE is required")
	}
	databaseURL, err := ReadMountedSecretText(databaseURLFile)
	if err != nil {
		return Common{}, fmt.Errorf("read AGENT_DATABASE_URL_FILE: %w", err)
	}
	common.DatabaseURL = databaseURL
	return common, nil
}

func LoadServer() (Server, error) {
	common, err := LoadCommon()
	if err != nil {
		return Server{}, err
	}
	server := Server{
		Common: common, ListenAddress: strings.TrimSpace(os.Getenv("AGENT_GRPC_LISTEN")),
		TLSCertFile: strings.TrimSpace(os.Getenv("AGENT_TLS_CERT_FILE")),
		TLSKeyFile:  strings.TrimSpace(os.Getenv("AGENT_TLS_KEY_FILE")),
		PepperFile:  strings.TrimSpace(os.Getenv("AGENT_SERVICE_KEY_PEPPER_FILE")),
	}
	if server.ListenAddress == "" {
		server.ListenAddress = ":9443"
	}
	if server.TLSCertFile == "" || server.TLSKeyFile == "" {
		return Server{}, errors.New("AGENT_TLS_CERT_FILE and AGENT_TLS_KEY_FILE are required")
	}
	if server.PepperFile == "" {
		return Server{}, errors.New("AGENT_SERVICE_KEY_PEPPER_FILE is required")
	}
	return server, nil
}

func ReadKeyMaterial(path string) ([]byte, error) {
	if err := ValidateMountedSecretFile(path); err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read mounted secret file: %w", err)
	}
	defer clear(raw)
	trimmed := bytes.TrimSpace(raw)
	if decoded, ok := decodeKeyMaterial(base64.RawURLEncoding, trimmed); ok {
		return decoded, nil
	}
	if decoded, ok := decodeKeyMaterial(base64.StdEncoding, trimmed); ok {
		return decoded, nil
	}
	if len(trimmed) >= 32 {
		return append([]byte(nil), trimmed...), nil
	}
	return nil, errors.New("mounted secret material must contain at least 32 bytes")
}

func decodeKeyMaterial(encoding *base64.Encoding, value []byte) ([]byte, bool) {
	decoded := make([]byte, encoding.DecodedLen(len(value)))
	written, err := encoding.Decode(decoded, value)
	if err != nil || written < 32 {
		clear(decoded)
		return nil, false
	}
	return decoded[:written], true
}

func ReadMountedSecretText(path string) (string, error) {
	if err := ValidateMountedSecretFile(path); err != nil {
		return "", err
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read mounted secret file: %w", err)
	}
	defer clear(raw)
	value := strings.TrimSpace(string(raw))
	if value == "" {
		return "", errors.New("mounted secret file must not be empty")
	}
	if strings.ContainsAny(value, "\r\n\x00") {
		return "", errors.New("mounted secret file must contain one text value")
	}
	return value, nil
}

func ValidateMountedSecretFile(path string) error {
	if strings.TrimSpace(path) == "" {
		return errors.New("mounted secret path is required")
	}
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("inspect mounted secret file: %w", err)
	}
	if !info.Mode().IsRegular() {
		return errors.New("mounted secret path must be a regular file")
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return errors.New("mounted secret file must not be group/world accessible")
	}
	return nil
}
