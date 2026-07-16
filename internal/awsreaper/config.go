package awsreaper

import (
	"errors"
	"regexp"
	"strings"

	"github.com/google/uuid"
)

var (
	ErrInvalidConfig = errors.New("invalid AWS Reaper configuration")
	tableNamePattern = regexp.MustCompile(`^[A-Za-z0-9_.-]{3,255}$`)
	regionPattern    = regexp.MustCompile(`^[a-z]{2}(?:-[a-z0-9]+)+-[0-9]+$`)
)

type Config struct {
	AgentInstanceID string
	Region          string
	ManifestTable   string
}

type Getenv func(string) string

func LoadConfig(getenv Getenv) (Config, error) {
	if getenv == nil {
		return Config{}, ErrInvalidConfig
	}
	config := Config{
		AgentInstanceID: strings.TrimSpace(getenv("AGENT_INSTANCE_ID")),
		Region:          strings.TrimSpace(getenv("AWS_REGION")),
		ManifestTable:   strings.TrimSpace(getenv("RESOURCE_MANIFEST_TABLE")),
	}
	if err := config.Validate(); err != nil {
		return Config{}, err
	}
	return config, nil
}

func (config Config) Validate() error {
	instanceID, err := uuid.Parse(config.AgentInstanceID)
	if err != nil || instanceID == uuid.Nil || !regionPattern.MatchString(config.Region) || !tableNamePattern.MatchString(config.ManifestTable) {
		return ErrInvalidConfig
	}
	return nil
}
