package sdkclient

import (
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
)

func TestCloudWorkerSDKClientsDisableInternalRetries(t *testing.T) {
	configured := false
	config := awssdk.Config{Retryer: func() awssdk.Retryer {
		configured = true
		return nil
	}}
	config = withoutSDKRetries(config)
	retryer := config.Retryer()
	if configured || retryer == nil || retryer.MaxAttempts() != 1 || retryer.IsErrorRetryable(assertionError("retry")) {
		t.Fatalf("cloud worker SDK retryer is not single-attempt: configured=%t retryer=%T", configured, retryer)
	}
}

type assertionError string

func (value assertionError) Error() string { return string(value) }
