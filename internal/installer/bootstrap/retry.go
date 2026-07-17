package bootstrap

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/aws/smithy-go"
)

// accessDeniedRetry is intentionally limited to the short IAM/resource-policy
// propagation window immediately after the control plane binds a Worker
// principal. It never converts malformed data, timeouts, or arbitrary AWS
// errors into retries. The socket stays disabled until the caller succeeds.
type accessDeniedRetry struct {
	attempts int
	wait     func(context.Context, time.Duration) error
}

func defaultAccessDeniedRetry() accessDeniedRetry {
	return accessDeniedRetry{attempts: 5, wait: waitForAccessRetry}
}

func (retry accessDeniedRetry) valid() bool {
	return retry.attempts >= 1 && retry.attempts <= 8 && retry.wait != nil
}

func retryAccessDenied[T any](ctx context.Context, retry accessDeniedRetry, operation func() (T, error)) (T, error) {
	var zero T
	if ctx == nil || operation == nil || !retry.valid() {
		return zero, ErrInvalidInput
	}
	for attempt := 0; attempt < retry.attempts; attempt++ {
		value, err := operation()
		if err == nil || !bootstrapAccessDenied(err) || attempt == retry.attempts-1 {
			return value, err
		}
		if waitErr := retry.wait(ctx, accessRetryDelay(attempt)); waitErr != nil {
			return zero, waitErr
		}
	}
	return zero, ErrInvalidInput
}

func waitForAccessRetry(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func accessRetryDelay(attempt int) time.Duration {
	if attempt < 0 {
		return 250 * time.Millisecond
	}
	delay := 250 * time.Millisecond * time.Duration(1<<attempt)
	if delay > 2*time.Second {
		return 2 * time.Second
	}
	return delay
}

func bootstrapAccessDenied(err error) bool {
	var apiErr smithy.APIError
	if !errors.As(err, &apiErr) {
		return false
	}
	switch strings.ToLower(apiErr.ErrorCode()) {
	case "accessdenied", "accessdeniedexception", "unauthorizedoperation":
		return true
	default:
		return false
	}
}
