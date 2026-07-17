//go:build !linux

package bootstrap

import (
	"context"
	"errors"
	"testing"
)

func TestNonLinuxVolumeMaterializerFailsClosed(t *testing.T) {
	if err := NewLinuxVolumeMaterializer().Prepare(context.Background(), []VolumeMountV1{testVolumeMount()}); !errors.Is(err, ErrMaterialize) {
		t.Fatalf("non-Linux volume materialization error = %v", err)
	}
}
