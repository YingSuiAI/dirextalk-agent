//go:build !linux

package installer

import (
	"context"
	"runtime"
)

type unsupportedArtifactInspector struct{}

func NewRootOwnedArtifactInspector(root string) (ArtifactInspector, error) {
	if _, err := validateTargetRoot(root); err != nil {
		return nil, err
	}
	return unsupportedArtifactInspector{}, nil
}

func (unsupportedArtifactInspector) Verify(context.Context, ArtifactV1) error {
	return errorf(CodeArtifactVerification, "root-owned artifact verification is unsupported on %s", runtime.GOOS)
}

func ReadRootOwnedFile(string, int64) ([]byte, error) {
	return nil, errorf(CodeInvalidRequest, "root-owned trust files are unsupported on %s", runtime.GOOS)
}
