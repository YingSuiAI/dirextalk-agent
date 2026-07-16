//go:build !linux

package bootstrap

import (
	"context"
	"io"
)

type AtomicArtifactMaterializer struct{}

func NewAtomicArtifactMaterializer() *AtomicArtifactMaterializer {
	return &AtomicArtifactMaterializer{}
}

func (*AtomicArtifactMaterializer) Replace(context.Context, ArtifactFileSpec, io.Reader) (bool, error) {
	return false, ErrMaterialize
}
