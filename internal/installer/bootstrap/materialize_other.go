//go:build !linux

package bootstrap

import "context"

type AtomicTrustMaterializer struct{}

func NewAtomicTrustMaterializer() *AtomicTrustMaterializer { return &AtomicTrustMaterializer{} }

func (*AtomicTrustMaterializer) Replace(context.Context, TrustFileSpec, []byte) (bool, error) {
	return false, ErrMaterialize
}
