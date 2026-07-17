//go:build !linux

package bootstrap

import "context"

type AtomicSecretMaterializer struct{}

func NewAtomicSecretMaterializer() *AtomicSecretMaterializer { return &AtomicSecretMaterializer{} }

func (*AtomicSecretMaterializer) ReplaceSecret(context.Context, SecretFileSpec, []byte) (bool, error) {
	return false, ErrMaterialize
}
