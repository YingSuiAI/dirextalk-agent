package workermaintenance

import (
	"context"
	"crypto/ed25519"
	"errors"

	"github.com/YingSuiAI/dirextalk-agent/internal/installer"
	"github.com/YingSuiAI/dirextalk-agent/internal/installer/roothelper"
	"github.com/YingSuiAI/dirextalk-agent/internal/workeroperation"
)

type SocketRootControl struct{ client *roothelper.SocketClient }

func NewSocketRootControl(client *roothelper.SocketClient) (*SocketRootControl, error) {
	if client == nil {
		return nil, ErrInvalid
	}
	return &SocketRootControl{client: client}, nil
}

func (control *SocketRootControl) Bootstrap(ctx context.Context, deliveryCBOR, capabilityCBOR []byte) (roothelper.PossessionProof, error) {
	var delivery installer.DeliveryV1
	var capability installer.SignedRootHelperBootstrapCapabilityV1
	if installer.DecodeCanonical(deliveryCBOR, &delivery) != nil ||
		installer.DecodeCanonical(capabilityCBOR, &capability) != nil {
		return roothelper.PossessionProof{}, ErrInvalid
	}
	value, err := control.client.Bootstrap(ctx, delivery, capability)
	return value, rootPublicError(err)
}

func (control *SocketRootControl) Canary(ctx context.Context, deliveryCBOR, capabilityCBOR []byte) (roothelper.CanaryProof, error) {
	var delivery installer.DeliveryV1
	var capability installer.SignedRootHelperBootstrapCapabilityV1
	if installer.DecodeCanonical(deliveryCBOR, &delivery) != nil ||
		installer.DecodeCanonical(capabilityCBOR, &capability) != nil {
		return roothelper.CanaryProof{}, ErrInvalid
	}
	value, err := control.client.Canary(ctx, delivery, capability)
	return value, rootPublicError(err)
}

func (control *SocketRootControl) Restart(ctx context.Context, deliveryCBOR, capabilityCBOR,
	helperPublicKey []byte) (workeroperation.RootHelperReceipt, error) {
	var delivery installer.DeliveryV1
	var capability installer.SignedRootHelperRestartCapabilityV1
	if installer.DecodeCanonical(deliveryCBOR, &delivery) != nil ||
		installer.DecodeCanonical(capabilityCBOR, &capability) != nil ||
		len(helperPublicKey) != ed25519.PublicKeySize {
		return workeroperation.RootHelperReceipt{}, ErrInvalid
	}
	value, err := control.client.Restart(ctx, delivery, capability, ed25519.PublicKey(append([]byte(nil), helperPublicKey...)))
	return value, rootPublicError(err)
}

func rootPublicError(err error) error {
	if errors.Is(err, roothelper.ErrUnavailable) || errors.Is(err, roothelper.ErrNotReady) {
		return ErrUnavailable
	}
	return err
}

var _ RootControl = (*SocketRootControl)(nil)
