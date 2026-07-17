package app

import (
	"context"
	"crypto/ed25519"
	"time"

	cloudapproval "github.com/YingSuiAI/dirextalk-agent/internal/cloud/approval"
	"github.com/YingSuiAI/dirextalk-agent/internal/helperkey"
)

type approvalDeviceKeyReader interface {
	GetDeviceKey(context.Context, string) (cloudapproval.DeviceKeyV1, error)
}

type rootHelperApprovalDeviceVerifier struct {
	devices approvalDeviceKeyReader
	now     func() time.Time
}

func (verifier rootHelperApprovalDeviceVerifier) VerifyRootHelperKeyApproval(ctx context.Context, ownerID, keyID string,
	payload, signature []byte) error {
	if verifier.devices == nil || verifier.now == nil || ctx == nil {
		return helperkey.ErrInvalid
	}
	device, err := verifier.devices.GetDeviceKey(ctx, keyID)
	if err != nil || device.OwnerID != ownerID || device.ValidateAt(verifier.now().UTC()) != nil ||
		!ed25519.Verify(device.PublicKey, payload, signature) {
		return helperkey.ErrInvalid
	}
	return nil
}

var _ helperkey.ApprovalDeviceVerifier = rootHelperApprovalDeviceVerifier{}
