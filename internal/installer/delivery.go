package installer

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"slices"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloud/canonical"
	"github.com/google/uuid"
)

const (
	DeliverySchemaV1          = "dirextalk.agent.installer-delivery/v1"
	PreinstalledArtifactRoot  = "/usr/local/share/dirextalk-worker/artifacts"
	maximumLeaseGrantDuration = 30 * time.Minute
)

// DeliveryV1 is an immutable, non-secret per-deployment trust and command
// manifest. The same object is digest-locked in the Worker execution bundle
// and consumed by the trusted root bootstrap when it writes the public key and
// daemon configuration. The signing seed is never included.
type DeliveryV1 struct {
	SchemaVersion string                `json:"schema_version"`
	TrustID       string                `json:"trust_id"`
	PublicKey     []byte                `json:"public_key"`
	Config        DaemonConfigV1        `json:"config"`
	SignedPlan    SignedInstallerPlanV1 `json:"signed_plan"`
}

type RootTrustMaterialV1 struct {
	TrustID    string
	PublicKey  []byte
	ConfigCBOR []byte
}

// TrustIssuer derives a stable, independent Ed25519 key for each exact signed
// capability. Exact publication retries reproduce the same delivery while any
// command, artifact, deployment, plan, or approval change rotates trust. A
// short-lived lease grant is signed separately and never changes this key.
type TrustIssuer struct{ key []byte }

func NewTrustIssuer(key []byte) (*TrustIssuer, error) {
	if len(key) != sha256.Size {
		return nil, errorf(CodeInvalidRequest, "installer issuer key must contain 32 bytes")
	}
	return &TrustIssuer{key: append([]byte(nil), key...)}, nil
}

func (issuer *TrustIssuer) Close() {
	if issuer == nil {
		return
	}
	clear(issuer.key)
	issuer.key = nil
}

func (issuer *TrustIssuer) Issue(plan InstallerPlanV1, config DaemonConfigV1, now time.Time) (DeliveryV1, error) {
	if issuer == nil || len(issuer.key) != sha256.Size || now.IsZero() || config.SchemaVersion != DaemonConfigSchema || config.Binding != plan.Binding {
		return DeliveryV1{}, errorf(CodeInvalidRequest, "installer delivery inputs are invalid")
	}
	if err := validateDeliveryPlan(plan, config, now); err != nil {
		return DeliveryV1{}, err
	}
	privateKey, planBytes, err := issuer.derivePrivateKey(plan)
	if err != nil {
		return DeliveryV1{}, err
	}
	defer clear(privateKey)
	defer clear(planBytes)
	publicKey := append(ed25519.PublicKey(nil), privateKey.Public().(ed25519.PublicKey)...)
	signed := SignedInstallerPlanV1{
		Plan: plan, SignerKeyID: SignerKeyID(publicKey), Signature: ed25519.Sign(privateKey, planBytes),
	}
	clonedPlan, err := cloneSignedPlan(signed)
	if err != nil {
		clear(publicKey)
		clear(signed.Signature)
		return DeliveryV1{}, err
	}
	delivery := DeliveryV1{SchemaVersion: DeliverySchemaV1, PublicKey: publicKey, Config: config, SignedPlan: clonedPlan}
	delivery.TrustID, err = deliveryDigest(delivery)
	if err != nil {
		clear(delivery.PublicKey)
		clear(delivery.SignedPlan.Signature)
		return DeliveryV1{}, err
	}
	return delivery, nil
}

func (issuer *TrustIssuer) IssueLeaseGrant(delivery DeliveryV1, commandID string, leaseEpoch int64, leaseExpiresAt, now time.Time) (SignedLeaseGrantV1, error) {
	if issuer == nil || len(issuer.key) != sha256.Size || leaseEpoch < 1 || now.IsZero() || leaseExpiresAt.IsZero() {
		return SignedLeaseGrantV1{}, errorf(CodeInvalidRequest, "installer lease grant inputs are invalid")
	}
	if err := ValidateDeliveryAt(delivery, now); err != nil {
		return SignedLeaseGrantV1{}, err
	}
	if _, found := findCommand(delivery.SignedPlan.Plan.Commands, commandID); !found {
		return SignedLeaseGrantV1{}, errorf(CodeCommandNotAllowed, "command is not declared by the delivery")
	}
	issuedAt := now.UTC()
	expiresAt := leaseExpiresAt.UTC()
	planExpiresAt, _ := time.Parse(time.RFC3339Nano, delivery.SignedPlan.Plan.ExpiresAt)
	if !issuedAt.Before(expiresAt) || expiresAt.Sub(issuedAt) > maximumLeaseGrantDuration || expiresAt.After(planExpiresAt) {
		return SignedLeaseGrantV1{}, errorf(CodeLeaseRejected, "installer lease grant exceeds its capability")
	}
	planDigest, err := canonical.Digest(delivery.SignedPlan.Plan)
	if err != nil {
		return SignedLeaseGrantV1{}, errorf(CodeInvalidRequest, "digest installer plan")
	}
	grant := LeaseGrantV1{
		SchemaVersion: LeaseGrantSchemaV1, TrustID: delivery.TrustID, Binding: delivery.Config.Binding,
		PlanDigest: planDigest, OperationID: installerOperationID(delivery.TrustID, commandID), CommandID: commandID,
		LeaseEpoch: leaseEpoch, IssuedAt: issuedAt.Format(time.RFC3339Nano), ExpiresAt: expiresAt.Format(time.RFC3339Nano),
	}
	privateKey, planBytes, err := issuer.derivePrivateKey(delivery.SignedPlan.Plan)
	if err != nil {
		return SignedLeaseGrantV1{}, err
	}
	defer clear(privateKey)
	defer clear(planBytes)
	if !hmac.Equal(privateKey.Public().(ed25519.PublicKey), delivery.PublicKey) {
		return SignedLeaseGrantV1{}, errorf(CodeInvalidSignature, "installer issuer does not own delivery trust")
	}
	payload, err := LeaseGrantSigningBytes(grant)
	if err != nil {
		return SignedLeaseGrantV1{}, errorf(CodeInvalidRequest, "canonicalize installer lease grant")
	}
	defer clear(payload)
	return SignedLeaseGrantV1{Grant: grant, SignerKeyID: delivery.SignedPlan.SignerKeyID, Signature: ed25519.Sign(privateKey, payload)}, nil
}

func ValidateDeliveryAt(delivery DeliveryV1, now time.Time) error {
	if delivery.SchemaVersion != DeliverySchemaV1 || !digestPattern.MatchString(delivery.TrustID) || len(delivery.PublicKey) != ed25519.PublicKeySize ||
		delivery.Config.SchemaVersion != DaemonConfigSchema || delivery.Config.Binding != delivery.SignedPlan.Plan.Binding || now.IsZero() {
		return errorf(CodeInvalidRequest, "installer delivery contract is invalid")
	}
	if delivery.SignedPlan.SignerKeyID != SignerKeyID(ed25519.PublicKey(delivery.PublicKey)) || len(delivery.SignedPlan.Signature) != ed25519.SignatureSize {
		return errorf(CodeInvalidSignature, "installer delivery signer is invalid")
	}
	planBytes, err := PlanSigningBytes(delivery.SignedPlan.Plan)
	if err != nil || !ed25519.Verify(ed25519.PublicKey(delivery.PublicKey), planBytes, delivery.SignedPlan.Signature) {
		clear(planBytes)
		return errorf(CodeInvalidSignature, "installer delivery signature is invalid")
	}
	clear(planBytes)
	if err := validateDeliveryPlan(delivery.SignedPlan.Plan, delivery.Config, now); err != nil {
		return err
	}
	digest, err := deliveryDigest(delivery)
	if err != nil || !hmac.Equal([]byte(digest), []byte(delivery.TrustID)) {
		return errorf(CodeInvalidRequest, "installer delivery digest does not match")
	}
	return nil
}

func ValidateLeaseGrantAt(delivery DeliveryV1, signed SignedLeaseGrantV1, commandID string, now time.Time) error {
	if err := ValidateDeliveryAt(delivery, now); err != nil {
		return err
	}
	planDigest, err := canonical.Digest(delivery.SignedPlan.Plan)
	if err != nil {
		return errorf(CodeInvalidRequest, "digest installer plan")
	}
	grant := signed.Grant
	if grant.SchemaVersion != LeaseGrantSchemaV1 || grant.TrustID != delivery.TrustID || grant.Binding != delivery.Config.Binding ||
		grant.PlanDigest != planDigest || grant.OperationID != installerOperationID(delivery.TrustID, commandID) || grant.CommandID != commandID || grant.LeaseEpoch < 1 ||
		signed.SignerKeyID != delivery.SignedPlan.SignerKeyID || len(signed.Signature) != ed25519.SignatureSize {
		return errorf(CodeLeaseRejected, "installer lease grant binding is invalid")
	}
	issuedAt, issuedErr := parseCanonicalUTC(grant.IssuedAt)
	expiresAt, expiresErr := parseCanonicalUTC(grant.ExpiresAt)
	planExpiresAt, _ := time.Parse(time.RFC3339Nano, delivery.SignedPlan.Plan.ExpiresAt)
	current := now.UTC()
	if issuedErr != nil || expiresErr != nil || !issuedAt.Before(expiresAt) || expiresAt.Sub(issuedAt) > maximumLeaseGrantDuration ||
		current.Before(issuedAt) || !current.Before(expiresAt) || expiresAt.After(planExpiresAt) {
		return errorf(CodeLeaseRejected, "installer lease grant has expired or exceeds capability")
	}
	payload, err := LeaseGrantSigningBytes(grant)
	if err != nil || !ed25519.Verify(ed25519.PublicKey(delivery.PublicKey), payload, signed.Signature) {
		clear(payload)
		return errorf(CodeInvalidSignature, "installer lease grant signature is invalid")
	}
	clear(payload)
	return nil
}

func (delivery DeliveryV1) ExecuteRequest(commandID string, leaseGrant SignedLeaseGrantV1, now time.Time) (RequestV1, error) {
	if err := ValidateLeaseGrantAt(delivery, leaseGrant, commandID, now); err != nil {
		return RequestV1{}, err
	}
	signedPlan, err := cloneSignedPlan(delivery.SignedPlan)
	if err != nil {
		return RequestV1{}, err
	}
	clonedGrant, err := cloneSignedLeaseGrant(leaseGrant)
	if err != nil {
		return RequestV1{}, err
	}
	operationID := installerOperationID(delivery.TrustID, commandID)
	return RequestV1{
		SchemaVersion:  RequestSchemaV1,
		RequestID:      installerRequestID(operationID),
		IdempotencyKey: installerIdempotencyKey(operationID),
		Action:         ActionExecute, Binding: delivery.Config.Binding, SignedPlan: signedPlan, CommandID: commandID,
		OperationID: operationID, LeaseGrant: &clonedGrant,
	}, nil
}

func (delivery DeliveryV1) RootTrustMaterial(now time.Time) (RootTrustMaterialV1, error) {
	if err := ValidateDeliveryAt(delivery, now); err != nil {
		return RootTrustMaterialV1{}, err
	}
	config, err := canonical.Marshal(delivery.Config)
	if err != nil {
		return RootTrustMaterialV1{}, errorf(CodeInvalidRequest, "encode root installer binding")
	}
	return RootTrustMaterialV1{TrustID: delivery.TrustID, PublicKey: append([]byte(nil), delivery.PublicKey...), ConfigCBOR: config}, nil
}

func validateDeliveryPlan(plan InstallerPlanV1, config DaemonConfigV1, now time.Time) error {
	root, err := validateTargetRoot(config.TargetRoot)
	if err != nil {
		return err
	}
	if root != PreinstalledArtifactRoot {
		return errorf(CodeInvalidPath, "installer delivery permits only preinstalled artifacts")
	}
	if err := validatePlan(plan, root); err != nil {
		return err
	}
	for _, command := range plan.Commands {
		executableLocked := false
		for _, artifact := range plan.Artifacts {
			if artifact.TargetPath == command.Argv[0] && slices.Contains(command.ArtifactRefs, artifact.Name) {
				executableLocked = true
				break
			}
		}
		if !executableLocked {
			return errorf(CodeCommandNotAllowed, "installer executable is not a referenced preinstalled artifact")
		}
	}
	expiresAt, _ := time.Parse(time.RFC3339Nano, plan.ExpiresAt)
	if current := now.UTC(); !current.Before(expiresAt) {
		return errorf(CodePlanExpired, "installer delivery has expired")
	}
	return nil
}

func deliveryDigest(delivery DeliveryV1) (string, error) {
	document := delivery
	document.TrustID = ""
	digest, err := canonical.Digest(document)
	if err != nil {
		return "", errorf(CodeInvalidRequest, "digest installer delivery")
	}
	return digest, nil
}

func cloneSignedPlan(value SignedInstallerPlanV1) (SignedInstallerPlanV1, error) {
	encoded, err := canonical.Marshal(value)
	if err != nil {
		return SignedInstallerPlanV1{}, errorf(CodeInvalidRequest, "clone installer delivery")
	}
	defer clear(encoded)
	var cloned SignedInstallerPlanV1
	if err := DecodeCanonical(encoded, &cloned); err != nil {
		return SignedInstallerPlanV1{}, err
	}
	return cloned, nil
}

func (issuer *TrustIssuer) derivePrivateKey(plan InstallerPlanV1) (ed25519.PrivateKey, []byte, error) {
	if issuer == nil || len(issuer.key) != sha256.Size {
		return nil, nil, errorf(CodeInvalidRequest, "installer issuer is unavailable")
	}
	bindingBytes, err := canonical.Marshal(plan.Binding)
	if err != nil {
		return nil, nil, errorf(CodeInvalidRequest, "canonicalize installer binding")
	}
	defer clear(bindingBytes)
	planBytes, err := PlanSigningBytes(plan)
	if err != nil {
		return nil, nil, errorf(CodeInvalidRequest, "canonicalize installer plan")
	}
	seedMAC := hmac.New(sha256.New, issuer.key)
	seedMAC.Write([]byte(DeliverySchemaV1))
	seedMAC.Write([]byte{0})
	seedMAC.Write(bindingBytes)
	seedMAC.Write([]byte{0})
	seedMAC.Write(planBytes)
	seed := seedMAC.Sum(nil)
	privateKey := ed25519.NewKeyFromSeed(seed)
	clear(seed)
	return privateKey, planBytes, nil
}

func installerOperationID(trustID, commandID string) string {
	return uuid.NewSHA1(uuid.NameSpaceOID, []byte("dirextalk-installer-operation/v1\x00"+trustID+"\x00"+commandID)).String()
}

func installerRequestID(operationID string) string {
	return uuid.NewSHA1(uuid.NameSpaceOID, []byte("dirextalk-installer-request/v1\x00"+operationID)).String()
}

func installerIdempotencyKey(operationID string) string {
	return uuid.NewSHA1(uuid.NameSpaceOID, []byte("dirextalk-installer-idempotency/v1\x00"+operationID)).String()
}

func parseCanonicalUTC(value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil || parsed.Location() != time.UTC || parsed.Format(time.RFC3339Nano) != value {
		return time.Time{}, errorf(CodeInvalidRequest, "time must be canonical UTC RFC3339Nano")
	}
	return parsed, nil
}

func cloneSignedLeaseGrant(value SignedLeaseGrantV1) (SignedLeaseGrantV1, error) {
	encoded, err := canonical.Marshal(value)
	if err != nil {
		return SignedLeaseGrantV1{}, errorf(CodeInvalidRequest, "clone installer lease grant")
	}
	defer clear(encoded)
	var cloned SignedLeaseGrantV1
	if err := DecodeCanonical(encoded, &cloned); err != nil {
		return SignedLeaseGrantV1{}, err
	}
	return cloned, nil
}
