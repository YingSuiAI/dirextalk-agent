package secretbootstrap

import (
	"crypto/ecdh"
	"encoding/base64"
	"regexp"
	"time"
)

var (
	uuidPattern       = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	identifierPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	credentialPattern = regexp.MustCompile(`(?i)(?:AKIA|ASIA)[A-Z0-9]{16}|aws[_ -]?(?:secret[_ -]?access[_ -]?key|session[_ -]?token)|-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----|(?:^|[^A-Za-z0-9])(?:gh[pousr]_[A-Za-z0-9]{20,}|hf_[A-Za-z0-9]{20,}|sk[-_][A-Za-z0-9_-]{20,}|xox[baprs]-[A-Za-z0-9-]{10,})`)
)

func validateBinding(value BindingV1) error {
	for _, item := range []string{value.AgentInstanceID, value.OwnerID, value.Purpose, value.TargetID} {
		if !identifierPattern.MatchString(item) || credentialPattern.MatchString(item) {
			return ErrInvalidContext
		}
	}
	return nil
}

func validateSession(value SessionV1) error {
	if value.SchemaVersion != SessionSchemaV1 || !uuidPattern.MatchString(value.SessionID) {
		return ErrInvalidContext
	}
	if err := validateBinding(value.Binding()); err != nil {
		return err
	}
	if value.CreatedAt.IsZero() || value.ExpiresAt.IsZero() || !value.CreatedAt.Before(value.ExpiresAt) || value.ExpiresAt.Sub(value.CreatedAt) != SessionTTL {
		return ErrInvalidContext
	}
	if value.Revision == 0 || !validStatus(value.Status) {
		return ErrInvalidContext
	}
	publicKey, err := decodeRawURL(value.ServerPublicKey, 32)
	if err != nil {
		return ErrInvalidContext
	}
	if _, err := ecdh.X25519().NewPublicKey(publicKey); err != nil {
		return ErrInvalidContext
	}
	return nil
}

func validStatus(value Status) bool {
	switch value {
	case StatusAwaitingUpload, StatusUploaded, StatusConsumed, StatusExpired:
		return true
	default:
		return false
	}
}

func validateEnvelope(session SessionV1, value EnvelopeV1) (clientPublicKey, nonce, ciphertext []byte, err error) {
	if value.SchemaVersion != EnvelopeSchemaV1 || value.SessionID != session.SessionID {
		return nil, nil, nil, ErrInvalidEnvelope
	}
	clientPublicKey, err = decodeRawURL(value.ClientPublicKey, 32)
	if err != nil {
		return nil, nil, nil, ErrInvalidEnvelope
	}
	if _, err = ecdh.X25519().NewPublicKey(clientPublicKey); err != nil {
		return nil, nil, nil, ErrInvalidEnvelope
	}
	nonce, err = decodeRawURL(value.Nonce, nonceSize)
	if err != nil {
		return nil, nil, nil, ErrInvalidEnvelope
	}
	ciphertext, err = decodeRawURLRange(value.Ciphertext, gcmTagSize+1, MaxPlaintextSize+gcmTagSize)
	if err != nil {
		return nil, nil, nil, ErrInvalidEnvelope
	}
	return clientPublicKey, nonce, ciphertext, nil
}

func parseUploadToken(value string) ([]byte, error) {
	decoded, err := decodeRawURL(value, uploadTokenSize)
	if err != nil {
		return nil, ErrInvalidUploadToken
	}
	return decoded, nil
}

func decodeRawURL(value string, size int) ([]byte, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(decoded) != size || base64.RawURLEncoding.EncodeToString(decoded) != value {
		return nil, ErrInvalidContext
	}
	return decoded, nil
}

func decodeRawURLRange(value string, minimum, maximum int) ([]byte, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(decoded) < minimum || len(decoded) > maximum || base64.RawURLEncoding.EncodeToString(decoded) != value {
		return nil, ErrInvalidContext
	}
	return decoded, nil
}

func utc(value time.Time) time.Time {
	return value.Round(0).UTC()
}
