package workermarket

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"

	"github.com/YingSuiAI/dirextalk-agent/internal/security"
)

// SignRegistryPayloadJSON validates and canonicalizes an operator-approved
// registry payload before signing it. Private key bytes are never serialized.
func SignRegistryPayloadJSON(
	raw []byte,
	privateKey ed25519.PrivateKey,
) ([]byte, error) {
	if len(raw) == 0 ||
		int64(len(raw)) > maximumRegistryBytes ||
		len(privateKey) != ed25519.PrivateKeySize ||
		security.ContainsLikelySecret(string(raw)) {
		return nil, ErrInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var payload RegistryPayloadV1
	if decoder.Decode(&payload) != nil {
		return nil, ErrInvalid
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, ErrInvalid
	}
	publicKey, ok := privateKey.Public().(ed25519.PublicKey)
	if !ok || payload.SignerKeyID != SignerKeyID(publicKey) {
		return nil, ErrInvalid
	}
	normalized, _, _, err := normalizePayload(payload)
	if err != nil {
		return nil, err
	}
	canonical, err := json.Marshal(normalized)
	if err != nil {
		return nil, ErrInvalid
	}
	document := SignedRegistryDocumentV1{
		Payload: normalized,
		SignatureBase64URL: base64.RawURLEncoding.EncodeToString(
			ed25519.Sign(privateKey, canonical),
		),
	}
	encoded, err := json.Marshal(document)
	if err != nil {
		return nil, ErrInvalid
	}
	return append(encoded, '\n'), nil
}
