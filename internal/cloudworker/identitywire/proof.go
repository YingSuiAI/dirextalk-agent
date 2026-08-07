// Package identitywire owns the one sensitive transport payload shared by the
// ephemeral Worker and the private WorkerControl listener. It contains no
// identity policy and cannot be logged or marshaled through generic JSON.
package identitywire

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
)

const MethodSTSSigV4IMDSPKCS7V1 = "aws_sts_sigv4_imds_pkcs7_v1"

var ErrInvalid = errors.New("invalid cloud Worker identity proof payload")

type Payload struct {
	Region        string `json:"region"`
	Endpoint      string `json:"endpoint"`
	Method        string `json:"method"`
	Host          string `json:"host"`
	ContentType   string `json:"content_type"`
	ContentSHA256 string `json:"content_sha256"`
	AmzDate       string `json:"amz_date"`
	Challenge     string `json:"challenge"`
	Body          []byte `json:"body"`
	Authorization []byte `json:"authorization"`
	SessionToken  []byte `json:"session_token"`
	IMDSDocument  []byte `json:"imds_document"`
	IMDSPKCS7     []byte `json:"imds_pkcs7"`
}

type payloadJSON Payload

func Encode(payload Payload) ([]byte, error) {
	raw, err := json.Marshal(payloadJSON(payload))
	if err != nil || len(raw) == 0 {
		clear(raw)
		return nil, ErrInvalid
	}
	return raw, nil
}

func Decode(raw []byte) (Payload, error) {
	if len(raw) == 0 {
		return Payload{}, ErrInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var decoded payloadJSON
	if decoder.Decode(&decoded) != nil {
		return Payload{}, ErrInvalid
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return Payload{}, ErrInvalid
	}
	canonical, err := json.Marshal(decoded)
	if err != nil || !bytes.Equal(canonical, raw) {
		clear(canonical)
		payload := Payload(decoded)
		payload.Destroy()
		return Payload{}, ErrInvalid
	}
	clear(canonical)
	return Payload(decoded), nil
}

func (payload *Payload) Destroy() {
	if payload == nil {
		return
	}
	clear(payload.Body)
	clear(payload.Authorization)
	clear(payload.SessionToken)
	clear(payload.IMDSDocument)
	clear(payload.IMDSPKCS7)
	*payload = Payload{}
}

func (Payload) String() string   { return "[redacted-cloud-worker-identity-payload]" }
func (Payload) GoString() string { return "identitywire.Payload{[redacted]}" }
func (Payload) LogValue() slog.Value {
	return slog.StringValue("[redacted-cloud-worker-identity-payload]")
}
func (Payload) MarshalJSON() ([]byte, error) { return nil, ErrInvalid }

var _ json.Marshaler = Payload{}
