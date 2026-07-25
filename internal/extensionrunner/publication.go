package extensionrunner

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
)

// PublishRequest is the authenticated runner publication operation. It carries
// only a canonical manifest; file bytes arrive as sealed SCM_RIGHTS descriptors
// in manifest order. Destination is never caller supplied.
type PublishRequest struct {
	Op      string          `json:"op"`
	Digest  string          `json:"digest"`
	Entries []ManifestEntry `json:"entries"`
}
type PublishFile struct {
	Path string
	Data []byte
}
type PublishResponse struct {
	Digest   string `json:"digest"`
	Replayed bool   `json:"replayed,omitempty"`
}

func ValidatePublishRequest(r PublishRequest, fdCount int) error {
	if r.Op != "publish_v1" || !digestRE.MatchString(r.Digest) || len(r.Entries) == 0 || len(r.Entries) != fdCount || ManifestDigest(r.Entries) != r.Digest {
		return ErrInvalid
	}
	last := ""
	for _, e := range r.Entries {
		if !safeRelativeSlash(e.Path) || e.Path == installManifestName || !digestRE.MatchString(e.SHA256) || e.Size < 0 || (last != "" && last >= e.Path) {
			return ErrInvalid
		}
		last = e.Path
	}
	return nil
}
func EncodePublishRequest(r PublishRequest) ([]byte, error) {
	if err := ValidatePublishRequest(r, len(r.Entries)); err != nil {
		return nil, err
	}
	b, e := json.Marshal(r)
	if e != nil {
		return nil, e
	}
	return b, nil
}
func DecodePublishRequest(b []byte) (PublishRequest, error) {
	var r PublishRequest
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(&r) != nil {
		return r, ErrInvalid
	}
	var extra any
	if d.Decode(&extra) == nil {
		return r, ErrInvalid
	}
	c, _ := json.Marshal(r)
	if !bytes.Equal(c, b) || strings.TrimSpace(r.Op) != "publish_v1" {
		return r, ErrInvalid
	}
	return r, nil
}

var ErrPublicationDenied = errors.New("runner publication denied")

type RemoveRequest struct {
	Op     string `json:"op"`
	Digest string `json:"digest"`
}

type ReadInstallRequest struct {
	Op     string `json:"op"`
	Digest string `json:"digest"`
	Path   string `json:"path"`
}

type ReadInstallResponse struct {
	Digest string `json:"digest"`
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

type RemoveResponse struct {
	Digest string `json:"digest"`
}

func (r RemoveRequest) Validate() error {
	if r.Op != "remove_v1" || !digestRE.MatchString(r.Digest) {
		return ErrInvalid
	}
	return nil
}

func (r ReadInstallRequest) Validate() error {
	if r.Op != "read_v1" || !digestRE.MatchString(r.Digest) || !safeRelativeSlash(r.Path) || r.Path == installManifestName {
		return ErrInvalid
	}
	return nil
}

func encodeCanonicalPublication(value any) ([]byte, error) {
	payload, err := json.Marshal(value)
	if err != nil || len(payload) == 0 || len(payload) > MaxV2PacketBytes {
		return nil, ErrInvalid
	}
	return payload, nil
}

func decodeCanonicalPublication(payload []byte, value any) error {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return ErrInvalid
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return ErrInvalid
	}
	canonical, err := json.Marshal(value)
	if err != nil || !bytes.Equal(canonical, payload) {
		return ErrInvalid
	}
	return nil
}
