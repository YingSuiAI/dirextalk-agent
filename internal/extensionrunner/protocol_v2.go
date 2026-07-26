package extensionrunner

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"io"
)

const ProbeProtocolV1 = "dirextalk.extension.runner.probe.v1"

type ProbeRequest struct {
	Op      string `json:"op"`
	Version string `json:"version"`
	Nonce   string `json:"nonce"`
}

type ProbeResponse struct {
	Ready   bool   `json:"ready"`
	Version string `json:"version"`
	Nonce   string `json:"nonce"`
}

func EncodeProbeRequest(r ProbeRequest) ([]byte, error) {
	if r.Op != "probe" || r.Version != ProbeProtocolV1 || r.Nonce == "" || len(r.Nonce) > 128 {
		return nil, ErrProtocol
	}
	b, err := json.Marshal(r)
	if err != nil || len(b) > MaxV2PacketBytes {
		return nil, ErrProtocol
	}
	return b, nil
}

func DecodeProbeRequest(b []byte) (ProbeRequest, error) {
	var r ProbeRequest
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if dec.Decode(&r) != nil || r.Op != "probe" || r.Version != ProbeProtocolV1 || r.Nonce == "" || len(r.Nonce) > 128 {
		return ProbeRequest{}, ErrProtocol
	}
	var extra any
	if dec.Decode(&extra) != io.EOF {
		return ProbeRequest{}, ErrProtocol
	}
	canonical, err := json.Marshal(r)
	if err != nil || !bytes.Equal(canonical, b) {
		return ProbeRequest{}, ErrProtocol
	}
	return r, nil
}

func EncodeProbeResponse(r ProbeResponse) ([]byte, error) {
	if r.Version != ProbeProtocolV1 || r.Nonce == "" || len(r.Nonce) > 128 {
		return nil, ErrProtocol
	}
	b, err := json.Marshal(r)
	if err != nil || len(b) > MaxV2PacketBytes {
		return nil, ErrProtocol
	}
	return b, nil
}

func DecodeProbeResponse(b []byte, wantNonce string) error {
	var r ProbeResponse
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if dec.Decode(&r) != nil || r.Version != ProbeProtocolV1 || r.Nonce != wantNonce || !r.Ready {
		return ErrProtocol
	}
	var extra any
	if dec.Decode(&extra) != io.EOF {
		return ErrProtocol
	}
	canonical, err := json.Marshal(r)
	if err != nil || !bytes.Equal(canonical, b) {
		return ErrProtocol
	}
	return nil
}

// EncodeRequestV2 returns one complete length-prefixed seqpacket datagram.
func EncodeRequestV2(r RequestV2) ([]byte, error) {
	if err := ValidateRequestV2(r); err != nil {
		return nil, err
	}
	b, err := json.Marshal(r)
	if err != nil || len(b) > MaxV2PacketBytes-4 {
		return nil, ErrProtocol
	}
	out := make([]byte, 4+len(b))
	binary.BigEndian.PutUint32(out, uint32(len(b)))
	copy(out[4:], b)
	return out, nil
}

// ReadRequestV2Datagram consumes exactly one datagram and its SCM_RIGHTS fds.
// A stream reader is deliberately not accepted: seqpacket boundaries are part
// of the ABI and truncation/concatenation are protocol failures.
func ReadRequestV2Datagram(datagram []byte, fds []int) (RequestV2, error) {
	if len(datagram) < 4 {
		return RequestV2{}, ErrProtocol
	}
	n := int(binary.BigEndian.Uint32(datagram[:4]))
	if n <= 0 || n > MaxV2PacketBytes-4 || len(datagram) != 4+n {
		return RequestV2{}, ErrProtocol
	}
	payload := datagram[4:]
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.DisallowUnknownFields()
	var r RequestV2
	if err := dec.Decode(&r); err != nil {
		return RequestV2{}, ErrProtocol
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return RequestV2{}, ErrProtocol
	}
	b, err := json.Marshal(r)
	if err != nil || !bytes.Equal(payload, b) {
		return RequestV2{}, ErrProtocol
	}
	if err := ValidateFDSet(r, len(fds)); err != nil {
		return RequestV2{}, err
	}
	return r, nil
}

func ValidateRequestFDs(r RequestV2, fds []int) error {
	if err := ValidateFDSet(r, len(fds)); err != nil {
		return err
	}
	if r.Stdin != nil {
		if err := VerifySealedFD(fds[r.Stdin.Index], r.Stdin.Size, r.Stdin.SHA256); err != nil {
			return err
		}
	}
	for _, s := range r.Secrets {
		if err := VerifySealedFD(fds[s.Index], s.Size, s.SHA256); err != nil {
			return err
		}
	}
	return nil
}

// ReadRequestV2 reads one frame from a test transport. Production callers use
// recvmsg on SOCK_SEQPACKET and pass the resulting datagram to the function
// above, preserving ancillary descriptor boundaries.
func ReadRequestV2(rd io.Reader, fds []int) (RequestV2, error) {
	var h [4]byte
	if _, err := io.ReadFull(rd, h[:]); err != nil {
		return RequestV2{}, ErrProtocol
	}
	n := int(binary.BigEndian.Uint32(h[:]))
	if n <= 0 || n > MaxV2PacketBytes-4 {
		return RequestV2{}, ErrProtocol
	}
	p := make([]byte, n)
	if _, err := io.ReadFull(rd, p); err != nil {
		return RequestV2{}, ErrProtocol
	}
	return ReadRequestV2Datagram(append(h[:], p...), fds)
}

func EncodeStatusV1(s StatusV1) ([]byte, error) {
	b, e := json.Marshal(s)
	if e != nil || len(b) > MaxV2PacketBytes-4 {
		return nil, ErrProtocol
	}
	out := make([]byte, 4+len(b))
	binary.BigEndian.PutUint32(out, uint32(len(b)))
	copy(out[4:], b)
	return out, nil
}

// ReadStatusV1Datagram accepts exactly one canonical status datagram.  Keeping
// this separate from the transport makes the client fail closed on framing,
// JSON, or canonicalization changes.
func ReadStatusV1Datagram(datagram []byte) (StatusV1, error) {
	if len(datagram) < 4 {
		return StatusV1{}, ErrProtocol
	}
	n := int(binary.BigEndian.Uint32(datagram[:4]))
	if n <= 0 || n > MaxV2PacketBytes-4 || len(datagram) != 4+n {
		return StatusV1{}, ErrProtocol
	}
	payload := datagram[4:]
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.DisallowUnknownFields()
	var status StatusV1
	if err := dec.Decode(&status); err != nil {
		return StatusV1{}, ErrProtocol
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return StatusV1{}, ErrProtocol
	}
	b, err := json.Marshal(status)
	if err != nil || !bytes.Equal(payload, b) {
		return StatusV1{}, ErrProtocol
	}
	return status, nil
}

// ValidateStatusV1 binds an untrusted runner response to the exact request
// admitted by this client.  The V2 response intentionally carries only RunID;
// TaskID and TaskFence are bound by validating the original request first.
func ValidateStatusV1(request RequestV2, status StatusV1) error {
	if err := ValidateRequestV2(request); err != nil || status.RunID != request.RunID ||
		!ValidPhase(status.Phase) || !ValidErrorCode(status.Error) ||
		(status.Phase != PhaseTombstone && status.Phase != PhaseFailed) ||
		len(status.Stdout) > MaxOutputBytes || len(status.Stderr) > MaxOutputBytes || len(status.ResultFiles) > len(request.ResultFiles) {
		return ErrProtocol
	}
	// A replay is terminally tombstoned by the registry.  All other runner
	// failures use PhaseFailed, so accepting only this explicit exception keeps
	// the lifecycle contract closed.
	if status.Phase == PhaseTombstone && status.Error != ErrorNone && status.Error != ErrorReplay {
		return ErrProtocol
	}
	allowed := make(map[string]struct{}, len(request.ResultFiles))
	for _, p := range request.ResultFiles {
		allowed[p] = struct{}{}
	}
	seen := make(map[string]struct{}, len(status.ResultFiles))
	for _, f := range status.ResultFiles {
		if _, ok := allowed[f.Path]; !ok || !safeRelativeSlash(f.Path) || f.Size < 0 || f.Size > MaxOutputBytes || !digestRE.MatchString(f.SHA256) {
			return ErrProtocol
		}
		if _, ok := seen[f.Path]; ok {
			return ErrProtocol
		}
		seen[f.Path] = struct{}{}
	}
	return nil
}
