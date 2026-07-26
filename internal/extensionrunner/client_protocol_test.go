package extensionrunner

import (
	"context"
	"fmt"
	"testing"
)

func clientProtocolRequest() RequestV2 {
	return RequestV2{RunID: "11111111-1111-4111-8111-111111111111", TaskID: "22222222-2222-4222-8222-222222222222", TaskFence: "33333333-3333-4333-8333-333333333333", InstallDigest: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Entry: "entry", TimeoutMS: 100, Limits: LimitsV2{CPUSeconds: 1, MemoryBytes: 1, Processes: 1, FileBytes: 1, OpenFiles: 1}}
}

// sandboxRequest is the canonical valid request used by Linux boundary tests.
func sandboxRequest() RequestV2 {
	return clientProtocolRequest()
}

func TestReadStatusV1DatagramRejectsNonCanonicalAndMismatchedStatus(t *testing.T) {
	request := clientProtocolRequest()
	payload, err := EncodeStatusV1(StatusV1{RunID: request.RunID, Phase: PhaseTombstone})
	if err != nil {
		t.Fatal(err)
	}
	status, err := ReadStatusV1Datagram(payload)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateStatusV1(request, status); err != nil {
		t.Fatal(err)
	}
	status.RunID = "44444444-4444-4444-8444-444444444444"
	if err := ValidateStatusV1(request, status); err == nil {
		t.Fatal("mismatched run id accepted")
	}
	if _, err := ReadStatusV1Datagram(append(payload, 'x')); err == nil {
		t.Fatal("extra response bytes accepted")
	}
}

func TestProbeProtocolBindsNonceAndVersion(t *testing.T) {
	request, err := EncodeProbeRequest(ProbeRequest{Op: "probe", Version: ProbeProtocolV1, Nonce: "nonce"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeProbeRequest(request); err != nil {
		t.Fatal(err)
	}
	response, err := EncodeProbeResponse(ProbeResponse{Ready: true, Version: ProbeProtocolV1, Nonce: "nonce"})
	if err != nil {
		t.Fatal(err)
	}
	if err := DecodeProbeResponse(response, "nonce"); err != nil {
		t.Fatal(err)
	}
	if err := DecodeProbeResponse(response, "wrong"); err == nil {
		t.Fatal("probe accepted a mismatched nonce")
	}
	if _, err := DecodeProbeRequest([]byte(`{"op":"probe","version":"wrong","nonce":"nonce"}`)); err == nil {
		t.Fatal("probe accepted a mismatched version")
	}
}

func TestValidateStatusV1AcceptsReplayTombstoneOnly(t *testing.T) {
	request := clientProtocolRequest()
	if err := ValidateStatusV1(request, StatusV1{RunID: request.RunID, Phase: PhaseTombstone, Error: ErrorReplay}); err != nil {
		t.Fatal(err)
	}
	if err := ValidateStatusV1(request, StatusV1{RunID: request.RunID, Phase: PhaseTombstone, Error: ErrorExecution}); err == nil {
		t.Fatal("non-replay tombstone accepted")
	}
}

func TestV2WirePacketBoundRejectsOversizeStatus(t *testing.T) {
	request := clientProtocolRequest()
	if _, err := EncodeStatusV1(StatusV1{RunID: request.RunID, Phase: PhaseTombstone, Stdout: make([]byte, MaxV2PacketBytes)}); err == nil {
		t.Fatal("oversize packet accepted")
	}
}

func TestFitStatusV1PacketMakesTerminalStatusSendable(t *testing.T) {
	request := clientProtocolRequest()
	status := fitStatusV1Packet(StatusV1{RunID: request.RunID, Phase: PhaseFailed, Error: ErrorTimeout, Stdout: make([]byte, MaxOutputBytes), Stderr: make([]byte, MaxOutputBytes)})
	payload, err := EncodeStatusV1(status)
	if err != nil || len(payload) > MaxV2PacketBytes {
		t.Fatalf("status remains unsendable: len=%d err=%v", len(payload), err)
	}
	if err := ValidateStatusV1(request, status); err != nil {
		t.Fatal(err)
	}
}

func TestRunnerRejectsSixHundredResultFilesBeforeExecution(t *testing.T) {
	request := clientProtocolRequest()
	request.ResultFiles = make([]string, 600)
	for i := range request.ResultFiles {
		request.ResultFiles[i] = fmt.Sprintf("result-%03d", i)
	}
	status, err := (Runner{}).RunV2(context.Background(), request, nil, NewRunRegistry())
	if err == nil || status.Error != ErrorInvalidRequest {
		t.Fatalf("oversize result registration reached execution: status=%+v err=%v", status, err)
	}
}
