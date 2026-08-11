//go:build linux

package extensionrunner

import (
	"context"
	"errors"
	"net"
	"os"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestServeV2ExecutionCapacityMatchesThreeSlotContainerBudget(t *testing.T) {
	const containerMemoryBytes = 1 << 30
	if serverMaxExecutions != 3 {
		t.Fatalf("execution slots=%d, want 3", serverMaxExecutions)
	}
	if serverMaxExecutions*serverMaxExecutionMemoryBytes >= containerMemoryBytes {
		t.Fatalf("execution memory budget leaves no runner headroom in 1 GiB: slots=%d per_slot=%d", serverMaxExecutions, serverMaxExecutionMemoryBytes)
	}
}

func TestServeV2AllowsThirdExecutionSlot(t *testing.T) {
	request := sandboxRequest()
	packet, err := EncodeRequestV2(request)
	if err != nil {
		t.Fatal(err)
	}
	clientFD, serverConn := serverSocketpair(t)
	defer unix.Close(clientFD)
	if _, err = unix.SendmsgN(clientFD, packet, nil, nil, 0); err != nil {
		t.Fatal(err)
	}
	slots := make(chan struct{}, serverMaxExecutions)
	for i := 0; i < serverMaxExecutions-1; i++ {
		slots <- struct{}{}
	}
	done := make(chan struct{})
	go func() {
		(Server{Authorizer: UIDAllowlist{uint32(os.Geteuid()): {}}, Registry: NewRunRegistry()}).serveV2Connection(context.Background(), serverConn, slots)
		close(done)
	}()
	buf := make([]byte, MaxV2PacketBytes)
	n, err := unix.Read(clientFD, buf)
	if err != nil {
		t.Fatal(err)
	}
	status, err := ReadStatusV1Datagram(buf[:n])
	if err != nil {
		t.Fatal(err)
	}
	if status.RunID != request.RunID || status.Phase != PhaseFailed || status.Error != ErrorUnavailableBackend || status.Status != "" {
		t.Fatalf("third execution slot was rejected: %+v", status)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("third-slot request did not release connection")
	}
}

func TestServeV2RejectsExecutionAboveCapacity(t *testing.T) {
	request := sandboxRequest()
	packet, err := EncodeRequestV2(request)
	if err != nil {
		t.Fatal(err)
	}
	clientFD, serverConn := serverSocketpair(t)
	defer unix.Close(clientFD)
	if _, err := unix.SendmsgN(clientFD, packet, nil, nil, 0); err != nil {
		t.Fatal(err)
	}
	slots := make(chan struct{}, serverMaxExecutions)
	for i := 0; i < cap(slots); i++ {
		slots <- struct{}{}
	}
	done := make(chan struct{})
	go func() {
		(Server{Authorizer: UIDAllowlist{uint32(os.Geteuid()): {}}, Registry: NewRunRegistry()}).serveV2Connection(context.Background(), serverConn, slots)
		close(done)
	}()
	buf := make([]byte, MaxV2PacketBytes)
	n, err := unix.Read(clientFD, buf)
	if err != nil {
		t.Fatal(err)
	}
	status, err := ReadStatusV1Datagram(buf[:n])
	if err != nil {
		t.Fatal(err)
	}
	if status.RunID != request.RunID || status.Phase != PhaseFailed || status.Error != ErrorUnavailableBackend || status.Status != "capacity" {
		t.Fatalf("capacity status=%+v", status)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("capacity rejection did not release connection")
	}
}

func TestServeV2RejectsLimitsAboveProductionContainerBudget(t *testing.T) {
	request := sandboxRequest()
	request.Limits.MemoryBytes = serverMaxExecutionMemoryBytes + 1
	packet, err := EncodeRequestV2(request)
	if err != nil {
		t.Fatal(err)
	}
	clientFD, serverConn := serverSocketpair(t)
	defer unix.Close(clientFD)
	if _, err := unix.SendmsgN(clientFD, packet, nil, nil, 0); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		(Server{Authorizer: UIDAllowlist{uint32(os.Geteuid()): {}}, Registry: NewRunRegistry()}).serveV2Connection(context.Background(), serverConn, make(chan struct{}, serverMaxExecutions))
		close(done)
	}()
	buf := make([]byte, MaxV2PacketBytes)
	n, err := unix.Read(clientFD, buf)
	if err != nil {
		t.Fatal(err)
	}
	status, err := ReadStatusV1Datagram(buf[:n])
	if err != nil {
		t.Fatal(err)
	}
	if status.RunID != request.RunID || status.Phase != PhaseFailed || status.Error != ErrorInvalidRequest || status.Status != "limits" {
		t.Fatalf("limit status=%+v", status)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("limit rejection did not release connection")
	}
}

func TestServeV2SlowConsumerCannotHoldConnection(t *testing.T) {
	sockets, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, 0)
	if err != nil {
		t.Fatal(err)
	}
	clientFD, serverFD := sockets[0], sockets[1]
	defer unix.Close(clientFD)
	fill := make([]byte, 1024)
	queued := 0
	for {
		if _, err := unix.SendmsgN(serverFD, fill, nil, nil, unix.MSG_DONTWAIT); err != nil {
			if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EWOULDBLOCK) {
				break
			}
			unix.Close(serverFD)
			t.Fatal(err)
		}
		queued++
	}
	if queued == 0 {
		unix.Close(serverFD)
		t.Fatal("failed to fill server send queue")
	}
	request, err := EncodeProbeRequest(ProbeRequest{Op: "probe", Version: ProbeProtocolV1, Nonce: "slow-consumer"})
	if err != nil {
		unix.Close(serverFD)
		t.Fatal(err)
	}
	if _, err := unix.SendmsgN(clientFD, request, nil, nil, 0); err != nil {
		unix.Close(serverFD)
		t.Fatal(err)
	}
	serverConn := unixConnForTest(t, serverFD)
	done := make(chan struct{})
	started := time.Now()
	go func() {
		(Server{Authorizer: UIDAllowlist{uint32(os.Geteuid()): {}}, RunnerUID: uint32(os.Geteuid()), Registry: NewRunRegistry()}).serveV2Connection(context.Background(), serverConn, make(chan struct{}, serverMaxExecutions))
		close(done)
	}()
	select {
	case <-done:
		if elapsed := time.Since(started); elapsed > serverSocketWriteTimeout+time.Second {
			t.Fatalf("slow consumer held connection for %v", elapsed)
		}
	case <-time.After(serverSocketWriteTimeout + time.Second):
		t.Fatal("slow consumer held server goroutine past write deadline")
	}
}

func serverSocketpair(t *testing.T) (int, *net.UnixConn) {
	t.Helper()
	sockets, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	return sockets[0], unixConnForTest(t, sockets[1])
}

func unixConnForTest(t *testing.T, fd int) *net.UnixConn {
	t.Helper()
	file := os.NewFile(uintptr(fd), "extension-runner-test")
	conn, err := net.FileConn(file)
	_ = file.Close()
	if err != nil {
		t.Fatal(err)
	}
	return conn.(*net.UnixConn)
}
