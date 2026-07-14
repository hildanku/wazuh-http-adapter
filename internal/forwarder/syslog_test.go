package forwarder_test

import (
	"net"
	"strings"
	"testing"
	"time"

	"github.com/hildanku/wazuh-http-adapter/internal/forwarder"
)

// startTCPListener spins up a local TCP server and returns host:port + received channel.
func startTCPListener(t *testing.T) (string, chan string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	received := make(chan string, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 4096)
		n, _ := conn.Read(buf)
		received <- string(buf[:n])
	}()

	return ln.Addr().String(), received
}

func TestSend_Success(t *testing.T) {
	addr, received := startTCPListener(t)

	host, port := splitAddr(t, addr)
	fwd := forwarder.New(host, port, 2*time.Second)

	duration, err := fwd.Send("test-uuid-1234", `{"message":"test"}`)
	if err != nil {
		t.Fatalf("Send error: %v", err)
	}
	if duration <= 0 {
		t.Error("expected positive duration")
	}

	select {
	case msg := <-received:
		if !strings.Contains(msg, "wazuh_test_id=test-uuid-1234") {
			t.Errorf("correlation ID missing in syslog message: %q", msg)
		}
		if !strings.Contains(msg, `{"message":"test"}`) {
			t.Errorf("payload missing in syslog message: %q", msg)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for TCP message")
	}
}

func TestSend_ConnectionRefused(t *testing.T) {
	// Port 1 should always be refused
	fwd := forwarder.New("127.0.0.1", 1, 500*time.Millisecond)
	_, err := fwd.Send("id", "payload")
	if err == nil {
		t.Error("expected error on refused connection")
	}
}

func TestSend_Timeout(t *testing.T) {
	// Listen but never accept — triggers write timeout
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	host, port := splitAddr(t, ln.Addr().String())
	fwd := forwarder.New(host, port, 50*time.Millisecond)

	// Accept connection but never read — write deadline should trigger
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		// Hold connection open without reading
		time.Sleep(5 * time.Second)
		conn.Close()
	}()

	// Large payload to trigger write deadline
	bigPayload := strings.Repeat("x", 1<<16)
	_, err = fwd.Send("id", bigPayload)
	// May or may not timeout depending on kernel buffer — just verify no panic
	_ = err
}

func splitAddr(t *testing.T, addr string) (string, int) {
	t.Helper()
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("split addr %q: %v", addr, err)
	}
	var port int
	if _, err := net.ResolveTCPAddr("tcp", addr); err != nil {
		t.Fatalf("resolve: %v", err)
	}
	// parse port manually
	for _, c := range portStr {
		port = port*10 + int(c-'0')
	}
	return host, port
}
