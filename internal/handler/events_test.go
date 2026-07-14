package handler_test

import (
	"bytes"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/hildanku/wazuh-http-adapter/internal/forwarder"
	"github.com/hildanku/wazuh-http-adapter/internal/handler"
)

// startTCPSink starts a TCP listener that accepts and discards data.
func startTCPSink(t *testing.T) (string, int) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				buf := make([]byte, 4096)
				for {
					_, err := c.Read(buf)
					if err != nil {
						return
					}
				}
			}(conn)
		}
	}()

	host, portStr, _ := net.SplitHostPort(ln.Addr().String())
	var port int
	for _, c := range portStr {
		port = port*10 + int(c-'0')
	}
	return host, port
}

func newHandler(t *testing.T) *handler.EventHandler {
	t.Helper()
	host, port := startTCPSink(t)
	fwd := forwarder.New(host, port, 2*time.Second)
	return handler.NewEventHandler(fwd)
}

func TestHandleIngest_ValidPayload(t *testing.T) {
	h := newHandler(t)

	body := `{"events":[{"message":"test event","level":"info"}]}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/events", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.HandleIngest(w, req)

	if w.Code != http.StatusAccepted {
		t.Errorf("expected 202, got %d", w.Code)
	}

	var resp map[string]any
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp["correlation_id"] == "" {
		t.Error("expected correlation_id in response")
	}
	if received, ok := resp["received"].(float64); !ok || received != 1 {
		t.Errorf("expected received=1, got %v", resp["received"])
	}
}

func TestHandleIngest_InvalidJSON(t *testing.T) {
	h := newHandler(t)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/events", bytes.NewBufferString(`not json`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.HandleIngest(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestHandleIngest_EmptyEvents(t *testing.T) {
	h := newHandler(t)

	body := `{"events":[]}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/events", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.HandleIngest(w, req)

	if w.Code != http.StatusAccepted {
		t.Errorf("expected 202, got %d", w.Code)
	}
}

func TestHandleHealth(t *testing.T) {
	h := newHandler(t)

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()

	h.HandleHealth(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestHandleIngest_WazuhDown(t *testing.T) {
	// Port 1 always refused — simulates Wazuh down
	fwd := forwarder.New("127.0.0.1", 1, 500*time.Millisecond)
	h := handler.NewEventHandler(fwd)

	body := `{"events":[{"message":"test"}]}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/events", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.HandleIngest(w, req)

	if w.Code != http.StatusBadGateway {
		t.Errorf("expected 502, got %d", w.Code)
	}
}
