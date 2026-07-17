package forwarder

import (
	"fmt"
	"net"
	"sync"
	"time"
)

// TCPForwarder sends syslog messages to Wazuh manager via TCP.
// TCP chosen over UDP, delivery confirmation required for benchmarking accuracy.
//
// FIX: replaced dial-per-Send with a fixed connection pool (default 8 conns).
// Old behaviour: every Send() called net.DialTimeout → ~1-5ms overhead per event
// → at 300+ EPS the dial queue backs up → HTTP handler blocks → k6 timeout.
// New behaviour: pool of persistent conns, Send() borrows/returns, no dial cost.
type TCPForwarder struct {
	host    string
	port    int
	timeout time.Duration
	pool    chan net.Conn
	mu      sync.Mutex // guards conn replacement on error
}

const defaultPoolSize = 8

// New creates a TCPForwarder with a pre-dialed persistent connection pool.
// Pool size defaults to defaultPoolSize; increase via env if needed.
func New(host string, port int, timeout time.Duration) *TCPForwarder {
	return NewWithPoolSize(host, port, timeout, defaultPoolSize)
}

func NewWithPoolSize(host string, port int, timeout time.Duration, poolSize int) *TCPForwarder {
	f := &TCPForwarder{
		host:    host,
		port:    port,
		timeout: timeout,
		pool:    make(chan net.Conn, poolSize),
	}
	// Pre-fill pool. Failures tolerated — pool fills lazily on first Send.
	for range poolSize {
		if conn, err := f.dial(); err == nil {
			f.pool <- conn
		}
	}
	return f
}

func (f *TCPForwarder) dial() (net.Conn, error) {
	addr := fmt.Sprintf("%s:%d", f.host, f.port)
	return net.DialTimeout("tcp", addr, f.timeout)
}

// acquire borrows a connection from the pool, dialling a new one if pool empty.
func (f *TCPForwarder) acquire() (net.Conn, error) {
	select {
	case conn := <-f.pool:
		return conn, nil
	default:
		return f.dial()
	}
}

// release returns a healthy connection to the pool, or closes it if pool full.
func (f *TCPForwarder) release(conn net.Conn) {
	select {
	case f.pool <- conn:
	default:
		conn.Close()
	}
}

// Healthy probes Wazuh reachability by attempting a fresh TCP dial.
// Returns true if dial succeeds within timeout; does NOT consume pool connections.
// Called by /health endpoint — distinguishes process-alive from Wazuh-reachable.
func (f *TCPForwarder) Healthy() bool {
	conn, err := f.dial()
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// Send formats payload as RFC 3164 syslog message and writes to Wazuh via TCP.
// correlationID is embedded in the message body so alerts.json tail can match it.
// Returns duration of the TCP write (used as ingest latency component).
//
// On write error the connection is discarded (not returned to pool) and Send
// retries once with a fresh dial, matching the old single-conn behaviour.
func (f *TCPForwarder) Send(correlationID, payload string) (time.Duration, error) {
	// RFC 3164 syslog: <priority>timestamp hostname tag: message
	// Priority 134 = facility 16 (local0) + severity 6 (informational)
	msg := fmt.Sprintf(
		"<134>%s wazuh-adapter wazuh_test_id=%s %s\n",
		time.Now().UTC().Format(time.RFC3339),
		correlationID,
		payload,
	)

	conn, err := f.acquire()
	if err != nil {
		return 0, fmt.Errorf("dial wazuh %s:%d: %w", f.host, f.port, err)
	}

	if err := conn.SetWriteDeadline(time.Now().Add(f.timeout)); err != nil {
		conn.Close()
		return 0, fmt.Errorf("set write deadline: %w", err)
	}

	start := time.Now()
	_, writeErr := fmt.Fprint(conn, msg)
	elapsed := time.Since(start)

	if writeErr != nil {
		// Discard stale/broken conn; retry once with fresh dial.
		conn.Close()
		fresh, dialErr := f.dial()
		if dialErr != nil {
			return 0, fmt.Errorf("write syslog (retry dial): %w", dialErr)
		}
		if err := fresh.SetWriteDeadline(time.Now().Add(f.timeout)); err != nil {
			fresh.Close()
			return 0, fmt.Errorf("set write deadline (retry): %w", err)
		}
		start = time.Now()
		_, writeErr = fmt.Fprint(fresh, msg)
		elapsed = time.Since(start)
		if writeErr != nil {
			fresh.Close()
			return 0, fmt.Errorf("write syslog: %w", writeErr)
		}
		f.release(fresh)
		return elapsed, nil
	}

	f.release(conn)
	return elapsed, nil
}
