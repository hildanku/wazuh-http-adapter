package forwarder

import (
	"fmt"
	"net"
	"time"
)

// TCPForwarder sends syslog messages to Wazuh manager via TCP.
// TCP chosen over UDP, delivery confirmation required for benchmarking accuracy.
type TCPForwarder struct {
	host    string
	port    int
	timeout time.Duration
}

func New(host string, port int, timeout time.Duration) *TCPForwarder {
	return &TCPForwarder{
		host:    host,
		port:    port,
		timeout: timeout,
	}
}

// Send formats payload as RFC 3164 syslog message and writes to Wazuh via TCP.
// correlationID is embedded in the message body so alerts.json tail can match it.
// Returns duration of the TCP write (used as ingest latency component).
func (f *TCPForwarder) Send(correlationID, payload string) (time.Duration, error) {
	addr := fmt.Sprintf("%s:%d", f.host, f.port)

	conn, err := net.DialTimeout("tcp", addr, f.timeout)
	if err != nil {
		return 0, fmt.Errorf("dial wazuh %s: %w", addr, err)
	}
	defer conn.Close()

	if err := conn.SetWriteDeadline(time.Now().Add(f.timeout)); err != nil {
		return 0, fmt.Errorf("set write deadline: %w", err)
	}

	// RFC 3164 syslog: <priority>timestamp hostname tag: message
	// Priority 134 = facility 16 (local0) + severity 6 (informational)
	msg := fmt.Sprintf(
		"<134>%s wazuh-adapter wazuh_test_id=%s %s\n",
		time.Now().UTC().Format(time.RFC3339),
		correlationID,
		payload,
	)

	start := time.Now()
	_, err = fmt.Fprint(conn, msg)
	elapsed := time.Since(start)

	if err != nil {
		return 0, fmt.Errorf("write syslog: %w", err)
	}

	return elapsed, nil
}
