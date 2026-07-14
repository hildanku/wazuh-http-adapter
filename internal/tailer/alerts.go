package tailer

import (
	"bufio"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"time"

	"github.com/hildanku/wazuh-http-adapter/internal/metrics"
)

// AlertEntry is a minimal parse of a single alerts.json line.
// Wazuh writes one JSON object per line (NDJSON format).
type AlertEntry struct {
	Timestamp string `json:"timestamp"`
	Rule      struct {
		Level       int    `json:"level"`
		Description string `json:"description"`
		ID          string `json:"id"`
	} `json:"rule"`
}

// AlertsTailer tails alerts.json and increments Prometheus counter per alert.
// alert rate granularity per-run, no correlation ID needed.
type AlertsTailer struct {
	path         string
	pollInterval time.Duration
}

func New(path string, pollInterval time.Duration) *AlertsTailer {
	return &AlertsTailer{
		path:         path,
		pollInterval: pollInterval,
	}
}

// Run starts tailing alerts.json. Blocks until ctx-equivalent done channel closes.
// Seeks to end of file on star, only counts alerts generated during benchmark run.
func (t *AlertsTailer) Run(done <-chan struct{}) {
	slog.Info("alerts tailer starting", "path", t.path)

	for {
		err := t.tail(done)
		if err == nil {
			return // done channel closed
		}

		// File missing or unreadable, Wazuh may not have started yet
		slog.Warn("alerts tailer error, retrying", "err", err, "retry_in", t.pollInterval)

		select {
		case <-done:
			return
		case <-time.After(t.pollInterval):
		}
	}
}

func (t *AlertsTailer) tail(done <-chan struct{}) error {
	f, err := os.Open(t.path)
	if err != nil {
		return err
	}
	defer f.Close()

	// Seek to end, ignore historical alerts, only count new ones during run
	if _, err := f.Seek(0, io.SeekEnd); err != nil {
		return err
	}

	reader := bufio.NewReader(f)

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			if err != io.EOF {
				return err
			}

			// EOF, no new data yet, poll
			select {
			case <-done:
				return nil
			case <-time.After(t.pollInterval):
				continue
			}
		}

		if line == "" || line == "\n" {
			continue
		}

		var entry AlertEntry
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			// Partial line or malformed, skip, Wazuh sometimes writes incomplete lines mid-flush
			slog.Debug("tailer skip malformed line", "err", err)
			continue
		}

		// Increment per-rule-level counter
		metrics.AlertsTotal.WithLabelValues(entry.Rule.ID, entry.Rule.Description).Inc()

		slog.Debug("alert observed",
			"rule_id", entry.Rule.ID,
			"level", entry.Rule.Level,
			"desc", entry.Rule.Description,
		)
	}
}
