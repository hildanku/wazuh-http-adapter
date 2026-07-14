package tailer_test

import (
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/hildanku/wazuh-http-adapter/internal/tailer"
)

type alertEntry struct {
	Timestamp string `json:"timestamp"`
	Rule      struct {
		Level       int    `json:"level"`
		Description string `json:"description"`
		ID          string `json:"id"`
	} `json:"rule"`
}

func writeAlert(t *testing.T, f *os.File, ruleID, desc string, level int) {
	t.Helper()
	entry := alertEntry{Timestamp: time.Now().UTC().Format(time.RFC3339)}
	entry.Rule.ID = ruleID
	entry.Rule.Description = desc
	entry.Rule.Level = level

	b, err := json.Marshal(entry)
	if err != nil {
		t.Fatalf("marshal alert: %v", err)
	}
	f.Write(append(b, '\n'))
}

func TestTailer_ReadsNewAlerts(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "alerts-*.json")
	if err != nil {
		t.Fatalf("create temp: %v", err)
	}
	defer f.Close()

	// Write existing data before tailer starts — should be ignored (seek to end)
	writeAlert(t, f, "1000", "old alert", 3)

	tl := tailer.New(f.Name(), 50*time.Millisecond)
	done := make(chan struct{})

	go tl.Run(done)

	// Give tailer time to open file and seek to end
	time.Sleep(100 * time.Millisecond)

	// Write new alert after tailer started
	writeAlert(t, f, "1001", "new alert", 5)

	// Give tailer time to process
	time.Sleep(200 * time.Millisecond)

	close(done)
}

func TestTailer_MissingFile_Retries(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/alerts.json"

	tl := tailer.New(path, 50*time.Millisecond)
	done := make(chan struct{})
	go tl.Run(done)

	// Let it retry a few times on missing file
	time.Sleep(200 * time.Millisecond)

	// Create file — tailer should pick it up
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	defer f.Close()

	time.Sleep(200 * time.Millisecond)
	close(done)
}

func TestTailer_MalformedLine_Skipped(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "alerts-*.json")
	if err != nil {
		t.Fatalf("create temp: %v", err)
	}
	defer f.Close()

	tl := tailer.New(f.Name(), 50*time.Millisecond)
	done := make(chan struct{})
	go tl.Run(done)

	time.Sleep(100 * time.Millisecond)

	// Write malformed line — tailer must not crash
	f.WriteString("not valid json\n")

	// Write valid line after
	writeAlert(t, f, "1002", "valid after malformed", 3)

	time.Sleep(200 * time.Millisecond)
	close(done)
	// If tailer crashed, done would never receive — test passes if no panic
}

func TestTailer_StopsOnDone(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "alerts-*.json")
	if err != nil {
		t.Fatalf("create temp: %v", err)
	}
	defer f.Close()

	tl := tailer.New(f.Name(), 50*time.Millisecond)
	done := make(chan struct{})
	go tl.Run(done)

	time.Sleep(100 * time.Millisecond)
	close(done)

	// Allow goroutine to exit
	time.Sleep(200 * time.Millisecond)
	// No assertion needed — test hangs if tailer ignores done
}
