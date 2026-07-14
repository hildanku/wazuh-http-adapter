package handler

import (
	"encoding/json"
	"io"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/hildanku/wazuh-http-adapter/internal/forwarder"
	"github.com/hildanku/wazuh-http-adapter/internal/metrics"
)

// EventRequest mirrors Xemarify's POST /api/v1/events payload so k6
// scripts require zero modification when targeting Wazuh via this adapter.
type EventRequest struct {
	Events []map[string]any `json:"events"`
}

type EventResponse struct {
	Received      int    `json:"received"`
	CorrelationID string `json:"correlation_id"`
}

type EventHandler struct {
	fwd *forwarder.TCPForwarder
}

func NewEventHandler(fwd *forwarder.TCPForwarder) *EventHandler {
	return &EventHandler{fwd: fwd}
}

func (h *EventHandler) HandleIngest(w http.ResponseWriter, r *http.Request) {
	receivedAt := time.Now()

	metrics.ActiveConnections.Inc()
	defer metrics.ActiveConnections.Dec()

	// Read and measure payload size
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20)) // 1 MB limit
	if err != nil {
		http.Error(w, "failed to read body", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	metrics.PayloadSizeBytes.Observe(float64(len(body)))
	metrics.EventsReceived.Add(1)

	var req EventRequest
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}

	// One correlation ID per HTTP request (not per event), sufficient for detection latency matching in alerts.json tail.
	correlationID := uuid.New().String()

	// Re-encode events as JSON string for syslog body
	eventsJSON, err := json.Marshal(req.Events)
	if err != nil {
		http.Error(w, "failed to marshal events", http.StatusInternalServerError)
		return
	}

	// Forward to Wazuh, this duration is the adapter ingest latency component.
	forwardDuration, err := h.fwd.Send(correlationID, string(eventsJSON))
	if err != nil {
		metrics.ForwardErrors.Add(1)
		http.Error(w, "failed to forward to wazuh", http.StatusBadGateway)
		return
	}

	metrics.EventsForwarded.Add(1)
	metrics.IngestLatency.Observe(forwardDuration.Seconds())

	// Total round-trip from HTTP receive to TCP send, useful for baseline subtraction.
	_ = time.Since(receivedAt)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted) // 202 matches Xemarify's response
	json.NewEncoder(w).Encode(EventResponse{
		Received:      len(req.Events),
		CorrelationID: correlationID,
	})
}

// HandleHealth is a liveness probe endpoint.
func (h *EventHandler) HandleHealth(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"ok"}`))
}
