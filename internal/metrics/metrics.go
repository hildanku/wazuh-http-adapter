package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	EventsReceived = promauto.NewCounter(prometheus.CounterOpts{
		Name: "wazuh_adapter_events_received_total",
		Help: "Total events received by adapter via HTTP.",
	})

	EventsForwarded = promauto.NewCounter(prometheus.CounterOpts{
		Name: "wazuh_adapter_events_forwarded_total",
		Help: "Total events successfully forwarded to Wazuh via TCP syslog.",
	})

	ForwardErrors = promauto.NewCounter(prometheus.CounterOpts{
		Name: "wazuh_adapter_forward_error_total",
		Help: "Total events that failed to forward to Wazuh.",
	})

	// IngestLatency measures time from HTTP receive to TCP send completion.
	// This is the adapter overhead component; subtract baseline to get Wazuh-only latency.
	IngestLatency = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "wazuh_adapter_ingest_latency_seconds",
		Help:    "Latency from HTTP receive to TCP syslog send (adapter overhead).",
		Buckets: prometheus.DefBuckets,
	})

	// DetectionLatency measures time from HTTP receive to alert appearing in alerts.json.
	// Requires correlation ID matching via alerts.json tail.
	DetectionLatency = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "wazuh_adapter_detection_latency_seconds",
		Help:    "Latency from HTTP receive to Wazuh alert detection (end-to-end).",
		Buckets: []float64{.005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10, 30, 60},
	})

	PayloadSizeBytes = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "wazuh_adapter_payload_size_bytes",
		Help:    "Size of incoming event payloads in bytes.",
		Buckets: prometheus.ExponentialBuckets(64, 2, 10),
	})

	ActiveConnections = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "wazuh_adapter_active_connections",
		Help: "Current number of active HTTP connections.",
	})

	// AlertsTotal counts alerts observed in alerts.json per rule.
	// per-run alert rate granularity, replaces hourly /manager/stats bucket.
	AlertsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "wazuh_adapter_alerts_total",
		Help: "Total alerts observed in alerts.json, labeled by rule_id and description.",
	}, []string{"rule_id", "description"})

	// PoolHealthy reflects whether TCP forwarder can reach Wazuh.
	// 1 = healthy (probe succeeded), 0 = unhealthy (probe failed).
	// Used by /health readiness check — runner waits until this is 1.
	PoolHealthy = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "wazuh_adapter_pool_healthy",
		Help: "1 if TCP forwarder can reach Wazuh syslog port, 0 otherwise.",
	})
)
