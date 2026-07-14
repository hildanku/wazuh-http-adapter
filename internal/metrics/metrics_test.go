package metrics_test

import (
	"testing"

	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/hildanku/wazuh-http-adapter/internal/metrics"
)

// TestBucketOrdering verifies all histograms have strictly increasing buckets.
// This prevents the panic we hit in prod: "histogram buckets must be in increasing order".
func TestBucketOrdering(t *testing.T) {
	histograms := []prometheus.Collector{
		metrics.IngestLatency,
		metrics.DetectionLatency,
		metrics.PayloadSizeBytes,
	}

	for _, h := range histograms {
		mfs, err := testutil.GatherAndCount(prometheus.DefaultGatherer)
		if err != nil {
			t.Logf("gatherer warning: %v", err)
		}
		_ = mfs

		// Collect metric to trigger any registration panics
		ch := make(chan prometheus.Metric, 10)
		go func() {
			h.Collect(ch)
			close(ch)
		}()
		for m := range ch {
			var pb dto.Metric
			if err := m.Write(&pb); err != nil {
				t.Errorf("metric write error: %v", err)
			}
			if hist := pb.GetHistogram(); hist != nil {
				prev := -1.0
				for _, b := range hist.GetBucket() {
					upper := b.GetUpperBound()
					if upper <= prev {
						t.Errorf("bucket not strictly increasing: %v <= %v", upper, prev)
					}
					prev = upper
				}
			}
		}
	}
}

func TestCountersExist(t *testing.T) {
	// Ensure counters are registered and incrementable without panic
	metrics.EventsReceived.Add(1)
	metrics.EventsForwarded.Add(1)
	metrics.ForwardErrors.Add(1)
	metrics.ActiveConnections.Inc()
	metrics.ActiveConnections.Dec()
	metrics.AlertsTotal.WithLabelValues("1001", "test rule").Inc()
}
