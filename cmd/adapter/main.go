package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/hildanku/wazuh-http-adapter/internal/forwarder"
	"github.com/hildanku/wazuh-http-adapter/internal/handler"
	"github.com/hildanku/wazuh-http-adapter/internal/tailer"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type config struct {
	AdapterPort     string
	MetricsPort     string
	WazuhHost       string
	WazuhSyslogPort int
	ForwardTimeout  time.Duration
	AlertsLogPath   string
	TailerPollMs    int
}

func loadConfig() config {
	wazuhPort, err := strconv.Atoi(getEnv("WAZUH_SYSLOG_PORT", "514"))
	if err != nil {
		slog.Error("invalid WAZUH_SYSLOG_PORT, using 514")
		wazuhPort = 514
	}

	timeoutSec, err := strconv.Atoi(getEnv("FORWARD_TIMEOUT_SEC", "5"))
	if err != nil {
		timeoutSec = 5
	}

	tailerPollMs, err := strconv.Atoi(getEnv("TAILER_POLL_MS", "100"))
	if err != nil {
		tailerPollMs = 500
	}

	return config{
		AdapterPort:     getEnv("ADAPTER_PORT", "8080"),
		MetricsPort:     getEnv("METRICS_PORT", "9090"),
		WazuhHost:       getEnv("WAZUH_HOST", "localhost"),
		WazuhSyslogPort: wazuhPort,
		ForwardTimeout:  time.Duration(timeoutSec) * time.Second,
		AlertsLogPath:   getEnv("ALERTS_LOG_PATH", "/var/ossec/logs/alerts/alerts.json"),
		TailerPollMs:    tailerPollMs,
	}
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	cfg := loadConfig()

	slog.Info("starting wazuh-http-adapter",
		"adapter_port", cfg.AdapterPort,
		"metrics_port", cfg.MetricsPort,
		"wazuh_host", cfg.WazuhHost,
		"wazuh_syslog_port", cfg.WazuhSyslogPort,
	)

	fwd := forwarder.New(cfg.WazuhHost, cfg.WazuhSyslogPort, cfg.ForwardTimeout)
	h := handler.NewEventHandler(fwd)

	// Main API server - matches Xemarify's route for k6 compatibility
	apiMux := http.NewServeMux()
	apiMux.HandleFunc("POST /api/v1/events", h.HandleIngest)
	apiMux.HandleFunc("GET /health", h.HandleHealth)

	apiServer := &http.Server{
		Addr:         ":" + cfg.AdapterPort,
		Handler:      apiMux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Separate metrics server - keeps /metrics off the main benchmark path
	metricsMux := http.NewServeMux()
	metricsMux.Handle("/metrics", promhttp.Handler())

	metricsServer := &http.Server{
		Addr:    ":" + cfg.MetricsPort,
		Handler: metricsMux,
	}

	// Start alerts.json tailer - counts alerts per run for per-run granularity (Opsi B)
	done := make(chan struct{})
	t := tailer.New(cfg.AlertsLogPath, time.Duration(cfg.TailerPollMs)*time.Millisecond)
	go t.Run(done)

	// Start both servers
	go func() {
		slog.Info("api server listening", "port", cfg.AdapterPort)
		if err := apiServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("api server error", "err", err)
			os.Exit(1)
		}
	}()

	go func() {
		slog.Info("metrics server listening", "port", cfg.MetricsPort)
		if err := metricsServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("metrics server error", "err", err)
		}
	}()

	// Graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	slog.Info("shutting down...")
	close(done) // signal tailer to stop
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := apiServer.Shutdown(ctx); err != nil {
		slog.Error("api server shutdown error", "err", err)
	}
	if err := metricsServer.Shutdown(ctx); err != nil {
		slog.Error("metrics server shutdown error", "err", err)
	}

	slog.Info("adapter stopped")
}
