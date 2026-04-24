// Package telemetry provides observability via structured logging, metrics, and tracing.
//
// Features:
// - Structured JSON logging via log/slog
// - Prometheus metrics on /metrics
// - OpenTelemetry spans
// - SIGIL_TELEMETRY=none disables all telemetry
package telemetry

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.21.0"
	"go.opentelemetry.io/otel/trace"
)

// Config holds telemetry configuration.
type Config struct {
	ServiceName string
	Enabled     bool
	LogWriter   io.Writer // For testing, defaults to os.Stdout
}

// Telemetry manages observability across logging, metrics, and tracing.
type Telemetry struct {
	enabled    bool
	logger     *slog.Logger
	tracer     trace.Tracer
	registry   *prometheus.Registry
	tracerShutdown func(context.Context) error

	// Prometheus metrics
	challengesCreated  *prometheus.CounterVec
	challengesVerified *prometheus.CounterVec
	mpaRequests        *prometheus.CounterVec
	challengeVerifyDuration prometheus.Histogram
	mpaRequestDuration prometheus.Histogram
}

// New creates a new telemetry instance.
//
// Reads SIGIL_TELEMETRY environment variable:
// - "none" = disabled
// - anything else or unset = enabled
func New(config Config) *Telemetry {
	enabled := config.Enabled
	if os.Getenv("SIGIL_TELEMETRY") == "none" {
		enabled = false
	}

	if !enabled {
		return &Telemetry{
			enabled: false,
			logger:  slog.New(slog.NewJSONHandler(io.Discard, nil)),
			tracer:  otel.Tracer("noop"),
			registry: prometheus.NewRegistry(),
		}
	}

	// Setup structured logging
	logWriter := config.LogWriter
	if logWriter == nil {
		logWriter = os.Stdout
	}

	logger := slog.New(slog.NewJSONHandler(logWriter, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	// Setup Prometheus metrics
	registry := prometheus.NewRegistry()

	challengesCreated := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "sigil_challenges_created_total",
			Help: "Total number of challenges created",
		},
		[]string{"action_type"},
	)

	challengesVerified := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "sigil_challenges_verified_total",
			Help: "Total number of challenges verified",
		},
		[]string{"action_type", "result"},
	)

	mpaRequests := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "sigil_mpa_requests_total",
			Help: "Total number of MPA requests",
		},
		[]string{"action_type"},
	)

	challengeVerifyDuration := prometheus.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "sigil_challenge_verify_duration_ms",
			Help:    "Duration of challenge verification in milliseconds",
			Buckets: prometheus.ExponentialBuckets(1, 2, 10), // 1ms to 512ms
		},
	)

	mpaRequestDuration := prometheus.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "sigil_mpa_request_duration_ms",
			Help:    "Duration of MPA request processing in milliseconds",
			Buckets: prometheus.ExponentialBuckets(10, 2, 10), // 10ms to 5s
		},
	)

	registry.MustRegister(challengesCreated)
	registry.MustRegister(challengesVerified)
	registry.MustRegister(mpaRequests)
	registry.MustRegister(challengeVerifyDuration)
	registry.MustRegister(mpaRequestDuration)

	// Setup OpenTelemetry tracer with configurable OTLP exporter
	shutdown, err := initTracer(config.ServiceName)
	if err != nil {
		logger.Warn("Failed to initialize tracer, continuing without tracing", "error", err)
		shutdown = func(context.Context) error { return nil }
	}

	tracer := otel.Tracer(config.ServiceName)

	return &Telemetry{
		enabled:                enabled,
		logger:                 logger,
		tracer:                 tracer,
		registry:               registry,
		tracerShutdown:         shutdown,
		challengesCreated:      challengesCreated,
		challengesVerified:     challengesVerified,
		mpaRequests:            mpaRequests,
		challengeVerifyDuration: challengeVerifyDuration,
		mpaRequestDuration:     mpaRequestDuration,
	}
}

// Shutdown gracefully shuts down the telemetry, flushing any pending traces.
func (t *Telemetry) Shutdown(ctx context.Context) error {
	if t.tracerShutdown != nil {
		return t.tracerShutdown(ctx)
	}
	return nil
}

// initTracer initializes the OpenTelemetry trace provider with configurable OTLP exporter.
//
// Reads standard OTel environment variables:
// - OTEL_EXPORTER_OTLP_ENDPOINT: OTLP endpoint (e.g., "localhost:4317" for gRPC, "http://localhost:4318" for HTTP)
// - OTEL_EXPORTER_OTLP_PROTOCOL: grpc or http/protobuf (default: grpc)
// - OTEL_SERVICE_NAME: service name (default: serviceName parameter)
// - OTEL_RESOURCE_ATTRIBUTES: comma-separated key=value pairs
//
// If OTEL_EXPORTER_OTLP_ENDPOINT is unset, returns a no-op shutdown function.
// If endpoint is unreachable, logs a warning and returns a no-op shutdown function.
func initTracer(serviceName string) (func(context.Context) error, error) {
	endpoint := os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT")
	if endpoint == "" {
		slog.Info("OTEL_EXPORTER_OTLP_ENDPOINT not set, tracing disabled")
		return func(context.Context) error { return nil }, nil
	}

	protocol := os.Getenv("OTEL_EXPORTER_OTLP_PROTOCOL")
	if protocol == "" {
		protocol = "grpc"
	}

	otelServiceName := os.Getenv("OTEL_SERVICE_NAME")
	if otelServiceName == "" {
		otelServiceName = serviceName
	}

	ctx := context.Background()

	res, err := resource.New(ctx,
		resource.WithAttributes(
			semconv.ServiceName(otelServiceName),
		),
	)
	if err != nil {
		return func(context.Context) error { return nil }, err
	}

	var exporter sdktrace.SpanExporter
	if protocol == "http/protobuf" || strings.Contains(endpoint, "http://") || strings.Contains(endpoint, "https://") {
		exporter, err = otlptracehttp.New(ctx,
			otlptracehttp.WithEndpoint(strings.TrimPrefix(strings.TrimPrefix(endpoint, "http://"), "https://")),
			otlptracehttp.WithInsecure(),
		)
	} else {
		exporter, err = otlptracegrpc.New(ctx,
			otlptracegrpc.WithEndpoint(endpoint),
			otlptracegrpc.WithInsecure(),
		)
	}

	if err != nil {
		slog.Warn("Failed to create OTLP exporter, continuing without tracing", "error", err, "endpoint", endpoint)
		return func(context.Context) error { return nil }, nil
	}

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(res),
	)

	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	slog.Info("OTel tracer initialized", "endpoint", endpoint, "protocol", protocol, "service", otelServiceName)

	return tp.Shutdown, nil
}

// IsEnabled returns true if telemetry is enabled.
func (t *Telemetry) IsEnabled() bool {
	return t.enabled
}

// LogChallengeCreated logs a challenge.created event per Knox §6.
func (t *Telemetry) LogChallengeCreated(ctx context.Context, fields map[string]interface{}) {
	if !t.enabled {
		return
	}

	args := []any{"event", "challenge.created"}
	for k, v := range fields {
		args = append(args, k, v)
	}

	t.logger.InfoContext(ctx, "Challenge created", args...)
}

// LogChallengeVerified logs a challenge.verified event per Knox §6.
func (t *Telemetry) LogChallengeVerified(ctx context.Context, fields map[string]interface{}) {
	if !t.enabled {
		return
	}

	args := []any{"event", "challenge.verified"}
	for k, v := range fields {
		args = append(args, k, v)
	}

	t.logger.InfoContext(ctx, "Challenge verified", args...)
}

// LogMPARequest logs an mpa.request event per Knox §6.
func (t *Telemetry) LogMPARequest(ctx context.Context, fields map[string]interface{}) {
	if !t.enabled {
		return
	}

	args := []any{"event", "mpa.request"}
	for k, v := range fields {
		args = append(args, k, v)
	}

	t.logger.InfoContext(ctx, "MPA request", args...)
}

// LogMPAQuorumSatisfied logs an mpa.quorum_satisfied event per Knox §6.
func (t *Telemetry) LogMPAQuorumSatisfied(ctx context.Context, fields map[string]interface{}) {
	if !t.enabled {
		return
	}

	args := []any{"event", "mpa.quorum_satisfied"}
	for k, v := range fields {
		args = append(args, k, v)
	}

	t.logger.InfoContext(ctx, "MPA quorum satisfied", args...)
}

// IncrementChallengesCreated increments the challenge creation counter.
func (t *Telemetry) IncrementChallengesCreated(actionType string) {
	if !t.enabled {
		return
	}
	t.challengesCreated.WithLabelValues(actionType).Inc()
}

// IncrementChallengesVerified increments the challenge verification counter.
func (t *Telemetry) IncrementChallengesVerified(actionType string, success bool) {
	if !t.enabled {
		return
	}

	result := "success"
	if !success {
		result = "failure"
	}

	t.challengesVerified.WithLabelValues(actionType, result).Inc()
}

// IncrementMPARequests increments the MPA request counter.
func (t *Telemetry) IncrementMPARequests(actionType string) {
	if !t.enabled {
		return
	}
	t.mpaRequests.WithLabelValues(actionType).Inc()
}

// RecordChallengeVerifyDuration records challenge verification duration in milliseconds.
func (t *Telemetry) RecordChallengeVerifyDuration(durationMs float64) {
	if !t.enabled {
		return
	}
	t.challengeVerifyDuration.Observe(durationMs)
}

// RecordMPARequestDuration records MPA request duration in milliseconds.
func (t *Telemetry) RecordMPARequestDuration(durationMs float64) {
	if !t.enabled {
		return
	}
	t.mpaRequestDuration.Observe(durationMs)
}

// MetricsHandler returns an HTTP handler for Prometheus /metrics endpoint.
func (t *Telemetry) MetricsHandler() http.Handler {
	if !t.enabled {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.NotFound(w, r)
		})
	}

	return promhttp.HandlerFor(t.registry, promhttp.HandlerOpts{})
}

// Span wraps OpenTelemetry span.
type Span struct {
	span trace.Span
}

// End ends the span.
func (s *Span) End() {
	if s.span != nil {
		s.span.End()
	}
}

// SetAttribute sets an attribute on the span.
func (s *Span) SetAttribute(key string, value interface{}) {
	if s.span == nil {
		return
	}

	switch v := value.(type) {
	case string:
		s.span.SetAttributes(attribute.String(key, v))
	case int:
		s.span.SetAttributes(attribute.Int(key, v))
	case int64:
		s.span.SetAttributes(attribute.Int64(key, v))
	case bool:
		s.span.SetAttributes(attribute.Bool(key, v))
	case float64:
		s.span.SetAttributes(attribute.Float64(key, v))
	default:
		s.span.SetAttributes(attribute.String(key, "unsupported"))
	}
}

// StartSpan starts a new OpenTelemetry span.
//
// Returns context with span and the span itself.
// Caller must call span.End() when done.
func (t *Telemetry) StartSpan(ctx context.Context, name string) (context.Context, *Span) {
	if !t.enabled {
		return ctx, &Span{span: nil}
	}

	ctx, span := t.tracer.Start(ctx, name)
	return ctx, &Span{span: span}
}
