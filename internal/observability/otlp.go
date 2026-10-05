// Package observability is a thin compatibility shim that delegates to the
// canonical chora-common/otel package. The canonical lib wires a real OTLP
// exporter (OTEL_EXPORTER_OTLP_ENDPOINT); this shim preserves the local
// Init(ctx) signature so call sites in cmd/server/main.go keep compiling
// without edits.
//
// The async variant InitAsync returns a bootstrap.OTLPHandle; pod
// bootstrap can now run pgx pool init with the FULL bootstrap deadline
// while OTLP wiring proceeds in its own goroutine + own deadline.
package observability

import (
	"context"

	"github.com/apollo-chora/chora-common/bootstrap"
	commonobs "github.com/apollo-chora/chora-common/observability"
	commonotel "github.com/apollo-chora/chora-common/otel"
)

// serviceName is the canonical OTLP service.name attribute for this binary.
const serviceName = "chora-governance"

// version is bumped per-release; matches the constant in cmd/server/main.go.
const version = "0.1.0"

// Init wires the OTel exporter via the canonical lib and registers a global
// TracerProvider. Returns a shutdown func the caller MUST defer to flush
// spans on exit. Public signature preserved for backward compatibility.
//
// Prefer InitAsync in new call sites — it decouples OTLP init from pgx
// pool bootstrap.
func Init(ctx context.Context) (shutdown func(context.Context) error, err error) {
	return commonotel.Init(ctx, serviceName, version)
}

// InitAsync is the fail-soft non-blocking variant of Init — OTLP init
// runs in its own goroutine with its own deadline
// (CHORA_OTLP_INIT_TIMEOUT_SECONDS, default 15s). Timeout / init-error
// degrade to a no-op shutdown so pgx pool + event bus get the FULL
// bootstrap budget.
func InitAsync(ctx context.Context) *bootstrap.OTLPHandle {
	return commonobs.InitOTLPAsync(ctx, serviceName, version)
}
