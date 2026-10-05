// otlp_test.go — unit tests for the observability shim.
//
// The shim is a thin delegation to chora-common (otel.Init +
// observability.InitOTLPAsync); these tests verify the delegation contract:
// Init returns a usable shutdown func, InitAsync returns a settleable handle.
//
// OTLP_EXPORTER=stdout is forced so both paths exercise the deterministic
// stdout exporter instead of the Cloud Trace ADC/dial path (which requires
// real credentials and would hang a unit test).
package observability_test

import (
	"context"
	"testing"
	"time"

	"github.com/apollo-chora/chora-governance/internal/observability"
)

func TestInit_ReturnsUsableShutdown(t *testing.T) {
	t.Setenv("OTEL_EXPORTER", "stdout")

	shutdown, err := observability.Init(context.Background())
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	if shutdown == nil {
		t.Fatal("Init returned nil shutdown func")
	}
	if err := shutdown(context.Background()); err != nil {
		t.Errorf("shutdown: %v", err)
	}
}

func TestInitAsync_ReturnsSettleableHandle(t *testing.T) {
	t.Setenv("OTEL_EXPORTER", "stdout")

	h := observability.InitAsync(context.Background())
	if h == nil {
		t.Fatal("InitAsync returned nil handle")
	}

	res := h.Wait(10 * time.Second)
	if res.Shutdown == nil {
		t.Error("handle resolved with nil shutdown func")
	}
	if res.Err != nil {
		t.Errorf("handle resolved with unexpected err: %v", res.Err)
	}
	if err := res.Shutdown(context.Background()); err != nil {
		t.Errorf("handle shutdown: %v", err)
	}
}
