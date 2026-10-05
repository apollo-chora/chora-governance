// internal_tail_test.go — INTERNAL test package (package outbox) covering
// the leftover branches the external suite (dispatcher_test.go,
// store_test.go, publisher_test.go) does not reach:
//
//   - Publisher.Publish (the simple Recorder-shape entry point)
//   - Dispatcher.reconstructEnvelope schema_version / parse fallbacks
//   - parseEnvelopeTime branch table
//   - publishOne store-failure branches (MarkPublished / Deadletter /
//     MarkFailed erroring)
//   - Run's non-context drain-error loop
//   - NewDispatcher config defaults (PollInterval/Backoff/Logger/Now)
package outbox

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	cgcenvelope "github.com/apollo-chora/chora-common/envelope"

	"github.com/apollo-chora/chora-governance/internal/adapter/events"
)

// -----------------------------------------------------------------------------
// Publisher.Publish (simple Recorder shape)
// -----------------------------------------------------------------------------

func TestInternal_Publisher_Publish_SimpleShape(t *testing.T) {
	t.Parallel()
	store := NewInMemoryStore()
	p := NewPublisher(PublisherConfig{Store: store})
	rec := p.Publish("chora.governance.tenant.created.v1", events.Header{
		TenantID: "t1",
		GCID:     "g1",
	}, map[string]interface{}{"tenant_id": "t1"})
	if rec.Topic != "chora.governance.tenant.created.v1" {
		t.Errorf("rec.Topic = %q", rec.Topic)
	}
	rows, err := store.FetchPending(context.Background(), 10)
	if err != nil {
		t.Fatalf("FetchPending: %v", err)
	}
	if len(rows) == 0 {
		t.Error("Publish should have written a pending row")
	}

	// no store → zero PublishedEvent, no panic
	rec2 := NewPublisher(PublisherConfig{}).Publish("chora.governance.tenant.created.v1",
		events.Header{TenantID: "t1"}, nil)
	if rec2.Topic != "" {
		t.Errorf("nil-store Publish Topic = %q; want zero", rec2.Topic)
	}
}

func TestInternal_Publisher_Defaults(t *testing.T) {
	t.Parallel()
	p := NewPublisher(PublisherConfig{Store: NewInMemoryStore()})
	if p.cfg.SourceProject != "chora-local" || p.cfg.SourceService != "chora-governance" {
		t.Errorf("defaults not applied: %+v", p.cfg)
	}
	if p.cfg.Now().IsZero() {
		t.Error("Now default not applied")
	}
}

// -----------------------------------------------------------------------------
// reconstructEnvelope + parseEnvelopeTime
// -----------------------------------------------------------------------------

func TestInternal_ReconstructEnvelope_SchemaVersionFallbacks(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC()
	row := Row{
		ID:         "r1",
		TenantID:   "t1",
		GCID:       "g1",
		OccurredAt: now,
		Envelope: map[string]string{
			"schema_version": "0", // non-positive → rebound to 1
			"event_id":       "",
			"tenant_id":      "",
			"gcid":           "",
			"occurred_at":    "garbage-time",
			"source_project": "",
			"source_service": "",
		},
	}
	d := NewDispatcher(DispatcherConfig{Store: NewInMemoryStore(), Bus: &okBus{}, WorkerID: "w"})
	env, err := d.reconstructEnvelope(&row)
	if err != nil {
		t.Fatalf("reconstructEnvelope: %v", err)
	}
	if env.SchemaVersion != 1 {
		t.Errorf("SchemaVersion = %d; want 1 (0 rebound)", env.SchemaVersion)
	}
	if env.EventID != "r1" || env.TenantID != "t1" || env.GCID != "g1" {
		t.Errorf("envelope did not fall back to row fields: %+v", env)
	}
	if env.SourceProject != "chora-local" || env.SourceService != "chora-governance" {
		t.Errorf("source defaults missing: %+v", env)
	}
	if !env.OccurredAt.Equal(now) {
		t.Errorf("OccurredAt = %v; want row fallback %v", env.OccurredAt, now)
	}
	if env.PublishedAt.IsZero() {
		t.Error("PublishedAt missing (now fallback)")
	}

	// non-numeric schema_version → also rebound
	row2 := Row{ID: "r2", OccurredAt: now, Envelope: map[string]string{"schema_version": "banana"}}
	env2, err := d.reconstructEnvelope(&row2)
	if err != nil {
		t.Fatalf("reconstructEnvelope(banana): %v", err)
	}
	if env2.SchemaVersion != 1 {
		t.Errorf("banana SchemaVersion = %d; want 1", env2.SchemaVersion)
	}
}

func TestInternal_ReconstructEnvelope_NilEnvelope(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC()
	row := Row{ID: "r3", TenantID: "t3", GCID: "g3", OccurredAt: now}
	d := NewDispatcher(DispatcherConfig{Store: NewInMemoryStore(), Bus: &okBus{}, WorkerID: "w"})
	env, err := d.reconstructEnvelope(&row)
	if err != nil {
		t.Fatalf("reconstructEnvelope: %v", err)
	}
	if env.SchemaVersion != 1 || !env.OccurredAt.Equal(now) {
		t.Errorf("nil-envelope result wrong: %+v", env)
	}
}

func TestInternal_ParseEnvelopeTime_Branches(t *testing.T) {
	t.Parallel()
	fallback := time.Now().UTC()

	if got := parseEnvelopeTime("", fallback); !got.Equal(fallback) {
		t.Error("empty → fallback")
	}
	want := time.Date(2026, 1, 2, 3, 4, 5, 123456000, time.UTC)
	if got := parseEnvelopeTime("2026-01-02T03:04:05.123456Z", fallback); !got.Equal(want) {
		t.Errorf("RFC3339Nano parse = %v; want %v", got, want)
	}
	want2 := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	if got := parseEnvelopeTime("2026-01-02T03:04:05Z", fallback); !got.Equal(want2) {
		t.Errorf("RFC3339 parse = %v; want %v", got, want2)
	}
	if got := parseEnvelopeTime("clearly-not-a-time", fallback); !got.Equal(fallback) {
		t.Errorf("garbage → fallback, got %v", got)
	}
}

// -----------------------------------------------------------------------------
// publishOne store-failure branches
// -----------------------------------------------------------------------------

// failingStore embeds InMemoryStore and fails one mutating method.
type failingStore struct {
	*InMemoryStore
	mu             sync.Mutex
	failMarkPub    bool
	failDeadletter bool
	failMarkFailed bool
}

func (f *failingStore) MarkPublished(ctx context.Context, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failMarkPub {
		return errors.New("mark published boom")
	}
	return f.InMemoryStore.MarkPublished(ctx, id)
}

func (f *failingStore) Deadletter(ctx context.Context, id, failureReason string, attemptCount int) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failDeadletter {
		return errors.New("deadletter boom")
	}
	return f.InMemoryStore.Deadletter(ctx, id, failureReason, attemptCount)
}

func (f *failingStore) MarkFailed(ctx context.Context, id string, errMsg string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failMarkFailed {
		return errors.New("mark failed boom")
	}
	return f.InMemoryStore.MarkFailed(ctx, id, errMsg)
}

// okBus publishes successfully.
type okBus struct{}

func (okBus) Publish(context.Context, string, cgcenvelope.Envelope, []byte) error { return nil }

// errBus always fails.
type errBus struct{ err error }

func (e errBus) Publish(context.Context, string, cgcenvelope.Envelope, []byte) error { return e.err }

func TestInternal_PublishOne_MarkPublishedError(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := &failingStore{InMemoryStore: NewInMemoryStore()}
	store.failMarkPub = true
	now := time.Now().UTC()

	// envelope reconstruct fails → Deadletter path is taken, not publish.
	row := Row{ID: "r1", TenantID: "t1", OccurredAt: now, Envelope: map[string]string{"event_id": "e1"}}
	d := NewDispatcher(DispatcherConfig{Store: store, Bus: okBus{}, WorkerID: "w"})

	// corrupt envelope (no tenant, non-envelope... actually reconstruct always
	// succeeds). Use publish-success → MarkPublished failure.
	row2 := Row{ID: "r2", TenantID: "t2", OccurredAt: now,
		Envelope: map[string]string{"event_id": "e2", "tenant_id": "t2", "occurred_at": now.Format(time.RFC3339Nano)}}
	if err := d.publishOne(ctx, &row2); err == nil {
		t.Fatal("expected error from MarkPublished failure")
	}

	// corrupt-row deadletter branch: reconstruct always succeeds for any row,
	// so force the bus to fail past MaxAttempts and make Deadletter fail.
	store2 := &failingStore{InMemoryStore: NewInMemoryStore()}
	store2.failDeadletter = true
	d2 := NewDispatcher(DispatcherConfig{Store: store2, Bus: errBus{errors.New("bus down")}, WorkerID: "w", MaxAttempts: 1})
	if err := d2.publishOne(ctx, &row); err == nil {
		t.Fatal("expected error bubbling from deadletter failure")
	}

	// transient failure + MarkFailed failure
	store3 := &failingStore{InMemoryStore: NewInMemoryStore()}
	store3.failMarkFailed = true
	d3 := NewDispatcher(DispatcherConfig{Store: store3, Bus: errBus{errors.New("bus down")}, WorkerID: "w", MaxAttempts: 5})
	if err := d3.publishOne(ctx, &row); err == nil {
		t.Fatal("expected error from publish failure")
	}
}

// -----------------------------------------------------------------------------
// Dispatcher.Run + NewDispatcher defaults
// -----------------------------------------------------------------------------

func TestInternal_NewDispatcher_ConfigDefaults(t *testing.T) {
	t.Parallel()
	d := NewDispatcher(DispatcherConfig{Store: NewInMemoryStore(), Bus: okBus{}, WorkerID: "w"})
	if d.cfg.MaxAttempts != 5 {
		t.Errorf("MaxAttempts = %d; want 5", d.cfg.MaxAttempts)
	}
	if d.cfg.PollInterval != 250*time.Millisecond {
		t.Errorf("PollInterval = %v; want 250ms", d.cfg.PollInterval)
	}
	if d.cfg.BackoffBase != 50*time.Millisecond || d.cfg.BackoffCap != 5*time.Second {
		t.Error("backoff defaults missing")
	}
	if d.cfg.Logger == nil {
		t.Error("Logger default missing")
	}
	if d.cfg.Now == nil {
		t.Error("Now default missing")
	}
	if d.cfg.SourceService != "chora-governance" {
		t.Errorf("SourceService = %q", d.cfg.SourceService)
	}
}

func TestInternal_Dispatcher_Run_DrainErrorLoop(t *testing.T) {
	t.Parallel()
	// store whose FetchPending errors once → Run warns and keeps looping
	// until ctx cancellation.
	store := &failingFetchStore{InMemoryStore: NewInMemoryStore(), failFetch: true}
	d := NewDispatcher(DispatcherConfig{Store: store, Bus: okBus{}, WorkerID: "w", PollInterval: time.Millisecond})
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()
	err := d.Run(ctx, 10)
	if err != context.Canceled {
		t.Errorf("Run err = %v; want context.Canceled", err)
	}
}

type failingFetchStore struct {
	*InMemoryStore
	failFetch bool
}

func (f *failingFetchStore) FetchPending(ctx context.Context, limit int) ([]Row, error) {
	if f.failFetch {
		return nil, errors.New("fetch boom")
	}
	return f.InMemoryStore.FetchPending(ctx, limit)
}
