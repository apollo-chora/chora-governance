// CostAnomalySubscriber ingests cost-anomaly events emitted by
// chora-observability and projects them into the chora-governance D3
// `cost_anomalies` evidence table (per ADR-141 IMDA D3 = Cost + Monitoring +
// Safety + Testing).
//
// This is the FIRST non-agentic IMDA evidence ingestion source wired
// end-to-end as the canonical pattern. Cost anomalies are statistical outliers
// detected by the observability cost-tracking pipeline (TokenUsageLedger
// sigma-detection per the ai-cost-tracking skill) — NOT an agentic
// orchestrator emission, so this subscriber is independent of the
// agent-decision / eval-run path (which another session owns).
//
// Source-of-truth + conventions:
//   - .claude/skills/imda-governance-4-dimensions/SKILL.md (D3 routing)
//   - .claude/skills/ai-cost-tracking/SKILL.md (anomaly detection semantics)
//   - internal/domain/evidence (CostAnomaly aggregate + NewCostAnomaly ctor)
//   - mirrors the AgentDecisionConsumer / ClosureSubscriber inbound-adapter
//     shape (idempotent.Store dedupe + FAIL-LOUD validation + append-only
//     evidence write).
//
// Hexagonal: INBOUND adapter; depends only on the evidence.Repository port.
// Cross-DB queries forbidden — chora-governance writes ONLY its own DB.
//
// WIRE-SHAPE NOTE (flagged follow-up): unlike the agent-decision topic, the
// cost-anomaly topic does NOT yet have a binary-protobuf schema in
// chora-contracts (no proto/events/observability/cost_anomaly.proto). This
// subscriber therefore decodes a JSON envelope-shaped payload. When the
// canonical proto lands, swap decodeCostAnomaly for proto.Unmarshal exactly
// as AgentDecisionConsumer.Handle does, and register a binary encoder in
// internal/adapter/events/protomarshal for the publisher side.
package events

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/apollo-chora/chora-common/idempotent"
	"github.com/apollo-chora/chora-governance/internal/domain/evidence"
)

// TopicCostAnomalyDetected is the canonical Pub/Sub topic for cost-anomaly
// events emitted by chora-observability. Follows the
// chora.{domain}.{aggregate}.{event_type}.v{N} convention established by
// chora.observability.agent_decision.logged.v1.
//
// FOLLOW-UP: confirm against chora-infra Terraform when the observability
// cost-anomaly topic is provisioned; the subscription name + DLQ binding live
// there (this constant must match the provisioned topic).
const TopicCostAnomalyDetected = "chora.observability.cost_anomaly.detected.v1"

// CostAnomalyInboxTTL is the dedupe-key retention window. Matches the
// AgentDecisionInboxTTL / AuditPaymentsInboxTTL convention.
const CostAnomalyInboxTTL = 24 * time.Hour

// costAnomalyDimension is the IMDA dimension this subscriber writes evidence
// under. chora-governance is the D3 consumer for cost evidence per ADR-141.
const costAnomalyDimension = "safety_and_robustness"

// CostAnomalyEvent is the envelope-shaped JSON payload the observability cost
// pipeline emits. Envelope-mandatory fields ride the top level (consistent
// with the closure-saga JSON payloads); the anomaly detail is the remainder.
//
// When the binary proto lands this struct is replaced by the generated
// observabilityv1.CostAnomalyDetected message (see the WIRE-SHAPE NOTE above).
type CostAnomalyEvent struct {
	EventID            string `json:"event_id"`
	IdempotencyKey     string `json:"idempotency_key,omitempty"`
	TenantID           string `json:"tenant_id"`
	GCID               string `json:"gcid,omitempty"`
	Traceparent        string `json:"traceparent,omitempty"`
	ChoraImdaDimension string `json:"chora_imda_dimension,omitempty"`
	ImdaLifecycleStage string `json:"imda_lifecycle_stage,omitempty"`

	AnomalyID      string  `json:"anomaly_id"`
	AgentID        string  `json:"agent_id"`
	BaselineMicros int64   `json:"baseline_micros"`
	ObservedMicros int64   `json:"observed_micros"`
	SigmaFactor    float64 `json:"sigma_factor"`
}

// CostAnomalySubscriber appends D3 cost-anomaly evidence rows from inbound
// observability events. Depends only on the evidence.Repository port.
type CostAnomalySubscriber struct {
	repo  evidence.Repository
	inbox idempotent.Store
	ttl   time.Duration
}

// NewCostAnomalySubscriber wires the evidence repo + an idempotency inbox.
// When inbox is nil an in-memory store is allocated (matching sibling
// subscribers). Panics on a nil repo — a subscriber with no sink is a
// misconfiguration that must fail at boot, not silently drop evidence.
func NewCostAnomalySubscriber(repo evidence.Repository, inbox idempotent.Store) *CostAnomalySubscriber {
	if repo == nil {
		panic("events: NewCostAnomalySubscriber: evidence repository required")
	}
	if inbox == nil {
		inbox = idempotent.NewMemoryStore()
	}
	return &CostAnomalySubscriber{
		repo:  repo,
		inbox: inbox,
		ttl:   CostAnomalyInboxTTL,
	}
}

// SubscribedTopic returns the canonical topic this subscriber binds to.
func (s *CostAnomalySubscriber) SubscribedTopic() string { return TopicCostAnomalyDetected }

// HandleBytes decodes the raw Pub/Sub message data + dispatches to Handle.
// FAIL LOUD: a malformed payload returns an error so the caller's Pub/Sub
// adapter NACKs → DLQ (no silent drop).
func (s *CostAnomalySubscriber) HandleBytes(ctx context.Context, body []byte) error {
	ev, err := decodeCostAnomaly(body)
	if err != nil {
		return fmt.Errorf("events: cost_anomaly decode: %w", err)
	}
	return s.Handle(ctx, ev)
}

// Handle validates + appends one cost-anomaly event as a D3 CostAnomaly
// evidence row. Idempotent on event_id (prefers idempotency_key) — re-delivery
// from at-least-once Pub/Sub is a no-op (the evidence repo is also idempotent
// on EventID).
//
// Returns nil on successful append; an error on validation failure or repo
// error so the caller NACKs for redelivery.
func (s *CostAnomalySubscriber) Handle(ctx context.Context, ev CostAnomalyEvent) error {
	if s == nil || s.repo == nil {
		return errors.New("events: CostAnomalySubscriber not initialised")
	}
	if err := validateCostAnomaly(ev); err != nil {
		return err
	}

	dedupeKey := strings.TrimSpace(ev.IdempotencyKey)
	if dedupeKey == "" {
		dedupeKey = ev.EventID
	}

	return s.inbox.Process(ctx, dedupeKey, s.ttl, func() error {
		stage := evidence.LifecycleStage(strings.TrimSpace(ev.ImdaLifecycleStage))
		row, err := evidence.NewCostAnomaly(evidence.CostAnomalyParams{
			EventID:        ev.EventID,
			TenantID:       ev.TenantID,
			AnomalyID:      ev.AnomalyID,
			AgentID:        ev.AgentID,
			BaselineMicros: ev.BaselineMicros,
			ObservedMicros: ev.ObservedMicros,
			SigmaFactor:    ev.SigmaFactor,
			LifecycleStage: stage, // empty ⇒ ctor defaults to runtime
		})
		if err != nil {
			return fmt.Errorf("events: cost_anomaly build: %w", err)
		}
		if err := s.repo.AppendCostAnomaly(ctx, row); err != nil {
			return fmt.Errorf("events: cost_anomaly append: %w", err)
		}
		return nil
	})
}

// decodeCostAnomaly parses the JSON envelope-shaped payload. Unknown fields
// are tolerated (forward-compat with new envelope fields); strict decoding is
// deferred to the binary-proto migration.
func decodeCostAnomaly(body []byte) (CostAnomalyEvent, error) {
	var ev CostAnomalyEvent
	if len(body) == 0 {
		return ev, errors.New("empty body")
	}
	if err := json.Unmarshal(body, &ev); err != nil {
		return ev, err
	}
	return ev, nil
}

// validateCostAnomaly enforces envelope-mandatory + payload-required fields.
// The chora_imda_dimension, when present, MUST be the D3 dimension; a blank
// dimension is tolerated (observability emitters may omit it — the subscriber
// stamps the canonical D3 dimension on the evidence row regardless).
func validateCostAnomaly(ev CostAnomalyEvent) error {
	if strings.TrimSpace(ev.EventID) == "" {
		return errors.New("events: cost_anomaly event_id required")
	}
	if strings.TrimSpace(ev.TenantID) == "" {
		return errors.New("events: cost_anomaly tenant_id required")
	}
	if strings.TrimSpace(ev.AnomalyID) == "" {
		return errors.New("events: cost_anomaly anomaly_id required")
	}
	if strings.TrimSpace(ev.AgentID) == "" {
		return errors.New("events: cost_anomaly agent_id required")
	}
	if dim := strings.ToLower(strings.TrimSpace(ev.ChoraImdaDimension)); dim != "" && dim != costAnomalyDimension {
		return fmt.Errorf(
			"events: cost_anomaly unexpected imda_dimension %q (want %q or blank)",
			dim, costAnomalyDimension,
		)
	}
	return nil
}
