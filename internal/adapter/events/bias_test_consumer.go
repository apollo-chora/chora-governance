// BiasTestConsumer projects `chora.governance.bias_test.completed.v1` events
// into IMDA D4 (fairness_and_human_oversight) bias_test_runs evidence — the
// D4 half of the O+ golden evidence pipeline (ADR-173, CHO-1641).
//
// Source-of-truth:
//   - chora-contracts/proto/events/governance/bias_test.proto §BiasTestCompleted
//     (BINARY, Schema-Registry-bound)
//   - services/chora-ai-kernel-orchestrator/eval/bias/ (the real deepeval
//     BiasMetric harness that scores the MCQ-AI-Assist crew and publishes one
//     BiasTestCompleted per scored demographic sample)
//
// 1:1 mapping — one BiasTestCompleted → one bias_test_runs row. The fairness
// transform (score = 1 - raw_bias, threshold = 1 - native_threshold) is
// applied UPSTREAM by the harness, so the projector's derived
// `Passed = Score >= Threshold` reproduces deepeval's own success verdict.
// agent_id names the system-under-test crew so O+ auditors see the bias
// test's scope (4.1/4.3 are NOT platform-wide attestations).
//
// Cross-DB queries forbidden — chora-governance reads only its own DB.
package events

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	governancev1 "github.com/apollo-chora/chora-contracts/gen/go/chora/governance/v1"

	"github.com/apollo-chora/chora-common/idempotent"
	"github.com/apollo-chora/chora-governance/internal/domain/evidence"
	"github.com/apollo-chora/chora-governance/internal/domain/projector"
)

// TopicBiasTestCompleted is the canonical provisioned bias-test topic.
const TopicBiasTestCompleted = "chora.governance.bias_test.completed.v1"

// BiasTestInboxTTL is the dedupe-key retention window.
const BiasTestInboxTTL = 24 * time.Hour

// fairnessDimension is the canonical D4 IMDA dimension (ADR-141).
const fairnessDimension = "fairness_and_human_oversight"

// biasEventType routes the projector to the bias_test_runs aggregate
// (routeD4 matches on EventType contains "bias").
const biasEventType = "bias_test_completed"

// BiasTestAttrs are the envelope-derived Pub/Sub message attributes (fallback
// to the proto envelope, which is authoritative).
type BiasTestAttrs struct {
	EventID        string
	IdempotencyKey string
	TenantID       string
}

// BiasTestConsumer ingests BiasTestCompleted events + projects them into D4
// fairness bias_test_runs evidence via the chora-governance projector.
type BiasTestConsumer struct {
	proj  ProjectorPort
	inbox idempotent.Store
	ttl   time.Duration

	mu sync.Mutex
}

// NewBiasTestConsumer wires the projector + an idempotency inbox.
func NewBiasTestConsumer(proj ProjectorPort, inbox idempotent.Store) *BiasTestConsumer {
	if inbox == nil {
		inbox = idempotent.NewMemoryStore()
	}
	return &BiasTestConsumer{proj: proj, inbox: inbox, ttl: BiasTestInboxTTL}
}

// SubscribedTopic returns the canonical topic this subscriber binds to.
func (c *BiasTestConsumer) SubscribedTopic() string { return TopicBiasTestCompleted }

// Handle decodes one BINARY BiasTestCompleted message and projects a single
// bias_test_runs row. FAIL LOUD on decode error (NACK → DLQ); idempotent on
// the event_id via the inbox AND the evidence repo's append-only dedupe.
func (c *BiasTestConsumer) Handle(ctx context.Context, body []byte, attrs BiasTestAttrs) error {
	if c == nil || c.proj == nil {
		return errors.New("events: BiasTestConsumer not initialised")
	}

	var msg governancev1.BiasTestCompleted
	if err := proto.Unmarshal(body, &msg); err != nil {
		return fmt.Errorf("events: bias_test proto decode: %w", err)
	}

	env := msg.GetEnvelope()
	eventID := firstNonBlank(env.GetEventId(), attrs.EventID)
	tenantID := firstNonBlank(env.GetTenantId(), attrs.TenantID)
	idempotencyKey := firstNonBlank(env.GetIdempotencyKey(), attrs.IdempotencyKey)
	runID := strings.TrimSpace(msg.GetRunId())
	agentID := strings.TrimSpace(msg.GetAgentId())
	attr := strings.TrimSpace(msg.GetProtectedAttribute())
	testType := strings.TrimSpace(msg.GetTestType())

	if strings.TrimSpace(eventID) == "" {
		return errors.New("events: bias_test envelope event_id required")
	}
	if strings.TrimSpace(tenantID) == "" {
		return errors.New("events: bias_test envelope tenant_id required")
	}
	if runID == "" || agentID == "" || attr == "" || testType == "" {
		return errors.New("events: bias_test run_id/agent_id/protected_attribute/test_type required")
	}

	dedupeKey := idempotencyKey
	if dedupeKey == "" {
		dedupeKey = eventID
	}

	return c.inbox.Process(ctx, dedupeKey, c.ttl, func() error {
		ev := projector.IncomingEvent{
			EventID:            eventID,
			TenantID:           tenantID,
			ImdaDimension:      fairnessDimension,
			LifecycleStage:     string(evidence.LifecyclePreDeploy),
			EventType:          biasEventType,
			OccurredAt:         envelopeTime(env.GetOccurredAt()),
			Traceparent:        env.GetTraceparent(),
			RunID:              runID,
			AgentID:            agentID,
			ProtectedAttribute: attr,
			TestType:           testType,
			Score:              msg.GetScore(),
			Threshold:          msg.GetThreshold(),
			Provenance: map[string]any{
				"raw_bias_score": msg.GetRawBiasScore(),
				"judge_model":    msg.GetJudgeModel(),
				"reason":         msg.GetReason(),
			},
		}
		return c.proj.Project(ctx, ev)
	})
}

// HandleEnvelope is the in-process / test convenience wrapper.
func (c *BiasTestConsumer) HandleEnvelope(ctx context.Context, raw []byte) error {
	return c.Handle(ctx, raw, BiasTestAttrs{})
}
