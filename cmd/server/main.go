// Package main is the chora-governance service entrypoint.
//
// Service: chora-governance (Governance supporting domain)
// Project: chora-489812 (platform host; Team 3 / Platform)
// Topic prefix: chora.governance.*
//
// Phase 5 (2026-05-13) wired the canonical persistence layer:
//   - pgxpool-backed audit + IMDA + policy + evidence repositories when
//     CHORA_DB_DSN is set (all 4 pgx repos land in Phase 5.A + 5.B)
//   - producer-side outbox (postgres-backed when CHORA_OUTBOX_DSN is set,
//     dispatching to the NATS JetStream event bus when NATS_URL is set)
//
// Per CLAUDE.md §1, IMDA Model AI Governance Framework is the NorthStar
// — all 4 dimensions in O+ from launch.
package main

import (
	"context"
	"database/sql"
	"errors"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	// pgx stdlib driver — registered for sql.Open("pgx", dsn) used by the
	// per-domain outbox PostgresStore in bootstrap.go.
	_ "github.com/jackc/pgx/v5/stdlib"

	"google.golang.org/grpc"
	healthgrpc "google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"

	governancev1 "github.com/apollo-chora/chora-contracts/gen/go/chora/services/governance/v1"

	"github.com/apollo-chora/chora-common/durabilityguard"
	"github.com/apollo-chora/chora-common/eventbus"
	govevents "github.com/apollo-chora/chora-governance/internal/adapter/events"
	grpcadapter "github.com/apollo-chora/chora-governance/internal/adapter/grpc"
	httpadapter "github.com/apollo-chora/chora-governance/internal/adapter/http"
	"github.com/apollo-chora/chora-governance/internal/adapter/outbox"
	"github.com/apollo-chora/chora-governance/internal/adapter/pg"
	"github.com/apollo-chora/chora-governance/internal/domain/aitransparency"
	"github.com/apollo-chora/chora-governance/internal/domain/audit"
	"github.com/apollo-chora/chora-governance/internal/domain/compliance"
	"github.com/apollo-chora/chora-governance/internal/domain/evidence"
	"github.com/apollo-chora/chora-governance/internal/domain/evidencepack"
	"github.com/apollo-chora/chora-governance/internal/domain/gatekeeper"
	"github.com/apollo-chora/chora-governance/internal/domain/imda"
	"github.com/apollo-chora/chora-governance/internal/domain/policy"
	"github.com/apollo-chora/chora-governance/internal/domain/projector"
	"github.com/apollo-chora/chora-governance/internal/observability"
)

// Compile-time guard: keep events package referenced even when unused at
// the wire point (publisher attached when CHORA_OUTBOX_DSN is set).
var _ govevents.Header

const (
	serviceName = "chora-governance"
	version     = "0.1.0"
)

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// OTLP wiring per Tier 3 D13 — direct to Cloud Trace in prod.
	//
	// Per C(a).S1 path (b) — tracker #151 — OTLP init runs in its own
	// goroutine with its own (env-tunable, default 15s) deadline + fail-
	// soft semantics. Timeout / init-error degrade to a no-op shutdown,
	// so the rest of bootstrap (pgx pool, event bus) gets the FULL
	// CHORA_BOOTSTRAP_TIMEOUT_SECONDS budget. Previously a slow Cloud
	// Trace TLS handshake could swallow the shared budget and crash-
	// loop the pod under PgBouncer 4-container cold-start.
	otlpHandle := observability.InitAsync(ctx)
	defer func() {
		// WaitContext blocks until init settles — usually a no-op by
		// shutdown time because pgx-pool init below already gave OTLP
		// best-effort wall-clock to land.
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		res := otlpHandle.WaitContext(shutdownCtx)
		if err := res.Shutdown(shutdownCtx); err != nil {
			log.Printf("trace shutdown error: %v", err)
		}
	}()

	// ---------------------------------------------------------------------
	// Repository wiring — pgx-backed when CHORA_DB_DSN[_SECRET_ID] is set,
	// in-memory otherwise. Phase 5.B (2026-05-13) added pgx Policy +
	// Evidence repositories to complete the canonical persistence layer.
	// ---------------------------------------------------------------------
	var policyRepo policy.Repository = policy.NewInMemoryRepository()
	var auditRepo audit.Repository = audit.NewInMemoryRepository()
	var imdaRepo imda.Repository = imda.NewInMemoryRepository()
	var evidenceRepo evidence.Repository = evidence.NewInMemoryRepository()
	// AI Transparency (ADR-225) — disclosure config + acknowledgement evidence
	// live in chora_governance (migration 0011). The service is wired only when
	// a real DB pool is present (the disclosure config is seeded data, no stub);
	// with no pool the learner-self routes are not registered.
	var aiTransparencySvc *aitransparency.Service

	pool, poolShutdown := bootstrapDBPool(ctx)
	if poolShutdown != nil {
		defer poolShutdown()
	}
	if pool != nil {
		querier := pg.NewPgxPoolQuerier(pool)
		auditRepo = pg.NewAuditRepository(querier)
		imdaRepo = pg.NewIMDARepository(querier)
		policyRepo = pg.NewPolicyRepository(querier)
		evidenceRepo = pg.NewEvidenceRepository(querier)
		// ADR-225 backbone: real pg-backed repo + the standard age-signal
		// resolver (unknown -> standard wording; the hybrid sources are
		// roadmapped follow-ups behind this port).
		aiTransparencySvc = aitransparency.NewService(
			pg.NewAiTransparencyRepository(querier),
			aitransparency.StandardAgeSignalResolver{},
		)
		log.Printf("governance: pgx Audit + IMDA + Policy + Evidence + AITransparency repositories wired (pool=chora_governance)")
	}

	// ---------------------------------------------------------------------
	// Event bus — NATS JetStream when NATS_URL is set, in-memory otherwise.
	// The outbox dispatcher drains pending outbox_events rows to this bus;
	// the closure-saga subscriber + the evidence/audit consumers bind to it
	// as durable subscribers.
	// ---------------------------------------------------------------------
	jetBus, busShutdown := bootstrapBus(ctx)
	if busShutdown != nil {
		defer busShutdown()
	}
	var bus outbox.Bus = eventbus.NewInMemoryBus()
	if jetBus != nil {
		bus = jetBus
		log.Printf("governance: NATS JetStream event bus wired (url=%s)", os.Getenv("NATS_URL"))
	} else {
		log.Printf("governance: in-memory event bus wired (NATS_URL unset; NOT durable across restart)")
	}

	// Federated closure-saga subscriber (CHO-1719 / Tier 3 D11): consumes
	// chora.governance.pii.pseudonymise.requested.v1, applies the
	// per-domain PII_Closure_Map.yaml duty, and acks on
	// chora.governance.account.pseudonymised.v1.
	//
	// Repo seam (CHO-2198, W0-F1 durability + W0-F5 error-honesty): pg on a
	// healthy pool (durable ack/dedup — migration 0012,
	// closure_pseudonymisation_state), in-memory ONLY when the pool is
	// absent, mirroring the chora-payments else-branch shape. Before this
	// fix the repo was UNGATED — gated on the bus client only, never on pool
	// health — so the ack/dedup state was lost on every pod restart even
	// with a healthy chora_governance pool (see
	// docs/references/w0-f1-inmemory-inventory.md §6 item 4). Real
	// per-table pg tokenisation (actually redacting audit_log /
	// imda_assessments / ... columns) remains separate, deeper M12+ debt —
	// this fix is durability of the ack/dedup SIGNAL only, not the
	// redaction itself. Pull subscription is provisioned by infra (closure
	// deploy runbook); override the name via env.
	// closureRepo is hoisted to function scope so the CHO-2198 W0-F1 durability
	// guard (below) can classify it alongside the other repos. It stays nil when
	// jetBus is absent (closure subscriber unwired) — the guard reports nil
	// as UNKNOWN, never a false violation.
	var closureRepo govevents.ClosureRepository
	if jetBus != nil {
		piiPath := os.Getenv("CHORA_PII_CLOSURE_MAP_PATH")
		if piiPath == "" {
			piiPath = "config/PII_Closure_Map.yaml"
		}
		closureAckPub := govevents.NewEventBusClosurePublisher(
			jetBus,
			strings.TrimSpace(os.Getenv("CHORA_SOURCE_PROJECT")),
			"chora-governance",
		)
		if pool != nil {
			closureRepo = pg.NewClosureRepository(pg.NewPgxPoolQuerier(pool))
			log.Printf("governance: pg ClosureRepository wired (table=closure_pseudonymisation_state)")
		} else {
			closureRepo = govevents.NewInMemoryClosureRepo()
			log.Printf("governance: CHORA_DB_DSN unset — closure repo uses in-memory store (NOT durable across restart)")
		}
		if closureSub, err := govevents.BootstrapClosureSubscriber(piiPath, closureRepo, closureAckPub, nil); err != nil {
			log.Printf("governance: closure subscriber DISABLED (PII map load: %v)", err)
		} else {
			closureSubName := os.Getenv("CHORA_CLOSURE_SUBSCRIPTION")
			if closureSubName == "" {
				closureSubName = "chora-governance.closure-pseudonymise"
			}
			log.Printf("governance: closure subscriber binding %s -> %s", closureSubName, govevents.TopicPseudonymiseRequested)
			if err := jetBus.Subscribe(ctx, consumerConfig(closureSubName, govevents.TopicPseudonymiseRequested), govevents.ClosurePullHandler(closureSub)); err != nil && !errors.Is(err, context.Canceled) {
				log.Printf("governance: closure subscriber exited: %v", err)
			}
		}
	}

	// CHO-2198 W0-F1 — report-only runtime durability guard over the composition
	// root. Classifies each wired repository by SHAPE (holds a live *pgxpool.Pool
	// ⇒ DURABLE; a data map ⇒ IN_MEMORY; nil ⇒ UNKNOWN) and logs a structured,
	// greppable report at boot. Report-only unless CHORA_DURABILITY_GUARD=enforce
	// AND the binding is allow-listed — the nil allow-list matches the
	// chora-payments / chora-identity wirings. The 4 canonical repos resolve to pg
	// on a healthy pool (in-memory fallback otherwise); closureRepo is hoisted
	// above so its nil (jetBus absent) reports UNKNOWN, not a false
	// violation. The outbox store + event bus are transport, not data stores —
	// excluded, mirroring the payments/identity bindings.
	durabilityguard.Guard("chora-governance", []durabilityguard.Binding{
		{Port: "policy", Adapter: policyRepo},
		{Port: "audit", Adapter: auditRepo},
		{Port: "imda", Adapter: imdaRepo},
		{Port: "evidence", Adapter: evidenceRepo},
		{Port: "closure", Adapter: closureRepo},
	}, nil)

	var outboxStore outbox.Store
	var outboxDB *sql.DB
	var outboxClose func()
	outboxDB, outboxClose = bootstrapOutboxDB(ctx)
	if outboxClose != nil {
		defer outboxClose()
	}
	if outboxDB != nil {
		outboxStore = outbox.NewPostgresStore(
			sqlDBAdapter{db: outboxDB},
			outbox.PostgresStoreOptions{WorkerID: outboxWorkerID()},
		)
		log.Printf("governance: outbox PostgresStore wired (worker_id=%s)", outboxWorkerID())
	} else {
		outboxStore = outbox.NewInMemoryStore()
		log.Printf("governance: outbox InMemoryStore wired (CHORA_OUTBOX_DSN unset; NOT durable across restart)")
	}

	// Producer-side outbox publisher — the HITL verdict HTTP handler emits
	// chora.governance.audit.recorded.v1 through this. Writes a pending
	// outbox_events row (same store the Dispatcher drains to the event bus),
	// so audit events are durable across a crash between the verdict write
	// and the bus publish. Config (SourceProject) flows from env via the
	// same defaults the dispatcher uses — no inline config.
	auditPublisher := outbox.NewPublisher(outbox.PublisherConfig{
		Store:         outboxStore,
		SourceProject: strings.TrimSpace(os.Getenv("CHORA_SOURCE_PROJECT")),
		SourceService: serviceName,
	})

	dispatcher := outbox.NewDispatcher(outbox.DispatcherConfig{
		Store:        outboxStore,
		Bus:          bus,
		WorkerID:     outboxWorkerID(),
		MaxAttempts:  5,
		PollInterval: 250 * time.Millisecond,
	})
	go func() {
		if err := dispatcher.Run(ctx, 100); err != nil && err != context.Canceled && err != context.DeadlineExceeded {
			log.Printf("governance: outbox dispatcher exited: %v", err)
		}
	}()

	evaluator := gatekeeper.NewEvaluator(policyRepo, auditRepo)
	complianceGen := compliance.NewGenerator(auditRepo, imdaRepo)
	imdaProjector := projector.New(evidenceRepo)
	exporter := evidencepack.New(evidenceRepo, auditRepo)

	// ---------------------------------------------------------------------
	// Gate #8 — AgentDecisionLog StreamingPull consumer.
	//
	// Subscribes to chora.observability.agent_decision.logged.v1 via the
	// canonical subscription chora-governance.agent-decision-logged
	// (provisioned by chora-infra/terraform/environments/dev/main.tf via
	// m10-pubsub-subscriptions → m10-pubsub-dlq). The consumer projects
	// inbound events into AccountabilityEvidence (D1 per ADR-141) via the
	// existing imdaProjector.
	//
	// Per [[feedback-d6-resilience-first-class]] Pillar 2: handler errors
	// Nack so the bus redelivers; persistent failures hit the
	// subscription's dead_letter_policy after max_delivery_attempts (5 by
	// DLQ-A directive). The goroutine exits cleanly on ctx.Canceled —
	// same shape as the outbox dispatcher above.
	//
	// Env contract:
	//   CHORA_AGENT_DECISION_SUBSCRIPTION — full subscription resource or
	//     short name; default chora-governance.agent-decision-logged.
	// When jetBus is nil (dev mode without NATS_URL),
	// the consumer goroutine is NOT started; the in-memory bus path stays
	// the dev default.
	agentDecisionConsumer := govevents.NewAgentDecisionConsumer(imdaProjector, nil)
	if jetBus != nil {
		agentDecisionSub := strings.TrimSpace(os.Getenv("CHORA_AGENT_DECISION_SUBSCRIPTION"))
		if agentDecisionSub == "" {
			agentDecisionSub = "chora-governance.agent-decision-logged"
		}
		log.Printf(
			"governance: AgentDecisionConsumer subscribing on %q (subject=%s)",
			agentDecisionSub, govevents.TopicAgentDecisionLogged,
		)
		if err := jetBus.Subscribe(ctx, consumerConfig(agentDecisionSub, govevents.TopicAgentDecisionLogged), govevents.AgentDecisionHandler(agentDecisionConsumer)); err != nil && !errors.Is(err, context.Canceled) {
			log.Printf("governance: AgentDecisionSubscription exited: %v", err)
		}
	} else {
		log.Printf("governance: AgentDecisionConsumer wired (in-memory only; NATS_URL unset)")
	}

	// ---------------------------------------------------------------------
	// D2 transparency — AiAssistCompleted StreamingPull consumer (ADR-173).
	//
	// Subscribes to the EXISTING terminal qgen event
	// chora.creation.ai_assist.completed.v1 via the canonical subscription
	// chora-governance.creation-ai-assist-completed. Fans each completed event
	// out into decision_explanation rows (N learner from real option
	// explainers + auditor + instructor from the real critic diagnosis) via
	// the same imdaProjector — feeding O+ D2 items 2.1 (explainability) + 2.2
	// (source_attribution). The D2 half of the golden evidence pipeline.
	//
	// Env contract:
	//   CHORA_AI_ASSIST_COMPLETED_SUBSCRIPTION — full subscription resource or
	//     short name; default chora-governance.creation-ai-assist-completed.
	aiAssistCompletedConsumer := govevents.NewAiAssistCompletedConsumer(imdaProjector, nil)
	if jetBus != nil {
		aiAssistSub := strings.TrimSpace(os.Getenv("CHORA_AI_ASSIST_COMPLETED_SUBSCRIPTION"))
		if aiAssistSub == "" {
			aiAssistSub = "chora-governance.creation-ai-assist-completed"
		}
		log.Printf(
			"governance: AiAssistCompletedConsumer subscribing on %q (subject=%s)",
			aiAssistSub, govevents.TopicAiAssistCompleted,
		)
		if err := jetBus.Subscribe(ctx, consumerConfig(aiAssistSub, govevents.TopicAiAssistCompleted), govevents.AiAssistCompletedHandler(aiAssistCompletedConsumer)); err != nil && !errors.Is(err, context.Canceled) {
			log.Printf("governance: AiAssistCompletedSubscription exited: %v", err)
		}
	} else {
		log.Printf("governance: AiAssistCompletedConsumer wired (in-memory only; NATS_URL unset)")
	}

	// ---------------------------------------------------------------------
	// D2 transparency — WeaknessAnalyzed StreamingPull consumer (ADR-205,
	// Growth-Edge analyser graduation, CHO-1955 / WS-3).
	//
	// Subscribes to the terminal analyser event
	// chora.consumption.weakness.analyzed.v1 via the canonical subscription
	// chora-governance.consumption-weakness-analyzed. Fans each analyzed event
	// out into decision_explanation rows (N learner from the real per-edge
	// descriptor summaries + auditor + instructor from the real diagnosis with
	// model attribution) via the same imdaProjector — the D2 governance record
	// of WHAT the multimodal analyser diagnosed. Internal/auditor framing uses
	// "weakness"; the learner-facing "Growth Edge" framing lives in the A+ FE.
	//
	// Env contract:
	//   CHORA_WEAKNESS_ANALYZED_SUBSCRIPTION — full subscription resource or
	//     short name; default chora-governance.consumption-weakness-analyzed.
	weaknessAnalyzedConsumer := govevents.NewWeaknessAnalyzedConsumer(imdaProjector, nil)
	if jetBus != nil {
		weaknessSub := strings.TrimSpace(os.Getenv("CHORA_WEAKNESS_ANALYZED_SUBSCRIPTION"))
		if weaknessSub == "" {
			weaknessSub = "chora-governance.consumption-weakness-analyzed"
		}
		log.Printf(
			"governance: WeaknessAnalyzedConsumer subscribing on %q (subject=%s)",
			weaknessSub, govevents.TopicWeaknessAnalyzed,
		)
		if err := jetBus.Subscribe(ctx, consumerConfig(weaknessSub, govevents.TopicWeaknessAnalyzed), govevents.WeaknessAnalyzedHandler(weaknessAnalyzedConsumer)); err != nil && !errors.Is(err, context.Canceled) {
			log.Printf("governance: WeaknessAnalyzedSubscription exited: %v", err)
		}
	} else {
		log.Printf("governance: WeaknessAnalyzedConsumer wired (in-memory only; NATS_URL unset)")
	}

	// ---------------------------------------------------------------------
	// D4 fairness — BiasTest StreamingPull consumer (ADR-173).
	//
	// Subscribes to chora.governance.bias_test.completed.v1 via the canonical
	// subscription chora-governance.bias-test-completed. Each real deepeval
	// BiasMetric result (SUT = the MCQ-AI-Assist crew) projects into a
	// bias_test_runs row — feeding O+ D4 items 4.1 (bias_testing) + 4.3
	// (demographic_bias_testing). The D4 half of the golden evidence pipeline.
	//
	// Env contract:
	//   CHORA_BIAS_TEST_SUBSCRIPTION — full subscription resource or short
	//     name; default chora-governance.bias-test-completed.
	biasTestConsumer := govevents.NewBiasTestConsumer(imdaProjector, nil)
	if jetBus != nil {
		biasSub := strings.TrimSpace(os.Getenv("CHORA_BIAS_TEST_SUBSCRIPTION"))
		if biasSub == "" {
			biasSub = "chora-governance.bias-test-completed"
		}
		log.Printf(
			"governance: BiasTestConsumer subscribing on %q (subject=%s)",
			biasSub, govevents.TopicBiasTestCompleted,
		)
		if err := jetBus.Subscribe(ctx, consumerConfig(biasSub, govevents.TopicBiasTestCompleted), govevents.BiasTestHandler(biasTestConsumer)); err != nil && !errors.Is(err, context.Canceled) {
			log.Printf("governance: BiasTestSubscription exited: %v", err)
		}
	} else {
		log.Printf("governance: BiasTestConsumer wired (in-memory only; NATS_URL unset)")
	}

	// ---------------------------------------------------------------------
	// D3 safety_and_robustness: PolicyViolation StreamingPull consumer
	// (requirement G2, ADR-152 amendment 2026-08-07).
	//
	// Subscribes to chora.governance.policy.violation_detected.v1 via the
	// provisioned subscription
	// chora-governance.governance-policy-violation_detected. The producer is
	// chora-model-gateway: every Cloud Model Armor BLOCK at the single
	// un-bypassable LLM chokepoint (ADR-163) publishes one BINARY
	// PolicyViolationDetected, which projects into a policy_violation_log row
	// and thereby into the D3/policy_violation_log.csv of an exported O+
	// evidence pack. Without this consumer nothing drains the subscription and
	// a real refusal never becomes governance evidence.
	//
	// Env contract:
	//   CHORA_POLICY_VIOLATION_SUBSCRIPTION: full subscription resource or
	//     short name; default
	//     chora-governance.governance-policy-violation_detected.
	policyViolationConsumer := govevents.NewPolicyViolationConsumer(imdaProjector, nil)
	if jetBus != nil {
		policyViolationSub := strings.TrimSpace(os.Getenv("CHORA_POLICY_VIOLATION_SUBSCRIPTION"))
		if policyViolationSub == "" {
			policyViolationSub = "chora-governance.governance-policy-violation_detected"
		}
		log.Printf(
			"governance: PolicyViolationConsumer subscribing on %q (subject=%s)",
			policyViolationSub, govevents.TopicPolicyViolationDetected,
		)
		if err := jetBus.Subscribe(ctx, consumerConfig(policyViolationSub, govevents.TopicPolicyViolationDetected), govevents.PolicyViolationHandler(policyViolationConsumer)); err != nil && !errors.Is(err, context.Canceled) {
			log.Printf("governance: PolicyViolationSubscription exited: %v", err)
		}
	} else {
		log.Printf("governance: PolicyViolationConsumer wired (in-memory only; NATS_URL unset)")
	}

	// ---------------------------------------------------------------------
	// O+ Human-Oversight — HITL gate-requested StreamingPull consumer.
	//
	// Subscribes to chora.governance.hitl.requested.v1 (the qgen HITL
	// escalation event emitted by chora-ai-kernel-orchestrator, commit
	// a977a483) via the canonical subscription chora-governance.hitl-requested.
	// The consumer projects each event into a PENDING D4
	// (fairness_and_human_oversight) hitl_decision_log row — the
	// /api/hitl/pending source for the O+ Human-Oversight queue. The existing
	// Claim/Approve/Reject lifecycle later resolves the gate by APPENDING a
	// verdict row.
	//
	// Distinct from the AgentDecisionConsumer above (which is D1 only and
	// would NACK a D4 event). Per [[feedback-d6-resilience-first-class]]
	// Pillar 2: handler errors Nack so the bus redelivers; persistent failures
	// hit the subscription's dead_letter_policy.
	//
	// Env contract:
	//   CHORA_HITL_REQUESTED_SUBSCRIPTION — full subscription resource or
	//     short name; default chora-governance.hitl-requested.
	hitlRequestedConsumer := govevents.NewHITLRequestedConsumer(imdaProjector, nil)
	if jetBus != nil {
		hitlRequestedSub := strings.TrimSpace(os.Getenv("CHORA_HITL_REQUESTED_SUBSCRIPTION"))
		if hitlRequestedSub == "" {
			hitlRequestedSub = "chora-governance.hitl-requested"
		}
		log.Printf(
			"governance: HITLRequestedConsumer subscribing on %q (subject=%s)",
			hitlRequestedSub, govevents.TopicHITLRequested,
		)
		if err := jetBus.Subscribe(ctx, consumerConfig(hitlRequestedSub, govevents.TopicHITLRequested), govevents.HITLRequestedHandler(hitlRequestedConsumer)); err != nil && !errors.Is(err, context.Canceled) {
			log.Printf("governance: HITLRequestedSubscription exited: %v", err)
		}
	} else {
		log.Printf("governance: HITLRequestedConsumer wired (in-memory only; NATS_URL unset)")
	}

	// ---------------------------------------------------------------------
	// H+ Transaction-History audit subscribers (logical-growing-cat plan,
	// Agent A4 — 2026-05-26). Three new topics emitted by chora-payments:
	//
	//   chora.governance.audit.tenant_admin_viewed_payments.v1
	//   chora.governance.audit.cross_tenant_payments_viewed.v1
	//   chora.governance.audit.refund_issued.v1
	//
	// All three append a hash-chained row into audit_log via the existing
	// auditRepo port — same persistence + tamper-evidence guarantees as
	// the gatekeeper-decision path. Provides IMDA D1 (accountability)
	// evidence for H+ tx-history admin reads + cross-tenant
	// PLATFORM_OPERATOR access + refund issuance.
	//
	// Env contract:
	//   CHORA_AUDIT_PAYMENTS_TENANT_ADMIN_SUBSCRIPTION
	//     — default chora-governance.audit-tenant-admin-viewed-payments
	//   CHORA_AUDIT_PAYMENTS_CROSS_TENANT_SUBSCRIPTION
	//     — default chora-governance.audit-cross-tenant-payments-viewed
	//   CHORA_AUDIT_PAYMENTS_REFUND_SUBSCRIPTION
	//     — default chora-governance.audit-refund-issued
	//
	// Per [[feedback-d6-resilience-first-class]] Pillar 2: handler errors
	// Nack so the bus redelivers; persistent failures hit DLQ after
	// max_delivery_attempts.
	auditPaymentsSubscriber := govevents.NewAuditPaymentsSubscriber(auditRepo, nil)
	if jetBus != nil {
		// One durable consumer per subject — each binds to its own
		// subscription name.
		auditPaymentsBindings := []struct {
			envKey     string
			defaultSub string
			subject    string
		}{
			{
				"CHORA_AUDIT_PAYMENTS_TENANT_ADMIN_SUBSCRIPTION",
				"chora-governance.audit-tenant-admin-viewed-payments",
				govevents.TopicTenantAdminViewedPayments,
			},
			{
				"CHORA_AUDIT_PAYMENTS_CROSS_TENANT_SUBSCRIPTION",
				"chora-governance.audit-cross-tenant-payments-viewed",
				govevents.TopicCrossTenantPaymentsViewed,
			},
			{
				"CHORA_AUDIT_PAYMENTS_REFUND_SUBSCRIPTION",
				"chora-governance.audit-refund-issued",
				govevents.TopicRefundIssued,
			},
		}
		for _, b := range auditPaymentsBindings {
			subscription := strings.TrimSpace(os.Getenv(b.envKey))
			if subscription == "" {
				subscription = b.defaultSub
			}
			log.Printf(
				"governance: AuditPaymentsSubscriber subscribing on %q (subject=%s)",
				subscription, b.subject,
			)
			if err := jetBus.Subscribe(ctx, consumerConfig(subscription, b.subject), govevents.AuditPaymentsHandler(auditPaymentsSubscriber, b.subject)); err != nil && !errors.Is(err, context.Canceled) {
				log.Printf("governance: AuditPaymentsSubscription (%s) exited: %v", b.subject, err)
			}
		}
	} else {
		log.Printf("governance: AuditPaymentsSubscriber wired (in-memory only; NATS_URL unset)")
	}

	// External-egress audit subscriber (CHO-2245; ADR-231 Amendment 2026-07-17,
	// Open Question 3 closed). ONE topic emitted by chora-model-gateway (the LLM
	// chokepoint) as BINARY proto:
	//
	//   chora.governance.audit.external_egress.v1
	//
	// Appends a hash-chained audit_log row via the same auditRepo port as the
	// payments-audit path — IMDA D2 transparency + D1 accountability evidence for
	// every learner-triggered grounded web egress.
	//
	// Env contract:
	//   CHORA_AUDIT_EGRESS_SUBSCRIPTION
	//     — default chora-governance.audit-external-egress
	//
	// Per [[feedback-d6-resilience-first-class]] Pillar 2: handler errors Nack so
	// the bus redelivers; persistent failures hit the DLQ after max_delivery_attempts.
	auditEgressSubscriber := govevents.NewAuditEgressSubscriber(auditRepo, nil)
	if jetBus != nil {
		subscription := strings.TrimSpace(os.Getenv("CHORA_AUDIT_EGRESS_SUBSCRIPTION"))
		if subscription == "" {
			subscription = "chora-governance.audit-external-egress"
		}
		log.Printf(
			"governance: AuditEgressSubscriber subscribing on %q (subject=%s)",
			subscription, govevents.TopicExternalEgressAudited,
		)
		if err := jetBus.Subscribe(ctx, consumerConfig(subscription, govevents.TopicExternalEgressAudited), govevents.AuditEgressHandler(auditEgressSubscriber)); err != nil && !errors.Is(err, context.Canceled) {
			log.Printf("governance: ExternalEgressSubscription exited: %v", err)
		}
	} else {
		log.Printf("governance: AuditEgressSubscriber wired (in-memory only; NATS_URL unset)")
	}

	// Shared IMDA-evidence subscriber (CHO-2260). ONE topic emitted as BINARY
	// proto by every producing domain (chora-observability Familiar-Growth lane
	// CHO-2257, chora-identity KYC/role-grant/federation, ...):
	//
	//   chora.governance.evidence.recorded.v1
	//
	// Appends a hash-chained audit_log row via the same auditRepo port as the
	// payments-/egress-audit paths — the IMDA D1 accountability + D2 transparency
	// evidence trail. Sink rationale: the generic EvidenceRecorded wire carries
	// none of the structured fields the D1/D2 evidence projector requires
	// (agent_id/decision_id/decision_type/owner_gcid), so it lands in audit_log
	// (kind-agnostic, append-only, hash-chained) rather than the projector — see
	// the internal/adapter/events/evidence_recorded.go header + CHO-2260.
	//
	// Env contract:
	//   CHORA_EVIDENCE_RECORDED_SUBSCRIPTION
	//     — default chora-governance.evidence-recorded
	//
	// Per [[feedback-d6-resilience-first-class]] Pillar 2: handler errors Nack so
	// the bus redelivers; persistent failures hit the DLQ after max_delivery_attempts.
	evidenceRecordedSubscriber := govevents.NewEvidenceRecordedSubscriber(auditRepo, nil)
	if jetBus != nil {
		subscription := strings.TrimSpace(os.Getenv("CHORA_EVIDENCE_RECORDED_SUBSCRIPTION"))
		if subscription == "" {
			subscription = "chora-governance.evidence-recorded"
		}
		log.Printf(
			"governance: EvidenceRecordedSubscriber subscribing on %q (subject=%s)",
			subscription, govevents.TopicEvidenceRecorded,
		)
		if err := jetBus.Subscribe(ctx, consumerConfig(subscription, govevents.TopicEvidenceRecorded), govevents.EvidenceRecordedHandler(evidenceRecordedSubscriber)); err != nil && !errors.Is(err, context.Canceled) {
			log.Printf("governance: EvidenceRecordedSubscription exited: %v", err)
		}
	} else {
		log.Printf("governance: EvidenceRecordedSubscriber wired (in-memory only; NATS_URL unset)")
	}

	// Phase B (atomic-napping-spring.md O+ hydration plan) — load
	// config/imda_rubric.yaml + wire rubric resolver + IMDA dashboard service.
	// Both values are nil on YAML load failure; the HTTP router degrades to
	// 503 on /api/hitl/pending + /api/imda/dimensions/{name}/rubric.
	rubricResolver, dashboardSvc := bootstrapRubric(imdaRepo, evidenceRepo)

	handler := httpadapter.NewRouter(httpadapter.Deps{
		PolicyRepo:        policyRepo,
		AuditRepo:         auditRepo,
		IMDARepo:          imdaRepo,
		Evaluator:         evaluator,
		EvidenceRepo:      evidenceRepo,
		Projector:         imdaProjector,
		Exporter:          exporter,
		RubricResolver:    rubricResolver,
		DashboardSvc:      dashboardSvc,
		AuditPublisher:    auditPublisher,
		AITransparencySvc: aiTransparencySvc,
	})

	srv := &http.Server{
		Addr:              ":" + port,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	go func() {
		log.Printf("service=%s version=%s listening on %s", serviceName, version, srv.Addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("server error: %v", err)
		}
	}()

	// gRPC server :9090 (Wave-1 G-FULL per docs/m13/grpc-mass-remediation-2026-05-16.md)
	grpcPort := strings.TrimSpace(os.Getenv("CHORA_GRPC_PORT"))
	if grpcPort == "" {
		grpcPort = strings.TrimSpace(os.Getenv("GRPC_PORT"))
	}
	if grpcPort == "" {
		grpcPort = "9090"
	}
	grpcLis, err := net.Listen("tcp", ":"+grpcPort)
	if err != nil {
		log.Fatalf("governance: gRPC net.Listen :%s: %v", grpcPort, err)
	}
	grpcSrv := grpc.NewServer()
	registerGovernanceGRPC(grpcSrv, policyRepo, auditRepo, imdaRepo, evaluator, complianceGen)

	go func() {
		log.Printf("service=%s grpc listening on :%s (Governance + Health bound)", serviceName, grpcPort)
		if err := grpcSrv.Serve(grpcLis); err != nil && err != grpc.ErrServerStopped {
			log.Fatalf("governance: gRPC Serve: %v", err)
		}
	}()

	<-ctx.Done()
	log.Printf("shutting down...")

	grpcShutdownDone := make(chan struct{})
	go func() {
		grpcSrv.GracefulStop()
		close(grpcShutdownDone)
	}()
	select {
	case <-grpcShutdownDone:
		log.Printf("grpc server drained")
	case <-time.After(10 * time.Second):
		log.Printf("grpc graceful-stop deadline exceeded — forcing stop")
		grpcSrv.Stop()
	}

	drainCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(drainCtx); err != nil {
		log.Printf("server shutdown error: %v", err)
	}
}

// registerGovernanceGRPC wires the Governance + Health gRPC servers onto srv.
// Extracted as a top-level helper so cmd/server/grpc_test.go can drive the
// exact same registration code-path the prod entrypoint takes.
func registerGovernanceGRPC(
	srv *grpc.Server,
	policyRepo policy.Repository,
	auditRepo audit.Repository,
	imdaRepo imda.Repository,
	evaluator *gatekeeper.Evaluator,
	complianceGen *compliance.Generator,
) {
	governanceSrv := grpcadapter.NewGovernanceServer(
		policyRepo,
		auditRepo,
		imdaRepo,
		evaluator,
		complianceGen,
	)
	governancev1.RegisterGovernanceServer(srv, governanceSrv)

	healthSrv := healthgrpc.NewServer()
	healthpb.RegisterHealthServer(srv, healthSrv)
	healthSrv.SetServingStatus("", healthpb.HealthCheckResponse_SERVING)
	healthSrv.SetServingStatus("chora.services.governance.v1.Governance", healthpb.HealthCheckResponse_SERVING)
}
