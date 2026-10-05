package evidence

import (
	"testing"
	"time"
)

// An evidence row must record WHEN THE EVENT HAPPENED, not when the projector
// got round to writing it.
//
// Found 2026-08-14 running the G2 acceptance: 54 policy violations spanning
// 2026-08-08 to 2026-08-13 all landed with detected_at 17:33:23Z, the second the
// consumer drained the backlog. The exported D3 CSV therefore tells an auditor
// that 54 refusals happened inside one second, which is the wrong conclusion
// from the evidence the pack exists to carry. Every params-based constructor
// stamped time.Now() and no Params struct had a field to say otherwise.
//
// Scope note: the six CircuitBreaker/Quarantine call sites are deliberately NOT
// covered here. Those are state TRANSITIONS this service performs itself, so
// their transition instant genuinely is now(); they take no event params and
// project no incoming event.
const (
	evTimeSkew = 2 * time.Second
)

func eventInstant() time.Time { return time.Date(2026, 8, 8, 10, 47, 20, 0, time.UTC) }

// assertHonoured checks a constructor used the supplied event time verbatim.
func assertHonoured(t *testing.T, what string, got time.Time) {
	t.Helper()
	if !got.Equal(eventInstant()) {
		t.Errorf("%s = %s, want the supplied event time %s (an ingest timestamp misdates the evidence)",
			what, got.Format(time.RFC3339Nano), eventInstant().Format(time.RFC3339Nano))
	}
}

// assertDefaultsToNow checks a zero event time still yields a sane timestamp,
// so an un-migrated caller keeps working.
func assertDefaultsToNow(t *testing.T, what string, got time.Time) {
	t.Helper()
	if got.IsZero() {
		t.Fatalf("%s is zero; a missing event time must fall back to now, not to the zero value", what)
	}
	if d := time.Since(got); d < -evTimeSkew || d > evTimeSkew {
		t.Errorf("%s = %s, want ~now on a zero event time", what, got.Format(time.RFC3339Nano))
	}
}

func TestEventTime_HonouredByEveryProjectedConstructor(t *testing.T) {
	at := eventInstant()

	a, err := NewAccountabilityEvidence(AccountabilityParams{
		EventID: "e1", TenantID: "t1", AgentID: "a1", OwnerGcid: "g1", DecisionID: "d1", DecisionType: "x",
		OccurredAt: at,
	})
	if err != nil {
		t.Fatalf("accountability: %v", err)
	}
	assertHonoured(t, "AccountabilityEvidence.RecordedAt", a.RecordedAt)

	mc, err := NewModelCard(ModelCardParams{
		EventID: "e2", TenantID: "t1", ModelID: "m1", ModelVersion: "v1", CardMD: "#",
		OccurredAt: at,
	})
	if err != nil {
		t.Fatalf("model card: %v", err)
	}
	assertHonoured(t, "ModelCard.RegisteredAt", mc.RegisteredAt)

	dc, err := NewDataCard(DataCardParams{
		EventID: "e3", TenantID: "t1", DatasetID: "ds1", DatasetVersion: "v1", CardMD: "#",
		OccurredAt: at,
	})
	if err != nil {
		t.Fatalf("data card: %v", err)
	}
	assertHonoured(t, "DataCard.RegisteredAt", dc.RegisteredAt)

	de, err := NewDecisionExplanation(DecisionExplanationParams{
		EventID: "e4", TenantID: "t1", DecisionID: "d1", Audience: AudienceAuditor,
		ExplanationMD: "why", OccurredAt: at,
	})
	if err != nil {
		t.Fatalf("decision explanation: %v", err)
	}
	assertHonoured(t, "DecisionExplanation.GeneratedAt", de.GeneratedAt)

	rt, err := NewRedTeamRun(RedTeamRunParams{
		EventID: "e5", TenantID: "t1", RunID: "r1", AgentID: "a1", Verdict: "pass",
		OccurredAt: at,
	})
	if err != nil {
		t.Fatalf("red team: %v", err)
	}
	assertHonoured(t, "RedTeamRun.RunAt", rt.RunAt)

	er, err := NewEvalRun(EvalRunParams{
		EventID: "e6", TenantID: "t1", RunID: "r1", AgentID: "a1", EvalSuite: "s1",
		OccurredAt: at,
	})
	if err != nil {
		t.Fatalf("eval run: %v", err)
	}
	assertHonoured(t, "EvalRun.RunAt", er.RunAt)

	ca, err := NewCostAnomaly(CostAnomalyParams{
		EventID: "e7", TenantID: "t1", AnomalyID: "an1", AgentID: "a1",
		OccurredAt: at,
	})
	if err != nil {
		t.Fatalf("cost anomaly: %v", err)
	}
	assertHonoured(t, "CostAnomaly.RecordedAt", ca.RecordedAt)

	bt, err := NewBiasTestRun(BiasTestRunParams{
		EventID: "e8", TenantID: "t1", RunID: "r1", AgentID: "a1",
		ProtectedAttribute: "demographic", TestType: "deepeval_bias", OccurredAt: at,
	})
	if err != nil {
		t.Fatalf("bias run: %v", err)
	}
	assertHonoured(t, "BiasTestRun.RunAt", bt.RunAt)

	pv, err := NewPolicyViolation(PolicyViolationParams{
		EventID: "e9", TenantID: "t1", AgentID: "a1", PolicyName: "p", Severity: "high",
		Detector: "MODEL_ARMOR", OccurredAt: at,
	})
	if err != nil {
		t.Fatalf("policy violation: %v", err)
	}
	assertHonoured(t, "PolicyViolation.DetectedAt", pv.DetectedAt)
}

// The two HITL constructors are separate because their params differ.
func TestEventTime_HonouredByHITLConstructors(t *testing.T) {
	at := eventInstant()

	hd, err := NewHITLDecision(HITLDecisionParams{
		EventID: "h1", TenantID: "t1", DecisionID: "d1", RunID: "r1", OperatorGcid: "g1",
		Decision: HitlApprove, AutonomyLevel: AutonomyHitlL1, OccurredAt: at,
	})
	if err != nil {
		t.Fatalf("hitl decision: %v", err)
	}
	assertHonoured(t, "HITLDecision.DecidedAt", hd.DecidedAt)

	ph, err := NewPendingHITLDecision(PendingHITLDecisionParams{
		EventID: "h2", TenantID: "t1", DecisionID: "d2", RunID: "r2",
		AutonomyLevel: AutonomyHitlL1, OccurredAt: at,
	})
	if err != nil {
		t.Fatalf("pending hitl: %v", err)
	}
	assertHonoured(t, "PendingHITLDecision.DecidedAt (waiting_since)", ph.DecidedAt)
}

// A caller that supplies no event time must keep working: the fix is additive,
// so every existing call site stays valid and falls back to now.
func TestEventTime_ZeroFallsBackToNow(t *testing.T) {
	a, err := NewAccountabilityEvidence(AccountabilityParams{
		EventID: "z1", TenantID: "t1", AgentID: "a1", OwnerGcid: "g1", DecisionID: "d1", DecisionType: "x",
	})
	if err != nil {
		t.Fatalf("accountability: %v", err)
	}
	assertDefaultsToNow(t, "AccountabilityEvidence.RecordedAt", a.RecordedAt)

	pv, err := NewPolicyViolation(PolicyViolationParams{
		EventID: "z2", TenantID: "t1", AgentID: "a1", PolicyName: "p", Severity: "high",
		Detector: "MODEL_ARMOR",
	})
	if err != nil {
		t.Fatalf("policy violation: %v", err)
	}
	assertDefaultsToNow(t, "PolicyViolation.DetectedAt", pv.DetectedAt)

	er, err := NewEvalRun(EvalRunParams{
		EventID: "z3", TenantID: "t1", RunID: "r1", AgentID: "a1", EvalSuite: "s1",
	})
	if err != nil {
		t.Fatalf("eval run: %v", err)
	}
	assertDefaultsToNow(t, "EvalRun.RunAt", er.RunAt)
}

// A supplied non-UTC event time must be normalised, so two rows from the same
// instant compare equal regardless of the producer's zone.
func TestEventTime_NormalisedToUTC(t *testing.T) {
	zone := time.FixedZone("SGT", 8*3600)
	local := eventInstant().In(zone)

	pv, err := NewPolicyViolation(PolicyViolationParams{
		EventID: "u1", TenantID: "t1", AgentID: "a1", PolicyName: "p", Severity: "high",
		Detector: "MODEL_ARMOR", OccurredAt: local,
	})
	if err != nil {
		t.Fatalf("policy violation: %v", err)
	}
	if got := pv.DetectedAt.Location(); got != time.UTC {
		t.Errorf("DetectedAt location = %v, want UTC", got)
	}
	assertHonoured(t, "PolicyViolation.DetectedAt (from SGT)", pv.DetectedAt)
}
