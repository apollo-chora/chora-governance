// audit_egress_sample_test.go — validate-message sample generator (CHO-2245 D4).
//
// Emits a base64 of a REAL emitter-encoded ExternalEgressAudited (the same
// BINARY proto chora-model-gateway marshals via governancev1.ExternalEgressAudited
// — wire-compatible with the flat Schema-Registry schema whose nested Envelope /
// Timestamp inline the identical field numbers). The provisioning runbook pipes
// this into:
//
//	gcloud pubsub schemas validate-message \
//	  --schema-name=chora-governance-audit-external_egress-v1 \
//	  --message-encoding=BINARY --message="<base64>"
//
// to prove the schema accepts a real emitter payload BEFORE the topic binds.
//
// Run:
//
//	go test ./internal/adapter/events/ -run TestGenerateEgressValidateSample -v
package events_test

import (
	"encoding/base64"
	"testing"

	governancev1 "github.com/apollo-chora/chora-contracts/gen/go/chora/governance/v1"
)

func TestGenerateEgressValidateSample(t *testing.T) {
	// A representative DENIED egress (Armor pre-block, zero citations) — the
	// worst-case shape carrying every optional string, so validation exercises
	// the widest field set. egressPayload builds the emitter-shaped envelope.
	payload := egressPayload(governancev1.AuditResult_AUDIT_RESULT_DENIED)
	payload.DenialReason = "model_armor_pre_block"
	payload.CitationCount = 0
	payload.ModelArmorVerdictPre = "BLOCK"
	payload.ModelArmorVerdictPost = ""

	b := mustMarshal(t, payload)
	t.Logf("EXTERNAL_EGRESS_VALIDATE_SAMPLE_BASE64=%s", base64.StdEncoding.EncodeToString(b))
}
