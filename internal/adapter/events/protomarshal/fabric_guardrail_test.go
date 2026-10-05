// fabric_guardrail_test — the Flag-1 CI guardrail from the 2026-07-01
// event-fabric audit, ported to chora-governance. It is the durable regression
// gate that WOULD HAVE CAUGHT the kg_hexagon_fog class of bug: a topic that
// chora-governance PRODUCES and that is bound to a BINARY Pub/Sub Schema
// Registry schema, but for which protomarshal has NO encoder case — so the
// outbox silently JSON-falls-back and the binary schema rejects every publish →
// dead-letter forever.
//
// Data sources (deployed-reality precedence — CLAUDE.md source hierarchy #1):
//
//   - "bound to a binary schema" = a governance topic in the m10-data-plane
//     terraform `local.pubsub_topics` map MINUS `local.schemaless_topics`. That
//     terraform IS what provisions the Schema Registry bindings that make binary
//     encoding mandatory, so it is the authoritative source — NOT
//     chora-infra/topics/topics.yaml, which is a stale partial catalogue.
//
//   - "chora-governance produces it" = the topic string literal appears in the
//     service's Go source OUTSIDE the encoder (protomarshal), the decoder
//     (protodecode), the consume-only surfaces (any file that declares a
//     *Subscriber / *Consumer struct — e.g. audit_payments.go consumes the
//     cross_tenant_payments_viewed audit that chora-payments/chora-tenancy
//     PRODUCE) and any direct-codec surface (a file that calls proto.Marshal /
//     proto.Unmarshal encodes its own bytes and bypasses protomarshal) and the
//     tests. Scoping to emitted topics stops the guardrail false-failing on the
//     governance-domain topics the service merely SUBSCRIBES to
//     (bias_test.completed / hitl.requested / audit.*_viewed_payments / …).
//
// NOTE (per the audit): this is a CI TEST only. encodeOutboxPayload MUST NOT be
// made runtime-fail-loud — 57 topics platform-wide legitimately publish
// schemaless JSON, and a runtime blanket fail-loud would break them.
package protomarshal_test

import (
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"

	"github.com/apollo-chora/chora-governance/internal/adapter/events/protomarshal"
)

// fgServiceDir is the service whose produced topics this guardrail scopes to.
const fgServiceDir = "chora-governance"

// fgTopicRe matches a fully-qualified chora.governance topic that is a
// STANDALONE double-quoted string literal (Go source constant / TF map key /
// list element). Requiring the surrounding quotes distinguishes a real literal
// from a topic embedded in a larger log-format string.
var fgTopicRe = regexp.MustCompile(`"(chora\.governance\.[a-z0-9_.]+\.v[0-9]+)"`)

// fgTopicLiterals returns the set of governance topics quoted as standalone
// string literals in s (capture group 1 of each match).
func fgTopicLiterals(s string) map[string]bool {
	out := map[string]bool{}
	for _, m := range fgTopicRe.FindAllStringSubmatch(s, -1) {
		out[m[1]] = true
	}
	return out
}

// fgConsumeSurfaceRe matches a file that declares an inbound subscriber /
// consumer aggregate — a consume-only surface whose topic literals are
// SUBSCRIBED to, not produced.
var fgConsumeSurfaceRe = regexp.MustCompile(`type\s+\w*(Subscriber|Consumer)\s+struct`)

// fgDirectCodecRe matches a file that hand-marshals protobuf itself
// (proto.Marshal / proto.Unmarshal) — either a decoder or a producer that
// encodes its own binary bytes and therefore BYPASSES protomarshal. Neither is
// in scope for "does protomarshal have an encoder for this topic".
var fgDirectCodecRe = regexp.MustCompile(`proto\.(Marshal|Unmarshal)\(`)

// fgRepoRoot walks up from this test's source file (stable at build time,
// independent of the test's working directory) to the monorepo root — the
// directory holding both chora-infra/ and services/<fgServiceDir>/.
//
// In the standalone chora-governance repo the monorepo layout is absent, so
// the guardrail SKIPS (the binary-bound topic set is derived from the
// chora-infra terraform, which is not part of this repository). The
// protomarshal encoder coverage is still pinned by protomarshal_test.go and
// wire_compat_test.go.
func fgRepoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller(0) failed — cannot locate repo root")
	}
	dir := filepath.Dir(file)
	for i := 0; i < 15; i++ {
		infra := filepath.Join(dir, "chora-infra", "terraform", "modules", "m10-data-plane", "main.tf")
		svc := filepath.Join(dir, "services", fgServiceDir)
		if fgFileExists(infra) && fgDirExists(svc) {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Skipf("monorepo root (chora-infra + services/%s) not found walking up from %s — guardrail is monorepo-only", fgServiceDir, file)
	return ""
}

func fgFileExists(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && !fi.IsDir()
}

func fgDirExists(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.IsDir()
}

// fgBinaryBoundTopics returns the set of governance topics bound to a binary
// Schema Registry schema = every governance topic literal in the m10-data-plane
// terraform MINUS the ones in local.schemaless_topics.
func fgBinaryBoundTopics(t *testing.T, root string) map[string]bool {
	t.Helper()
	tfPath := filepath.Join(root, "chora-infra", "terraform", "modules", "m10-data-plane", "main.tf")
	raw, err := os.ReadFile(tfPath)
	if err != nil {
		t.Fatalf("read m10-data-plane main.tf: %v", err)
	}
	tf := string(raw)

	all := fgTopicLiterals(tf)

	// Extract the schemaless_topics = toset([ ... ]) block and remove its
	// governance members — those intentionally publish schemaless JSON.
	schemaless := map[string]bool{}
	if start := strings.Index(tf, "schemaless_topics = toset(["); start >= 0 {
		rest := tf[start:]
		if end := strings.Index(rest, "])"); end >= 0 {
			schemaless = fgTopicLiterals(rest[:end])
		} else {
			t.Fatal("schemaless_topics block has no closing '])' — TF parse assumption broken")
		}
	} else {
		t.Fatal("could not locate local.schemaless_topics in main.tf — TF parse assumption broken")
	}

	bound := map[string]bool{}
	for topic := range all {
		if !schemaless[topic] {
			bound[topic] = true
		}
	}
	if len(bound) == 0 {
		t.Fatal("0 binary-bound governance topics parsed from TF — parse is broken (would make the guardrail vacuously green)")
	}
	return bound
}

// fgProducedTopics scans the service's Go source for governance topic string
// literals, EXCLUDING the encoder (protomarshal — the code under test), the
// decoder (protodecode), the consume-only surfaces (files declaring a
// *Subscriber / *Consumer struct), the direct-codec surfaces (files calling
// proto.Marshal / proto.Unmarshal — they bypass protomarshal) and test files.
// What remains is the set of topics the service actually emits via the
// protomarshal-routed outbox Publisher.
func fgProducedTopics(t *testing.T, root string) map[string]bool {
	t.Helper()
	svcRoot := filepath.Join(root, "services", fgServiceDir)
	produced := map[string]bool{}
	err := filepath.WalkDir(svcRoot, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		// Encoder / decoder directories are not producers.
		if strings.Contains(path, string(filepath.Separator)+"protomarshal"+string(filepath.Separator)) ||
			strings.Contains(path, string(filepath.Separator)+"protodecode"+string(filepath.Separator)) {
			return nil
		}
		raw, rerr := os.ReadFile(path)
		if rerr != nil {
			return rerr
		}
		src := string(raw)
		// Consume-only surfaces + direct-codec surfaces do not count as
		// protomarshal-routed producers.
		if fgConsumeSurfaceRe.MatchString(src) || fgDirectCodecRe.MatchString(src) {
			return nil
		}
		for topic := range fgTopicLiterals(src) {
			produced[topic] = true
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk services/%s source: %v", fgServiceDir, err)
	}
	if len(produced) == 0 {
		t.Fatalf("0 produced governance topics found in services/%s — source scan is broken (would make the guardrail vacuously green)", fgServiceDir)
	}
	return produced
}

// TestFabricGuardrail_EveryProducedBinaryTopicHasEncoder is the Flag-1 gate.
// For every governance topic that chora-governance PRODUCES and that is bound
// to a binary Schema Registry schema, MarshalPayload MUST route to a real
// encoder (not ErrUnsupportedTopic → JSON fallback → schema-reject →
// dead-letter).
func TestFabricGuardrail_EveryProducedBinaryTopicHasEncoder(t *testing.T) {
	root := fgRepoRoot(t)
	binaryBound := fgBinaryBoundTopics(t, root)
	produced := fgProducedTopics(t, root)
	env := fixedEnvelope()
	// An empty payload routes to the encoder with every field proto3-default
	// omitted — enough to prove the switch has a case (no type coercion).
	empty := map[string]any{}

	checked := 0
	for topic := range binaryBound {
		if !produced[topic] {
			// Declared-only scaffolding (binary schema, no producer literal yet)
			// OR a topic the service only subscribes to.
			t.Logf("declared-only (binary schema, no chora-governance producer literal): %s", topic)
			continue
		}
		_, err := protomarshal.MarshalPayload(topic, env, empty)
		if protomarshal.IsUnsupportedTopic(err) {
			t.Errorf("topic %q is PRODUCED by chora-governance and bound to a binary Pub/Sub "+
				"schema, but protomarshal has NO encoder case → JSON fallback → Schema "+
				"Registry rejects → dead-letter (kg_hexagon_fog class). Add a MarshalPayload case.", topic)
			continue
		}
		if err != nil {
			t.Errorf("topic %q: MarshalPayload returned a non-routing error: %v", topic, err)
			continue
		}
		checked++
	}
	if checked == 0 {
		t.Fatal("guardrail asserted 0 produced binary-bound topics — the TF parse or the source scan is broken")
	}
	t.Logf("Flag-1 guardrail: %d produced binary-bound governance topics all have encoders", checked)
}
