// helpers_internal_test.go — INTERNAL (package pg) coverage tail for the
// unexported pure helpers: validateTenantIDLiteral, effectFromMode /
// modeFromEffect, jsonbArg, decodeMap, decodeLocales, hitlNoteFromEditPayload,
// isUniqueViolation + contains.
package pg

import (
	"errors"
	"testing"

	"github.com/apollo-chora/chora-governance/internal/domain/evidence"
	"github.com/apollo-chora/chora-governance/internal/domain/policy"
)

func TestInternal_ValidateTenantIDLiteral_Branches(t *testing.T) {
	t.Parallel()
	if err := validateTenantIDLiteral(""); err == nil {
		t.Error("empty id should error")
	}
	if err := validateTenantIDLiteral("bad;DROP"); err == nil {
		t.Error("forbidden char should error")
	}
	if err := validateTenantIDLiteral("01970000-0000-7000-8000-0000000000a1"); err != nil {
		t.Errorf("uuid should pass: %v", err)
	}
}

func TestInternal_EffectAndModeConverters(t *testing.T) {
	t.Parallel()
	if effectFromMode(policy.ModeDeny) != "denied" {
		t.Error("deny → denied")
	}
	if effectFromMode(policy.ModeAllow) != "permitted" {
		t.Error("allow → permitted")
	}
	if effectFromMode(policy.ModeWarn) != "permitted" {
		t.Error("warn → permitted")
	}
	if effectFromMode(policy.EnforcementMode("bogus")) != "permitted" {
		t.Error("unknown mode → permitted")
	}
	if modeFromEffect("denied") != policy.ModeDeny {
		t.Error("denied → ModeDeny")
	}
	if modeFromEffect("allowed") != policy.ModeAllow {
		t.Error("allowed → ModeAllow")
	}
	if modeFromEffect("") != policy.ModeAllow {
		t.Error("empty → ModeAllow")
	}
}

func TestInternal_JsonbArgAndDecodeMap(t *testing.T) {
	t.Parallel()
	if jsonbArg(nil) != "{}" {
		t.Error("nil map → {}")
	}
	if jsonbArg(map[string]any{}) != "{}" {
		t.Error("empty map → {}")
	}
	if got := jsonbArg(map[string]any{"a": "b"}); got != `{"a":"b"}` {
		t.Errorf("map → %q", got)
	}

	if m := decodeMap(""); len(m) != 0 {
		t.Error("empty → empty map")
	}
	if m := decodeMap("{}"); len(m) != 0 {
		t.Error("{} → empty map")
	}
	if m := decodeMap("not json"); len(m) != 0 {
		t.Error("invalid → empty map (no panic)")
	}
	if m := decodeMap(`{"k":"v"}`); m["k"] != "v" {
		t.Errorf("valid → %v", m)
	}
}

func TestInternal_HitlNoteFromEditPayload_Branches(t *testing.T) {
	t.Parallel()
	if hitlNoteFromEditPayload(nil) != "" {
		t.Error("nil map → empty")
	}
	if hitlNoteFromEditPayload(map[string]any{evidence.NoteEditPayloadKey: "a note"}) != "a note" {
		t.Error("string note should be returned")
	}
	if hitlNoteFromEditPayload(map[string]any{evidence.NoteEditPayloadKey: 42}) != "" {
		t.Error("non-string note → empty")
	}
	if hitlNoteFromEditPayload(map[string]any{"other": "x"}) != "" {
		t.Error("missing key → empty")
	}
}

func TestInternal_IsUniqueViolation(t *testing.T) {
	t.Parallel()
	if isUniqueViolation(nil) {
		t.Error("nil → false")
	}
	if !isUniqueViolation(errors.New(`SQLSTATE 23505 duplicate key value violates unique constraint "event_id"`)) {
		t.Error("23505 → true")
	}
	if !isUniqueViolation(errors.New("duplicate key value violates unique constraint")) {
		t.Error("duplicate-key message → true")
	}
	if isUniqueViolation(errors.New("connection refused")) {
		t.Error("other error → false")
	}
	_ = contains("abc", "") // empty needle is always contained
	if !contains("abc", "b") || contains("abc", "z") {
		t.Error("contains mismatch")
	}
}
