// tail_internal_test.go — INTERNAL (package protomarshal) unit tests for the
// field encoders + loose-typed coercion helpers, driving every branch of
// stringField / enumField / int64Field / boolField / timestampField /
// repeatedStringField / asInt32 / asInt64 / asTime / stringSlice, plus
// encodeEnvelope's skip branches.
package protomarshal

import (
	"errors"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protowire"
)

func TestInternal_FieldEncoders_Branches(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC()

	cases := []struct {
		name    string
		key     string
		payload map[string]any
		encode  func(fe *fieldEncoder)
		wantErr bool
	}{
		{"string ok", "s", map[string]any{"s": "hello"}, func(fe *fieldEncoder) { fe.stringField(1, "s") }, false},
		{"string empty skipped", "s", map[string]any{"s": ""}, func(fe *fieldEncoder) { fe.stringField(1, "s") }, false},
		{"string missing", "s", map[string]any{}, func(fe *fieldEncoder) { fe.stringField(1, "s") }, false},
		{"string wrong type", "s", map[string]any{"s": 7}, func(fe *fieldEncoder) { fe.stringField(1, "s") }, true},

		{"enum nil value", "e", map[string]any{"e": nil}, func(fe *fieldEncoder) { fe.enumField(2, "e") }, true},
		{"enum ok", "e", map[string]any{"e": 2}, func(fe *fieldEncoder) { fe.enumField(2, "e") }, false},
		{"enum zero skipped", "e", map[string]any{"e": 0}, func(fe *fieldEncoder) { fe.enumField(2, "e") }, false},
		{"enum float truncates", "e", map[string]any{"e": 1.5}, func(fe *fieldEncoder) { fe.enumField(2, "e") }, false},
		{"enum string bad", "e", map[string]any{"e": "x"}, func(fe *fieldEncoder) { fe.enumField(2, "e") }, true},

		{"int64 ok", "i", map[string]any{"i": int64(9)}, func(fe *fieldEncoder) { fe.int64Field(3, "i") }, false},
		{"int64 zero skipped", "i", map[string]any{"i": 0}, func(fe *fieldEncoder) { fe.int64Field(3, "i") }, false},
		{"int64 bad", "i", map[string]any{"i": "x"}, func(fe *fieldEncoder) { fe.int64Field(3, "i") }, true},

		{"bool ok", "b", map[string]any{"b": true}, func(fe *fieldEncoder) { fe.boolField(4, "b") }, false},
		{"bool false skipped", "b", map[string]any{"b": false}, func(fe *fieldEncoder) { fe.boolField(4, "b") }, false},
		{"bool bad", "b", map[string]any{"b": "yes"}, func(fe *fieldEncoder) { fe.boolField(4, "b") }, true},

		{"ts ok", "t", map[string]any{"t": now}, func(fe *fieldEncoder) { fe.timestampField(5, "t") }, false},
		{"ts missing", "t", map[string]any{}, func(fe *fieldEncoder) { fe.timestampField(5, "t") }, false},
		{"ts bad", "t", map[string]any{"t": "not-a-time"}, func(fe *fieldEncoder) { fe.timestampField(5, "t") }, true},

		{"repeated ok", "r", map[string]any{"r": []string{"a", "b"}}, func(fe *fieldEncoder) { fe.repeatedStringField(6, "r") }, false},
		{"repeated empty entries skipped", "r", map[string]any{"r": []string{"", "x"}}, func(fe *fieldEncoder) { fe.repeatedStringField(6, "r") }, false},
		{"repeated nil slice ok", "r", map[string]any{"r": []string{}}, func(fe *fieldEncoder) { fe.repeatedStringField(6, "r") }, false},
		{"repeated bad", "r", map[string]any{"r": "not-a-slice"}, func(fe *fieldEncoder) { fe.repeatedStringField(6, "r") }, true},
		{"repeated missing", "r", map[string]any{}, func(fe *fieldEncoder) { fe.repeatedStringField(6, "r") }, false},
		{"repeated any slice", "r", map[string]any{"r": []any{"a", "b"}}, func(fe *fieldEncoder) { fe.repeatedStringField(6, "r") }, false},

		// pre-existing error short-circuits
		{"error door", "s", map[string]any{"s": "x"}, func(fe *fieldEncoder) { fe.err = errTest }, true},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			fe := newFieldEncoder(nil, tc.payload)
			tc.encode(fe)
			_, err := fe.bytes()
			if tc.wantErr && err == nil {
				t.Errorf("expected error, got success")
			}
			if !tc.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestInternal_AsInt32AndAsInt64(t *testing.T) {
	t.Parallel()
	if _, ok := asInt32(nil); ok {
		t.Error("nil int32 → not ok")
	}
	if v, ok := asInt32(5); !ok || v != 5 {
		t.Errorf("int → %d/%v", v, ok)
	}
	if v, ok := asInt32(int32(5)); !ok || v != 5 {
		t.Errorf("int32 → %d/%v", v, ok)
	}
	if v, ok := asInt32(int64(5)); !ok || v != 5 {
		t.Errorf("int64 → %d/%v", v, ok)
	}
	if v, ok := asInt32(uint64(5)); !ok || v != 5 {
		t.Errorf("uint64 → %d/%v", v, ok)
	}
	if v, ok := asInt32(float64(5)); !ok || v != 5 {
		t.Errorf("float64 → %d/%v", v, ok)
	}
	if _, ok := asInt32("5"); ok {
		t.Error("string int32 → not ok")
	}

	if _, ok := asInt64(nil); ok {
		t.Error("nil int64 → not ok")
	}
	if v, ok := asInt64(int(5)); !ok || v != 5 {
		t.Errorf("int → %d/%v", v, ok)
	}
	if v, ok := asInt64(int64(5)); !ok || v != 5 {
		t.Errorf("int64 → %d/%v", v, ok)
	}
	if v, ok := asInt64(uint64(5)); !ok || v != 5 {
		t.Errorf("uint64 → %d/%v", v, ok)
	}
	if v, ok := asInt64(uint(5)); !ok || v != 5 {
		t.Errorf("uint → %d/%v", v, ok)
	}
	if v, ok := asInt64(float64(5)); !ok || v != 5 {
		t.Errorf("float64 → %d/%v", v, ok)
	}
	if _, ok := asInt64("5"); ok {
		t.Error("string int64 → not ok")
	}
}

func TestInternal_AsTimeAndStringSlice(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC()
	if t2, ok := asTime(now); !ok || !t2.Equal(now) {
		t.Errorf("time.Time → %v/%v", t2, ok)
	}
	ptr := &now
	if t2, ok := asTime(ptr); !ok || !t2.Equal(now) {
		t.Errorf("*time.Time → %v/%v", t2, ok)
	}
	if _, ok := asTime((*time.Time)(nil)); ok {
		t.Error("nil *time.Time → not ok")
	}
	if _, ok := asTime("not-a-time"); ok {
		t.Error("garbage time → not ok")
	}
	if _, ok := asTime(nil); ok {
		t.Error("nil time → not ok")
	}

	if ss, ok := stringSlice([]string{"a"}); !ok || len(ss) != 1 {
		t.Errorf("[]string → %v/%v", ss, ok)
	}
	if ss, ok := stringSlice([]any{"a", "b"}); !ok || len(ss) != 2 {
		t.Errorf("[]any → %v/%v", ss, ok)
	}
	if _, ok := stringSlice([]any{"a", 1}); ok {
		t.Error("[]any with non-string → not ok")
	}
	if _, ok := stringSlice("x"); ok {
		t.Error("string → not ok")
	}
	if _, ok := stringSlice(nil); ok {
		t.Error("nil → not ok")
	}
}

var errTest = errors.New("boom")

func TestInternal_EnvelopeEncode_Branches(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC()

	// full envelope + payload fields → non-empty output
	env := Envelope{
		EventID: "e1", IdempotencyKey: "k1", TenantID: "t1", GCID: "g1",
		OccurredAt: now, PublishedAt: now,
		Traceparent: "tp", Tracestate: "ts",
		SourceProject: "proj", SourceService: "svc", SchemaVersion: 1,
	}
	b, err := encodeEnvelope(env, map[string]any{
		"correlation_id": "c1", "causation_id": "c2",
		"chora_imda_dimension": "accountability", "imda_lifecycle_stage": "runtime",
	})
	if err != nil {
		t.Fatalf("encodeEnvelope: %v", err)
	}
	if len(b) == 0 {
		t.Error("full envelope should produce bytes")
	}

	// empty env + nil payload → empty output, no error
	b2, err := encodeEnvelope(Envelope{}, nil)
	if err != nil || len(b2) != 0 {
		t.Errorf("empty envelope → %d bytes, err=%v; want 0/nil", len(b2), err)
	}

	// zero schema_version skipped + non-string payload fields ignored
	b3, err := encodeEnvelope(Envelope{SchemaVersion: 0}, map[string]any{"correlation_id": 7})
	if err != nil || len(b3) != 0 {
		t.Errorf("schema-0 envelope → %d bytes, err=%v; want 0/nil", len(b3), err)
	}
}

// silence unused-import warnings when the wire helpers move.
var _ = protowire.VarintType
