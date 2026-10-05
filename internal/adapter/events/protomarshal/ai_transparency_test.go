package protomarshal

import (
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protowire"
)

func TestMarshalPayload_AiTransparencyNoticeAcknowledged(t *testing.T) {
	env := Envelope{
		EventID:       "01J-evt",
		TenantID:      "tenant-1",
		GCID:          "gcid-1",
		OccurredAt:    time.Date(2026, 7, 7, 9, 0, 0, 0, time.UTC),
		SchemaVersion: 1,
	}
	payload := map[string]any{
		"acknowledgement_id":   "01J-ack",
		"gcid":                 "gcid-1",
		"disclosure_version":   "2026-07-01",
		"surface":              "familiar",
		"scope":                "familiar_chat",
		"first_shown_at":       time.Date(2026, 7, 7, 8, 59, 0, 0, time.UTC),
		"acknowledged_at":      time.Date(2026, 7, 7, 9, 0, 0, 0, time.UTC),
		"locale":               "en",
		"minor_mode":           true,
		"chora_imda_dimension": "transparency",
		"imda_lifecycle_stage": "runtime",
	}

	bz, err := MarshalPayload("chora.governance.ai_transparency_notice.acknowledged.v1", env, payload)
	if err != nil {
		t.Fatalf("MarshalPayload: %v", err)
	}
	if len(bz) == 0 {
		t.Fatal("empty wire bytes")
	}

	fields := topLevelFields(t, bz)
	// field 1 = envelope (bytes), field 2 = acknowledgement_id (string).
	if _, ok := fields[1]; !ok {
		t.Errorf("missing envelope (field 1)")
	}
	if got := fields[2]; got != "01J-ack" {
		t.Errorf("acknowledgement_id (field 2) = %q, want 01J-ack", got)
	}
	if got := fields[4]; got != "2026-07-01" {
		t.Errorf("disclosure_version (field 4) = %q", got)
	}
	if got := fields[5]; got != "familiar" {
		t.Errorf("surface (field 5) = %q", got)
	}
}

func TestMarshalPayload_UnsupportedTopicStillErrors(t *testing.T) {
	_, err := MarshalPayload("chora.governance.unknown.event.v1", Envelope{}, map[string]any{})
	if !IsUnsupportedTopic(err) {
		t.Errorf("err = %v, want ErrUnsupportedTopic", err)
	}
}

// topLevelFields parses the top-level string/bytes fields of a message. Returns
// field number -> string value (envelope recorded as "" presence marker).
func topLevelFields(t *testing.T, b []byte) map[protowire.Number]string {
	t.Helper()
	out := map[protowire.Number]string{}
	for len(b) > 0 {
		num, typ, n := protowire.ConsumeTag(b)
		if n < 0 {
			t.Fatalf("bad tag")
		}
		b = b[n:]
		switch typ {
		case protowire.BytesType:
			v, n2 := protowire.ConsumeBytes(b)
			if n2 < 0 {
				t.Fatalf("bad bytes")
			}
			if _, seen := out[num]; !seen {
				out[num] = string(v)
			}
			b = b[n2:]
		case protowire.VarintType:
			_, n2 := protowire.ConsumeVarint(b)
			if n2 < 0 {
				t.Fatalf("bad varint")
			}
			out[num] = "<varint>"
			b = b[n2:]
		default:
			t.Fatalf("unexpected wire type %v", typ)
		}
	}
	return out
}
