// event_time.go: one place that turns a protobuf envelope timestamp into the
// event time an evidence row records.
//
// WHY THIS IS NOT JUST ts.AsTime(). timestamppb's AsTime() on a NIL message
// returns the Unix epoch, 1970-01-01T00:00:00Z, which is a perfectly valid
// non-zero time.Time. Passing that straight through would silently BACKDATE
// every evidence row from a producer that omitted the field by 56 years, and it
// would defeat the domain's zero-means-now fallback, because 1970 is not zero.
// A missing timestamp must read as ABSENT, not as 1970.
package events

import (
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"
)

// envelopeTime returns the first usable timestamp in order, or the zero time
// when none is set. The zero time is meaningful: the evidence constructors read
// it as "the producer did not state an event time" and stamp now instead.
func envelopeTime(candidates ...*timestamppb.Timestamp) time.Time {
	for _, ts := range candidates {
		if ts == nil || !ts.IsValid() {
			continue
		}
		t := ts.AsTime().UTC()
		if t.IsZero() || t.Unix() == 0 {
			// Explicit epoch or zero carries no information; keep looking.
			continue
		}
		return t
	}
	return time.Time{}
}

// parseRFC3339Nano turns a serialised timestamp back into a time, returning the
// zero time on anything unparseable so the domain falls back to now rather than
// recording a garbage instant.
func parseRFC3339Nano(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return time.Time{}
	}
	return t.UTC()
}
