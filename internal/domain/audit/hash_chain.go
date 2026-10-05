// Package audit — hash chain extension for tamper-evident audit log.
//
// Each entry includes prev_hash (the hash of the previous entry). Tampering
// with any entry breaks all subsequent entries' hashes. Repository computes
// the hash on Append and rejects out-of-order or duplicate entries.
//
// Hash algorithm: SHA-256 over a canonical concatenation of entry fields
// (event_id, tenant_id, gcid, action, resource, decision, prev_hash,
// created_at). prev_hash for the first entry in a chain is "" (empty string).
package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// ComputeHash returns the SHA-256 hex digest of e's canonical representation
// concatenated with prevHash. The empty string is used for the genesis entry.
func ComputeHash(e *Event, prevHash string) string {
	if e == nil {
		return ""
	}
	var b strings.Builder
	b.WriteString(e.EventID)
	b.WriteByte('|')
	b.WriteString(e.TenantID)
	b.WriteByte('|')
	b.WriteString(e.Gcid)
	b.WriteByte('|')
	b.WriteString(e.Agid)
	b.WriteByte('|')
	b.WriteString(e.Action)
	b.WriteByte('|')
	b.WriteString(e.Resource)
	b.WriteByte('|')
	b.WriteString(string(e.Decision))
	b.WriteByte('|')
	b.WriteString(e.Reason)
	b.WriteByte('|')
	b.WriteString(prevHash)
	b.WriteByte('|')
	b.WriteString(e.CreatedAt.UTC().Format("2006-01-02T15:04:05.000000000Z"))

	sum := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(sum[:])
}
