// Package events defines the publish-side types chora-governance uses to
// emit canonical events to the outbox.
//
// The chora-governance domain publishes the IMDA-aligned governance event
// streams (chora.governance.{aggregate}.{event_type}.v{N}) — most notably
// `chora.governance.policy.violation_detected.v1` (the gatekeeper deny
// path) plus IMDA evidence + closure-saga audit lifecycle.
//
// The outbox adapter (sibling package) takes Header + payload and writes a
// pending row in `outbox_events`; the Dispatcher drains it to Cloud
// Pub/Sub. The Header / PublishedEvent / ErrEmptyTenantID surface mirrors
// chora-tenancy's events package so the outbox adapter pattern is
// uniform across services.
package events

import (
	"errors"
	"time"
)

// TopicAuditRecorded is the canonical generic governance audit-event topic.
// Used by publishers that emit an append-only audit entry to Pub/Sub (e.g.
// the HITL verdict handler). The payload shape matches the
// chora.governance.audit.recorded.v1 schema (AuditEntryRecorded) — see
// internal/adapter/events/protomarshal.MarshalPayload, which has a binary
// protobuf encoder registered for this topic.
const TopicAuditRecorded = "chora.governance.audit.recorded.v1"

// TopicAiTransparencyNoticeAcknowledged is the canonical topic for an
// AI-transparency notice acknowledgement (ADR-225, IMDA D2 transparency
// evidence). Payload = AiTransparencyNoticeAcknowledged; a binary protobuf
// encoder is registered for it in
// internal/adapter/events/protomarshal.MarshalPayload.
const TopicAiTransparencyNoticeAcknowledged = "chora.governance.ai_transparency_notice.acknowledged.v1"

// ErrEmptyTenantID is returned by Publisher.PublishWithError when the
// caller supplies a Header with empty TenantID. Governance events carry
// IMDA D1 accountability — tenant attribution is required on every emit.
var ErrEmptyTenantID = errors.New("events: empty tenant_id")

// Header is the caller-supplied attribution for an emitted event. The
// publisher copies these fields into the Pub/Sub envelope so downstream
// subscribers can filter without parsing the payload.
type Header struct {
	TenantID    string
	GCID        string
	Traceparent string
}

// PublishedEvent is the per-publish receipt the outbox Publisher hands
// back to callers. Mirrors chora-tenancy's PublishedEvent so test helpers
// + roundtrip fixtures port across services.
type PublishedEvent struct {
	Topic          string
	EventID        string
	IdempotencyKey string
	TenantID       string
	GCID           string
	OccurredAt     time.Time
	PublishedAt    time.Time
	Traceparent    string
	SourceProject  string
	SourceService  string
	SchemaVersion  int
	Payload        map[string]interface{}
}
