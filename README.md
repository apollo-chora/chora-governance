# chora-governance

Governance supporting domain for Chora: the IMDA Model AI Governance
Framework evidence plane. All four IMDA dimensions (accountability,
transparency, safety_and_robustness, fairness_and_human_oversight) are
ingested, projected, and exported here.

The service is cloud-neutral: PostgreSQL for persistence, NATS JetStream for
the event bus, and OTLP for tracing. No cloud account or managed services are
required.

## Architecture

Hexagonal layout:

```
cmd/server/                     entrypoint — HTTP + gRPC, composition root
internal/domain/               policy, audit, imda, evidence, gatekeeper,
                                compliance, projector, rubric, aitransparency,
                                evidencepack, pii_closure_map
internal/adapter/pg/           pgx-backed repositories (RLS tenant isolation)
internal/adapter/http/         REST handlers + middleware
internal/adapter/grpc/         Governance gRPC service
internal/adapter/outbox/       producer-side outbox (durable publish)
internal/adapter/events/       eventbus subscribers + closure saga
internal/observability/        OTLP tracing shim
```

## Configuration

| Variable | Purpose | Default |
| --- | --- | --- |
| `PORT` | HTTP port | `8080` |
| `CHORA_GRPC_PORT` | gRPC port (`GRPC_PORT` accepted as alias) | `9090` |
| `CHORA_DB_DSN` | PostgreSQL DSN (app_rw role) | in-memory when unset |
| `CHORA_OUTBOX_DSN` | Durable outbox database | in-memory when unset |
| `NATS_URL` | NATS JetStream event bus | in-memory when unset |
| `CHORA_SOURCE_PROJECT` | source_project envelope stamp | `chora-local` |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | OTLP/gRPC trace endpoint | stdout when unset |

## Database

PostgreSQL is the durable backing store (`chora_governance` database). Schema
changes live in `migrations/` and are applied with the shared migration runner.
The same database backs the transactional outbox and the subscriber
idempotency store.

## Event bus

NATS JetStream carries the canonical event taxonomy
(`chora.{domain}.{aggregate}.{event_type}.v{N}`). The outbox dispatcher drains
pending rows to the bus; subscribers bind as durable consumers with at-least-once
delivery and `_dlq.<subject>` dead-letter routing.

## Run locally

```sh
cp .env.example .env
# edit .env with your local Postgres + NATS coordinates
go run ./cmd/server
```

HTTP is exposed on `http://localhost:8080`; gRPC on port `9090` by default.
