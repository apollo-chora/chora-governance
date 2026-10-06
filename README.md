# chora-governance

## About

chora-governance is the Governance supporting domain service for Chora. It exposes governance policy, Gatekeeper evaluation, append-only audit, IMDA assessment and dashboard, compliance report, evidence, HITL, and AI transparency APIs. The service is implemented in Go and supports PostgreSQL persistence, NATS JetStream events, transactional outbox delivery, and OTLP tracing, with in-memory fallbacks for local operation when those dependencies are not configured.

## Quick start

Prerequisites: Go 1.26.1 or newer. PostgreSQL and NATS are optional for a dependency-free local run; when their environment variables are unset, the service uses in-memory repositories and an in-memory event bus.

Run the service:

```sh
go run ./cmd/server
```

The HTTP server listens on `http://localhost:8080` and the gRPC server listens on `localhost:9090` by default.

For a local PostgreSQL/NATS setup, start from the checked-in example configuration:

```sh
cp .env.example .env
# edit .env for your PostgreSQL and NATS addresses
go run ./cmd/server
```

The repository's Docker image builds the service as a static Linux binary and copies `config/imda_rubric.yaml` and `config/PII_Closure_Map.yaml` into `/config`.

## Usage

The HTTP API provides public health endpoints:

- `GET /healthz`
- `GET /health`
- `GET /readyz`

The main governance endpoints are:

- `POST /api/policies`
- `GET /api/policies`
- `GET /api/policies/{id}`
- `POST /api/gatekeeper/evaluate`
- `GET /api/audit`
- `POST /api/imda/assessments`
- `GET /api/imda/dashboard`
- `POST /api/compliance/reports`

Additional IMDA/O+ routes include:

- `GET /v1/governance/dimensions/d1/accountability`
- `GET /v1/governance/dimensions/d2/transparency`
- `GET /v1/governance/dimensions/d3/safety`
- `GET /v1/governance/dimensions/d4/fairness`
- `GET /v1/governance/decisions/{id}/explanation`
- `GET /v1/governance/audit/verify`
- `POST /v1/governance/evidence/export`
- `GET /api/hitl/pending`
- `GET /api/hitl/decisions/{id}`
- `GET /api/imda/dimensions/{name}/rubric`
- `GET /v1/me/ai-transparency`
- `POST /v1/me/ai-transparency/acknowledge`
- `GET /governance/{tenant_id}`

Protected `/api/*` requests require both `X-Tenant-Id` and `gcid` headers. Auditor- and instructor-admin-only evidence routes also check `X-Chora-Role`.

The gRPC service is defined by the governance contract in `chora-contracts` and registers the following RPCs:

- `CreatePolicy`
- `GetPolicy`
- `ListPolicies`
- `Evaluate`
- `QueryAuditEvents`
- `RecordAssessment`
- `GetIMDADashboard`
- `GenerateComplianceReport`

Configuration is environment-based. The principal variables are:

| Variable | Purpose | Default |
| --- | --- | --- |
| `PORT` | HTTP port | `8080` |
| `CHORA_GRPC_PORT` | gRPC port | `9090` |
| `CHORA_DB_DSN` | PostgreSQL DSN for the governance repositories | in-memory when unset |
| `CHORA_OUTBOX_DSN` | PostgreSQL DSN for the transactional outbox | in-memory when unset |
| `NATS_URL` | NATS JetStream server | in-memory event bus when unset |
| `CHORA_SOURCE_PROJECT` | Event `source_project` value and service index project | `chora-local` |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | OTLP/gRPC trace endpoint | stdout when unset |

The service also reads `CHORA_IMDA_RUBRIC_PATH`, `CHORA_PII_CLOSURE_MAP_PATH`, and the subscription variables documented in `cmd/server/main.go` and `.env.example` for event consumers and the PII closure saga.

## Development

The repository is a single Go module:

```text
cmd/server/                    service entrypoint and composition root
internal/domain/               governance domain logic
internal/adapter/http/         REST handlers and middleware
internal/adapter/grpc/         Governance gRPC adapter
internal/adapter/pg/           PostgreSQL repositories
internal/adapter/outbox/       transactional outbox storage and dispatcher
internal/adapter/events/       event subscribers and closure saga
internal/observability/        OTLP tracing setup
internal/usecase/              application services
config/                        IMDA rubric and PII closure configuration
migrations/                    PostgreSQL schema migrations
```

Run the unit and package tests with:

```sh
go test ./...
```

Run the integration-tagged tests with:

```sh
go test -race -tags=integration ./...
```

Build the service with:

```sh
go build ./cmd/server
```

Database schema changes are kept in `migrations/`. The Docker build uses Go modules directly and targets both `linux/amd64` and `linux/arm64` in the repository's GitHub Actions publish workflow.
