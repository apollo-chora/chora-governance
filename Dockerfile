# syntax=docker/dockerfile:1.6
#
# chora-governance Dockerfile — standalone Go service.
#
# Build context = this repository. Shared Chora modules (chora-common,
# chora-contracts) are resolved through Go modules, not a workspace.

ARG GO_VERSION=1.26.6
ARG ALPINE_VERSION=3.23
ARG SERVICE_NAME=chora-governance
ARG GIT_SHA=unknown
ARG BUILD_TIME=unknown

############################
# Stage 1 — build
############################
FROM golang:${GO_VERSION}-alpine${ALPINE_VERSION} AS builder
ARG TARGETARCH

ARG SERVICE_NAME
ARG GIT_SHA
ARG BUILD_TIME

WORKDIR /src

RUN apk add --no-cache ca-certificates git

COPY . .

RUN go mod download

ENV CGO_ENABLED=0 \
    GOOS=linux \
    GOARCH=${TARGETARCH}
RUN go build -trimpath \
      -ldflags "-s -w \
        -X main.serviceName=${SERVICE_NAME} \
        -X main.gitSHA=${GIT_SHA} \
        -X main.buildTime=${BUILD_TIME}" \
      -o /out/service \
      ./cmd/server

############################
# Stage 2 — runtime
############################
FROM alpine:${ALPINE_VERSION}

ARG SERVICE_NAME
ARG GIT_SHA
ARG BUILD_TIME

RUN apk add --no-cache ca-certificates \
    && addgroup -S app \
    && adduser -S -G app app

LABEL org.opencontainers.image.title="${SERVICE_NAME}" \
      org.opencontainers.image.source="https://github.com/apollo-chora/chora-governance" \
      org.opencontainers.image.revision="${GIT_SHA}" \
      org.opencontainers.image.created="${BUILD_TIME}" \
      org.opencontainers.image.vendor="Chora Platform" \
      org.opencontainers.image.licenses="UNLICENSED" \
      io.chora.service="${SERVICE_NAME}" \
      io.chora.git-sha="${GIT_SHA}" \
      io.chora.build-time="${BUILD_TIME}"

WORKDIR /

COPY --from=builder /out/service /service

# IMDA rubric config (config/imda_rubric.yaml + PII_Closure_Map.yaml). The
# rubric resolver (cmd/server/rubric_bootstrap.go) loads imda_rubric.yaml at
# boot — without it the resolver is nil and every O+ endpoint
# (/api/imda/dimensions/{name}/rubric) returns 503/400. The deployment manifest
# points CHORA_IMDA_RUBRIC_PATH at /config/imda_rubric.yaml (the path copied
# here). Source-of-truth stays config/ in this repo.
COPY --from=builder /src/config /config

USER app:app
ENTRYPOINT ["/service"]
