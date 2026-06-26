# syntax=docker/dockerfile:1
#
# Standalone, sink-agnostic zap-kb image.
#
# Unlike ../Dockerfile (a fat OWASP ZAP runtime) and ../../deploy/k8s/Dockerfile
# (the Forgejo-coupled publisher), this image is JUST the zap-kb CLI on a minimal
# base. It carries no scanner and no sink wiring — every behaviour is chosen at
# run time via args/env, so the same image normalizes, enriches, dumps, or
# publishes to any sink (Forgejo, Jira, Confluence, JSON).
#
# Build context is the module dir (zap-kb/):
#   docker build -f deploy/Dockerfile -t zap-kb:standalone .
ARG GO_VERSION=1.24

FROM golang:${GO_VERSION}-alpine AS build
WORKDIR /src
# Warm the module cache before copying sources.
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
# Fully static (CGO off) so the binary runs on any minimal base.
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/zap-kb ./cmd/zap-kb

FROM alpine:3.20
LABEL org.opencontainers.image.title="zap-kb"
LABEL org.opencontainers.image.description="DevSecOps KB normalizer/publisher CLI — sink-agnostic, standalone"
LABEL org.opencontainers.image.source="https://github.com/Warlockobama/DevSecOpsKB"

# ca-certificates: outbound HTTPS to trackers (Jira/Confluence/Forgejo).
# tzdata: stable RFC3339 timestamps. A non-root user owns the /work dir so the
# CLI can write outputs there both under `docker run` and in a pod.
RUN apk add --no-cache ca-certificates tzdata \
 && adduser -D -H -u 65532 kb \
 && mkdir -p /work && chown kb:kb /work

COPY --from=build /out/zap-kb /usr/local/bin/zap-kb

USER 65532:65532
WORKDIR /work
ENTRYPOINT ["zap-kb"]
# Default to the offline help/self-test; real runs override args.
CMD ["-h"]
