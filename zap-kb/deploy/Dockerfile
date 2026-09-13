# syntax=docker/dockerfile:1
#
# zap-kb — ZAP → Atlassian (Jira + Confluence) publisher image.
#
# A minimal image of the zap-kb CLI for one job: run after a ZAP scan, pull the
# results, and init/update the Jira + Confluence sinks. Unlike ../Dockerfile (a
# fat OWASP ZAP runtime), it carries no scanner — point it at a live ZAP API or a
# saved ZAP report. Targets/credentials are supplied at run time via env.
#
# Build context is the module dir (zap-kb/):
#   docker build -f deploy/Dockerfile -t zap-kb:atlassian .
ARG GO_VERSION=1.24
ARG VERSION=dev
ARG REVISION=unknown
ARG BUILD_TIME=unknown

FROM golang:${GO_VERSION}-alpine AS build
ARG VERSION
ARG REVISION
ARG BUILD_TIME
WORKDIR /src
# Warm the module cache before copying sources.
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
# Fully static (CGO off) so the binary runs on any minimal base.
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/buildinfo.Version=${VERSION} -X github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/buildinfo.Revision=${REVISION} -X github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/buildinfo.BuildTime=${BUILD_TIME}" -o /out/zap-kb ./cmd/zap-kb

FROM alpine:3.20
ARG VERSION
ARG REVISION
ARG BUILD_TIME
LABEL org.opencontainers.image.title="zap-kb-atlassian"
LABEL org.opencontainers.image.description="ZAP → Atlassian (Jira + Confluence) KB publisher — post-scan"
LABEL org.opencontainers.image.source="https://github.com/Warlockobama/DevSecOpsKB"
LABEL org.opencontainers.image.documentation="https://github.com/Warlockobama/DevSecOpsKB/blob/main/zap-kb/deploy/README.md"
LABEL org.opencontainers.image.licenses="Apache-2.0"
LABEL org.opencontainers.image.version="${VERSION}"
LABEL org.opencontainers.image.revision="${REVISION}"
LABEL org.opencontainers.image.created="${BUILD_TIME}"

# ca-certificates: outbound HTTPS to Jira/Confluence Cloud.
# tzdata: stable RFC3339 timestamps.
# curl, jq: this image is used as a Jenkins pod sidecar, where the surrounding
#   pipeline shells out to poll the ZAP API (planProgress, endDelayJob) from
#   inside this container. The Alpine base only ships busybox wget, so those
#   stages failed with "curl: not found" -- a plain `apk add curl` is the whole
#   fix. jq comes along because the same loops parse ZAP's JSON, which they were
#   otherwise doing with sed and grep.
#   Neither is needed by zap-kb itself; the binary is static and speaks HTTP
#   directly. Measured cost: 19.9 MB -> 25.6 MB unpacked (+5.8 MB).
# A non-root user owns the /work dir so the CLI can write outputs there both
# under `docker run` and in a pod.
RUN apk add --no-cache ca-certificates tzdata curl jq \
 && adduser -D -H -u 65532 kb \
 && mkdir -p /work && chown kb:kb /work

COPY --from=build /out/zap-kb /usr/local/bin/zap-kb

USER 65532:65532
WORKDIR /work
ENTRYPOINT ["zap-kb"]
# Default to the offline help/self-test; real runs override args.
CMD ["-h"]
