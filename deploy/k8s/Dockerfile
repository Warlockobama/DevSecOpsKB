# Multi-stage build of the DevSecOpsKB publisher binary.
# Build context is the REPOSITORY ROOT (so the zap-kb module is available):
#
#   docker build -f deploy/k8s/Dockerfile --build-arg REVISION="$(git rev-parse HEAD)" -t ghcr.io/warlockobama/devsecopskb:local .
#
ARG VERSION=dev
ARG REVISION=unknown
ARG BUILD_TIME=unknown

FROM golang:1.24-alpine AS build
ARG VERSION
ARG REVISION
ARG BUILD_TIME
WORKDIR /src
# Pre-fetch modules for a warm cache.
COPY zap-kb/go.mod zap-kb/go.sum ./zap-kb/
WORKDIR /src/zap-kb
RUN go mod download
# Build.
COPY zap-kb/ /src/zap-kb/
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/buildinfo.Version=${VERSION} -X github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/buildinfo.Revision=${REVISION} -X github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/buildinfo.BuildTime=${BUILD_TIME}" -o /out/zap-kb ./cmd/zap-kb

FROM alpine:3.20
ARG VERSION
ARG REVISION
ARG BUILD_TIME
LABEL org.opencontainers.image.title="devsecopskb-publisher"
LABEL org.opencontainers.image.source="https://github.com/Warlockobama/DevSecOpsKB"
LABEL org.opencontainers.image.version="${VERSION}"
LABEL org.opencontainers.image.revision="${REVISION}"
LABEL org.opencontainers.image.created="${BUILD_TIME}"
RUN apk add --no-cache ca-certificates && adduser -D -u 1000 kb
COPY --from=build /out/zap-kb /usr/local/bin/zap-kb
USER kb
ENTRYPOINT ["zap-kb"]
