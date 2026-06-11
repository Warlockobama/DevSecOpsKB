# Multi-stage build of the DevSecOpsKB publisher binary.
# Build context is the REPOSITORY ROOT (so the zap-kb module is available):
#
#   docker build -f deploy/k8s/Dockerfile -t ghcr.io/warlockobama/devsecopskb:latest .
#
FROM golang:1.24-alpine AS build
WORKDIR /src
# Pre-fetch modules for a warm cache.
COPY zap-kb/go.mod zap-kb/go.sum ./zap-kb/
WORKDIR /src/zap-kb
RUN go mod download
# Build.
COPY zap-kb/ /src/zap-kb/
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/zap-kb ./cmd/zap-kb

FROM alpine:3.20
RUN apk add --no-cache ca-certificates && adduser -D -u 1000 kb
COPY --from=build /out/zap-kb /usr/local/bin/zap-kb
USER kb
ENTRYPOINT ["zap-kb"]
