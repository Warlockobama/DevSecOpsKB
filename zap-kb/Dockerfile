# syntax=docker/dockerfile:1

ARG GO_VERSION=1.24
ARG ZAP_IMAGE=ghcr.io/zaproxy/zaproxy:stable

FROM golang:${GO_VERSION}-bookworm AS build
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY cmd ./cmd
COPY internal ./internal

RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/zap-kb ./cmd/zap-kb

FROM ${ZAP_IMAGE} AS runtime

ARG RUNTIME_UID=1000
ARG RUNTIME_GID=1000

LABEL org.opencontainers.image.title="zap-kb"
LABEL org.opencontainers.image.description="OWASP ZAP runtime with the compiled DevSecOps KB zap-kb CLI"

USER root
COPY --from=build /out/zap-kb /usr/local/bin/zap-kb
COPY scripts/scan-zap.sh /usr/local/bin/scan-zap.sh
COPY scripts/zap_run_artifact.py /usr/local/bin/zap_run_artifact.py
COPY docker/zap-kb-entrypoint.sh /usr/local/bin/zap-kb-entrypoint
RUN chmod 0755 /usr/local/bin/zap-kb /usr/local/bin/scan-zap.sh /usr/local/bin/zap_run_artifact.py /usr/local/bin/zap-kb-entrypoint \
	&& mkdir -p /zap/wrk \
	&& chown -R "${RUNTIME_UID}:${RUNTIME_GID}" /zap/wrk

USER ${RUNTIME_UID}:${RUNTIME_GID}
WORKDIR /zap/wrk

ENTRYPOINT ["/usr/local/bin/zap-kb-entrypoint"]
CMD ["zap-kb", "-h"]
