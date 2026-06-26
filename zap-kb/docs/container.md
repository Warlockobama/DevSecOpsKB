# Container Image

> **Just need `zap-kb` in a pod?** For a minimal, sink-agnostic image (no ZAP)
> plus a portable Kubernetes Job manifest, see [`../deploy/README.md`](../deploy/README.md).
> This page covers the fuller ZAP-based runtime image below.

`zap-kb/Dockerfile` builds a ZAP-based runtime image that includes:

- OWASP ZAP from `ghcr.io/zaproxy/zaproxy:stable`.
- The compiled `zap-kb` CLI.
- `scan-zap.sh` for simple API-driven ZAP scans.
- `zap_run_artifact.py` for Python-only run artifact gathering.

The Go toolchain is used only in the build stage and is not present in the final
image.

## Build

From `zap-kb/`:

```bash
make container-build
```

Or from the repository root:

```bash
docker build -t devsecopskb/zap-kb-zap:local ./zap-kb
```

## Run `zap-kb`

The image defaults to the `zap-kb` CLI. These are equivalent:

```bash
docker run --rm devsecopskb/zap-kb-zap:local -init -format entities -plugins 10038 -out /tmp/entities.json
docker run --rm devsecopskb/zap-kb-zap:local zap-kb -init -format entities -plugins 10038 -out /tmp/entities.json
```

Mount a host directory when you want to keep outputs:

```bash
docker run --rm -v "$PWD/out:/zap/wrk/out" devsecopskb/zap-kb-zap:local \
  -format entities \
  -out out/entities.json \
  -zap-url "$ZAP_URL" \
  -api-key "$ZAP_API_KEY"
```

## Run ZAP And `zap-kb` In One Container

The image still includes `zap.sh`. Start ZAP as the container command, then
execute `zap-kb` inside the same running container:

```bash
docker run -d --name zap-kb \
  -p 8090:8090 \
  -e ZAP_API_KEY=changeme \
  -v "$PWD/out:/zap/wrk/out" \
  devsecopskb/zap-kb-zap:local \
  zap.sh -daemon -host 0.0.0.0 -port 8090 \
    -config api.disablekey=false \
    -config api.key=changeme \
    -config api.addrs.addr.name=.* \
    -config api.addrs.addr.regex=true

docker exec zap-kb zap-kb \
  -format entities \
  -out out/entities.json \
  -zap-url http://127.0.0.1:8090 \
  -api-key changeme
```

This keeps ZAP and the KB fetch/publish step in the same network namespace.

## Compose Demo

From the repository root:

```bash
docker compose -f zap-kb/docker/docker-compose.zap-kb.yml up -d --build
docker compose -f zap-kb/docker/docker-compose.zap-kb.yml exec zap-kb scan-zap.sh
docker compose -f zap-kb/docker/docker-compose.zap-kb.yml exec zap-kb zap-kb \
  -format entities \
  -out out/entities.json \
  -zap-url http://127.0.0.1:8090 \
  -api-key "${ZAP_API_KEY:-changeme}" \
  -baseurl http://juice-shop:3000 \
  -include-traffic \
  -traffic-scope first \
  -include-detection \
  -detection-details summary
```

Outputs are written to `zap-kb/out/` through the bind mount.
