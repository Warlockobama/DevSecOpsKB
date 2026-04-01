# DevSecOps KB

Tool-agnostic knowledge base that normalizes and publishes security findings. First module: `zap-kb` (OWASP ZAP).

## Build & Test

```bash
cd zap-kb
make build          # go build -o bin/zap-kb ./cmd/zap-kb
make test           # go test ./...
make run            # go run ./cmd/zap-kb
```

Go 1.18+. Format with `gofmt`. CI runs `gofmt`, `go vet`, and `go build` on push/PR.

## Key Directories

- `zap-kb/cmd/zap-kb/` — CLI entry point
- `zap-kb/internal/` — core logic (entities, enrichment, publishers)
- `zap-kb/docs/` — architecture, schema, triage workflow, AI instructions
- `zap-kb/scripts/` — Python/bash utilities (flatten reports, scan helpers)
- `archive/` — legacy experiments (gitignored, safe to ignore)

## Conventions

- **Entities model** is the normalized exchange format — definitions, findings, occurrences in a single JSON
- Outputs must be deterministic to support versioning and diffs
- Never commit generated data; `out/` dirs are gitignored
- DCO sign-off required on commits (`git commit -s`)
- EditorConfig: tabs for Go, 2-space indent for everything else, LF line endings

## Groq Integration

A Groq MCP server is configured in `.claude/settings.json`. Use it for simple tasks:
- "use Groq to explain this error"
- "ask Groq to generate boilerplate for a new exporter"

Reserve Claude for architecture decisions, multi-file refactoring, and complex debugging.
