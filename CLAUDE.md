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

## Multi-Tiered LLM Routing

This project uses a two-tier LLM setup to balance cost and capability.

### Tier 1: Groq (fast/cheap) — via subagents
Groq MCP server is configured in `.claude/settings.json` (Llama 3.3 70B, ~$0.60/M tokens).

**When to delegate to Groq:**
- Spawn `groq-fast` subagent for: research, code explanations, quick lookups, boilerplate, formatting questions, simple code gen
- Spawn `groq-batch` subagent for: processing multiple items (explain N functions, summarize N files, bulk classification)
- Spawn **multiple `groq-fast` agents in parallel** when tasks are independent (e.g., research 3 different topics simultaneously)

**Examples:**
- "Use groq-fast to explain what EnrichDetections does"
- "Use groq-batch to summarize all files in internal/entities/"
- Spawn 3 groq-fast agents in parallel: one researches CWE mappings, one explains the merge logic, one generates test boilerplate

### Tier 2: Claude (complex reasoning) — native
**Handle natively (do NOT delegate):**
- Architecture decisions and design
- Multi-file refactoring
- Complex debugging across multiple packages
- Security analysis and KB design
- Writing or editing code that requires understanding cross-file dependencies

### Routing rule of thumb
If a task can be answered by reading 1-2 files + a single LLM call → Groq.
If it requires reasoning across multiple files, planning, or tool orchestration → Claude.

## Agile Dev Team (Subagents)

The project has a full agile team as Claude Code subagents. Each agent has access to both Groq (cheap/fast) and Claude (smart) and picks the right tier per task.

### Roles

| Agent | Role | Model | Can write code? |
|-------|------|-------|-----------------|
| `product-owner` | Backlog, user stories, acceptance criteria, GitHub issues | sonnet | No |
| `scrum-master` | Status reports, standup, blockers, retros | haiku | No |
| `dev-lead` | Code review, architecture, pattern enforcement | sonnet | Yes |
| `qa` | Write tests, validate acceptance criteria, run suites | sonnet | Yes |
| `security-sme` | Security review, taxonomy validation, analyst perspective | sonnet | No (read-only) |
| `groq-fast` | Quick lookups, explanations, boilerplate via Groq | haiku | No |
| `groq-batch` | Batch-process multiple items via Groq | haiku | No |

### Agile Workflows

**Daily standup**: Spawn `scrum-master` — reviews git log, open issues/PRs, CI status, reports blockers.

**Sprint planning**: Spawn `product-owner` + `dev-lead` in parallel — PO drafts stories, dev-lead estimates effort and flags technical risks.

**Code review**: Spawn `dev-lead` + `security-sme` + `qa` in parallel — dev-lead reviews quality/patterns, security-sme audits for vulnerabilities, QA checks test coverage.

**Feature development**: Dev-lead designs → user implements → QA validates → security-sme reviews.

**Backlog grooming**: Spawn `product-owner` — reviews open issues, re-prioritizes, writes new stories.

### Parallel spawn patterns

Spawn multiple agents in a single message for independent tasks:
- "Run a code review on the last commit" → dev-lead + security-sme + qa (3 agents parallel)
- "Sprint planning for feature X" → product-owner + dev-lead (2 agents parallel)
- "Research 3 topics" → 3x groq-fast (parallel, cheap)

## Voice Input

Use `/voice` for push-to-talk dictation. Hold Space to record, release to transcribe. Tuned for coding vocabulary.
