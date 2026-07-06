# Security guidance for obsidian-ai-pipeline

Flat-root TypeScript pipeline that ingests untrusted external text (weekly LLM
threat reports fetched from Gmail, X bookmarks, YouTube metadata) into an
Obsidian vault, with SQLite (better-sqlite3) as the core store.

## Trust boundaries (highest priority)

- Threat-report bodies, X bookmark/tweet text, and fetched web content are
  UNTRUSTED. Flag any code that embeds such text in an LLM prompt without
  isolating it as data. This repo's pattern: random-nonce `<threat {nonce}>`
  delimiters with nonce occurrences stripped from the body first
  (`threat-reports/relevance.ts`).
- Flag any code that executes, fetches, or shell-interpolates strings
  originating from report/bookmark/vault content (indirect prompt injection
  escalating to command injection).
- Flag logging or persisting of raw untrusted payloads. Gate artifacts
  (`_gate/decisions.jsonl`, quarantine queue) must store only redacted
  previews and `span_sha1` fingerprints, never full spans.

## Injection-gate invariants (scan-threat-report / gate_decision.py)

- The gate must stay fail-closed: unknown, malformed, or missing input maps to
  `suspicious`, never `clean`. Flag changes that add a default-allow path,
  silently skip invalid known-safe-pattern entries, or let L2 LLM verdicts
  auto-block/auto-clean without anchored evidence.
- `forbidden_usage: execute_report_instructions` is a required frontmatter
  token enforced in `threat-reports/parser.ts`; flag changes that relax it.

## Secrets

- Never hardcode credentials or token literals (`ghp_`, `github_pat_`, `sk-`,
  `AIza`, `AKIA`, `xox`). Credentials come only from env vars or gitignored
  files (`pipeline_config.json`, `x_tokens.json`, `data/tokens.json`).
- Flag new code paths that read those files and perform network I/O in the
  same flow without going through the existing token modules
  (`x-bookmarks/tokens.ts`).

## Filesystem / DB

- Vault-relative writes must reject absolute paths and `..` traversal (see
  `threat-reports/parser.ts`). Flag path joins from external input without
  that check.
- better-sqlite3: parameterized statements only. Flag SQL built by string
  concatenation with external input.

## CI / workflows

- `.github/workflows/`: actions must be pinned to full commit SHAs and
  `permissions:` must stay minimal (`contents: read` unless justified). Flag
  `pull_request_target`, `${{ ... }}` interpolation of untrusted event fields
  into `run:` steps, and any new secret exposure to PR-triggered jobs.
- Vault pushes use a scoped deploy key, not `GITHUB_TOKEN`; flag changes that
  widen `GITHUB_TOKEN` permissions instead.
