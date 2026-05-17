# Qodfy

AI built it fast. Qodfy checks if it's ready.

Qodfy is an open-source launch-readiness scanner for AI-built apps. The first product is a local CLI focused on Next.js projects built with TypeScript, Vercel AI SDK, Cursor, Claude Code, v0, Lovable, Bolt, Replit, and similar AI coding workflows.

## Quick Start

Run Qodfy in any local project:

```bash
npx qodfy scan
```

Scan a specific folder:

```bash
npx qodfy scan --path apps/web
```

Print machine-readable JSON:

```bash
npx qodfy scan --json
```

Write JSON or Markdown reports:

```bash
npx qodfy scan --json --output qodfy-report.json
npx qodfy scan --report qodfy-report.md
```

The Markdown report is the **Qodfy Launch Report**: a senior-engineer-style review with a launch status, executive summary, top priorities, what looks good, and per-issue context (what Qodfy found, why it matters, evidence, suggested fix, and an AI fix prompt).

## What Qodfy Checks Today

Qodfy scans locally and looks for common launch-readiness risks:

- Next.js project detection
- missing `.env.example`
- API routes in `app/api` and `pages/api`
- API routes that may be missing auth/session checks
- AI-related files using keywords like `openai`, `@ai-sdk`, `anthropic`, `gemini`, `generateText`, `streamText`, and `useChat`
- AI routes/files that may be missing rate limiting
- large generated files
- a simple launch readiness score from `0` to `100`

Qodfy does not send your code to any external server.

## Example Output

```txt
Qodfy is scanning your project...

Qodfy Report

Launch Readiness: 72/100

Stats
Files scanned: 42
API routes: 3
AI-related files: 2
Large files: 1

Issues

CRITICAL AI route may be missing rate limiting
AI routes can create real API costs. Add rate limiting or usage limits before launch.
File: app/api/chat/route.ts

WARNING API route may be missing authentication
This API route does not appear to contain an auth/session check.
File: app/api/admin/route.ts

Recommended next step:
Fix critical issues first, then warnings, then cleanup items.
```

## Commands

```bash
qodfy scan
qodfy scan --path <project-path>
qodfy scan --json
qodfy scan --json --output qodfy-report.json
qodfy scan --report qodfy-report.md
qodfy --help
qodfy --version
```

## Scoring

Qodfy starts at `100`.

- Critical issue: `-20`
- Warning: `-8`
- Info: no major score penalty

The score is intentionally simple and will become more precise as the rule set improves.

## Roadmap

Near-term priorities:

- `.env.example` coverage for `process.env.*`
- exposed secret detection
- Stripe webhook signature checks
- better auth and rate-limit heuristics
- `--ci` and `--min-score`
- GitHub Action

## Repository

GitHub: https://github.com/yassinifguisse1/qodfy

Issues and feedback: https://github.com/yassinifguisse1/qodfy/issues

## License

MIT
