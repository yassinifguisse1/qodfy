<div align="center">

# Qodfy

### Open-source launch readiness scanner for AI-built apps.

AI helped you build fast. **Qodfy checks if it’s ready.**

<br />

```bash
npx qodfy scan
```

<br />

![Status](https://img.shields.io/badge/status-early_development-orange)
![License](https://img.shields.io/badge/license-MIT-blue)
![Built with TypeScript](https://img.shields.io/badge/built_with-TypeScript-3178c6)
![Next.js](https://img.shields.io/badge/focused_on-Next.js-black)

</div>

---

## What is Qodfy?

**Qodfy** is an open-source CLI that scans AI-built Next.js apps for common launch risks, messy code patterns, unsafe routes, missing setup, and production blockers.

It is designed for developers building with tools like Cursor, Claude Code, v0, Lovable, Bolt, Replit, Vercel AI SDK, and other AI coding workflows.

```txt
AI builds fast.
Qodfy helps you clean, check, and ship safely.
```

---

## Why Qodfy exists

AI coding tools make it easy to generate apps quickly.

But fast-generated codebases often hide problems:

- missing `.env.example` files
- unsafe API routes
- AI endpoints without rate limiting
- missing authentication checks
- large generated files
- messy project structure
- unclear production readiness
- launch blockers that are easy to miss

Qodfy gives you a quick local report before you continue building or ship to production.

---

## Example

```bash
qodfy scan
```

Output:

```txt
Qodfy is scanning your project...

Qodfy Report

Launch Readiness: 92/100

Stats
Files scanned: 4
API routes: 0
AI-related files: 0
Large files: 0

Issues

WARNING Missing .env.example
Add a .env.example file so future developers know which environment variables are required.

Recommended next step:
Fix critical issues first, then warnings, then cleanup items.
```

---

## Features

| Feature | Status | Description |
|---|---:|---|
| Next.js detection | ✅ | Checks whether the scanned project is a Next.js app |
| Environment checks | ✅ | Detects missing `.env.example` files |
| API route scanning | ✅ | Finds API routes inside `app/api` and `pages/api` |
| Auth risk detection | ✅ | Warns when API routes may be missing auth/session checks |
| AI route detection | ✅ | Detects AI-related files using OpenAI, AI SDK, Anthropic, Gemini, and similar patterns |
| Rate limit warnings | ✅ | Warns when AI routes may be missing rate limiting |
| Large file detection | ✅ | Finds files that may be hard to maintain |
| Launch readiness score | ✅ | Generates a simple score from `0` to `100` |
| Markdown reports | ✅ | Export scan results as human-readable Markdown |
| JSON reports | ✅ | Export scan results for integrations |
| GitHub Action | Planned | Scan pull requests automatically |
| Dashboard | Future | Track scans, history, teams, and reports |

---

## Current focus

Qodfy is currently focused on:

```txt
Next.js apps
TypeScript / JavaScript projects
AI-built codebases
local CLI scanning
launch readiness checks
```

This project is still early. The first goal is to make one command useful:

```bash
qodfy scan
```

---

## Monorepo structure

```txt
qodfy/
  apps/
    web/              # Website, docs, and future dashboard

  packages/
    cli/              # CLI package: qodfy
    core/             # Scanner engine
    rules/            # Future reusable scan rules
    reporter/         # Future report formatters

  examples/           # Future example apps
```

---

## Local development

Install dependencies:

```bash
pnpm install
```

Run the website:

```bash
pnpm dev
```

Run the CLI locally against the web app:

```bash
pnpm dev:cli
```

Generate machine-readable JSON:

```bash
pnpm --filter qodfy exec tsx src/index.ts scan --path ../../apps/web --json
```

Generate a Markdown report:

```bash
pnpm --filter qodfy exec tsx src/index.ts scan --path ../../apps/web --report qodfy-report.md
```

Generate a standalone HTML report:

```bash
pnpm --filter qodfy exec tsx src/index.ts scan --path ../../apps/web --html qodfy-report.html
```

Generate a standalone HTML report and open it in the default browser:

```bash
pnpm --filter qodfy exec tsx src/index.ts scan --path ../../apps/web --html qodfy-report.html --open
```

Preview an HTML report (writes to `.qodfy/qodfy-report.html` inside the scanned project and opens it):

```bash
pnpm --filter qodfy exec tsx src/index.ts scan --path ../../apps/web --preview
```

The HTML report is standalone and opens locally in your browser. It uses only inline CSS, no external CDN, no external fonts, no external images, and no JavaScript.

Build all packages:

```bash
pnpm build
```

---

## Development commands

| Command | Description |
|---|---|
| `pnpm dev` | Run the Qodfy website |
| `pnpm dev:cli` | Run the CLI locally against `apps/web` |
| `pnpm build` | Build all packages |
| `pnpm lint` | Run lint checks |

---

## How Qodfy scores a project

Qodfy starts with a score of `100`.

Then it reduces the score based on issues found:

```txt
Critical issue: -20 points
Warning:        -8 points
Info:           no major score penalty
```

Example:

```txt
100
- 8  missing .env.example
= 92/100
```

The score is simple for now and will improve as Qodfy adds more rules.

---

## Roadmap

### v0.1

- [x] Create monorepo
- [x] Create Next.js web app
- [x] Create CLI package
- [x] Create core scanner package
- [x] Add launch readiness score
- [x] Detect missing `.env.example`
- [x] Detect API routes
- [x] Detect AI-related files
- [x] Detect large files

### v0.2

- [x] Add Markdown report output
- [x] Add JSON report output
- [ ] Detect exposed environment variables
- [ ] Detect Stripe webhook signature verification
- [ ] Detect missing rate limits more accurately
- [ ] Detect missing tests
- [ ] Improve Next.js App Router checks
- [ ] Add better issue categories

### Future

- [ ] GitHub Action
- [ ] Pull request comments
- [ ] Web dashboard
- [ ] Scan history
- [ ] Team workspaces
- [ ] Custom rules
- [ ] AI cleanup suggestions
- [ ] Cursor-ready fix prompts

---

## Vision

Qodfy aims to become the cleanup and launch-readiness layer for AI-built apps.

Developers are building faster than ever with AI.

Qodfy helps them answer one important question:

```txt
Is this app actually ready to ship?
```

---

## License

MIT

---

<div align="center">

Built for developers shipping AI-generated apps.

</div>
