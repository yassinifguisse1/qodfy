# Qodfy

**Open-source launch readiness scanner for AI-built apps.**

Qodfy helps developers scan AI-built Next.js apps for unsafe routes, missing environment setup, duplicated code, messy structure, AI route risks, and launch blockers.

```bash
npx qodfy scan
```

> AI built it fast. Qodfy checks if it’s ready.

---

## Why Qodfy?

AI coding tools make it easier than ever to build apps quickly.

But fast-generated codebases often come with hidden problems:

- missing environment setup
- unsafe API routes
- AI endpoints without rate limiting
- missing authentication checks
- large generated files
- messy structure
- launch blockers
- unclear production readiness

Qodfy gives developers a quick local report before they continue building or ship to production.

---

## Current Status

Qodfy is in early development.

The first version focuses on:

- Next.js apps
- TypeScript / JavaScript projects
- local CLI scanning
- launch readiness scoring
- basic AI route risk detection

---

## Features

### Project Detection

Qodfy checks if the scanned project is a Next.js app.

### Environment Check

Detects missing `.env.example` files.

### API Route Check

Scans API routes inside:

```txt
app/api/
pages/api/
```

and warns when routes may be missing authentication checks.

### AI Route Check

Detects files using AI-related keywords such as:

```txt
openai
@ai-sdk
anthropic
gemini
generateText
streamText
```

and warns when AI routes may be missing rate limiting.

### Large File Detection

Finds large files that may be difficult to maintain, especially in AI-generated codebases.

### Launch Readiness Score

Generates a simple score from `0` to `100` based on critical issues and warnings.

---

## Example Output

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

## Monorepo Structure

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

## Local Development

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

Build all packages:

```bash
pnpm build
```

---

## CLI Development

The CLI package lives in:

```txt
packages/cli
```

The scanner engine lives in:

```txt
packages/core
```

Current local test command:

```bash
pnpm dev:cli
```

Future public command:

```bash
npx qodfy scan
```

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

- [ ] Add Markdown report output
- [ ] Add JSON report output
- [ ] Detect exposed environment variables
- [ ] Detect Stripe webhook signature verification
- [ ] Detect missing rate limits more accurately
- [ ] Detect missing tests
- [ ] Improve Next.js App Router checks

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

AI tools help developers build fast.

Qodfy helps them check, clean, secure, and ship safely.

---

## License

MIT