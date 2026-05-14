# @qodfy/core

Scanner engine for Qodfy.

Most developers should use the CLI:

```bash
npx qodfy scan
```

This package contains the deterministic local scanner used by the `qodfy` CLI. It is published separately so Qodfy can later support more report formats, integrations, and programmatic usage without coupling everything to terminal output.

## Install

```bash
npm install @qodfy/core
```

## Usage

```ts
import { scanProject } from "@qodfy/core";

const report = await scanProject(process.cwd());

console.log(report.score);
console.log(report.issues);
```

## What It Returns

`scanProject(projectPath)` returns a launch-readiness report with:

- project path
- Next.js detection result
- score from `0` to `100`
- issues with severity, title, message, and optional file path
- stats for scanned files, API routes, AI-related files, and large files

## Local-Only

`@qodfy/core` reads files from the local project path you provide. It does not call AI APIs, upload code, require login, or contact an external Qodfy server.

## Repository

GitHub: https://github.com/yassinifguisse1/qodfy

Issues and feedback: https://github.com/yassinifguisse1/qodfy/issues

## License

MIT
