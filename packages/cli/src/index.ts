#!/usr/bin/env node

import fs from "node:fs/promises";
import path from "node:path";
import { checkbox, select } from "@inquirer/prompts";
import { Command } from "commander";
import pc from "picocolors";
import {
  recommendedScanChecks,
  scanProject,
  validScanChecks,
  type Issue,
  type IssueCategory,
  type IssueConfidence,
  type IssueEvidence,
  type IssueSeverity,
  type ScanCheck,
  type ScanReport
} from "@qodfy/core";

type PathValidationResult =
  | { ok: true; projectPath: string }
  | { ok: false; reason: string };

type ScanModeResult =
  | { ok: true; checks: ScanCheck[]; label: string; notice?: string; includeLowConfidence?: boolean }
  | { ok: false; reason: string };
type ResolvedScanMode = Extract<ScanModeResult, { ok: true }>;

type ScanCommandOptions = {
  path: string;
  maxIssues: string;
  prompts?: boolean;
  prompt?: string;
  checks?: string;
  all?: boolean;
  interactive?: boolean;
  json?: boolean;
  output?: string;
  report?: string;
  html?: string;
};

type PromptCommandOptions = {
  path: string;
  checks?: string;
  all?: boolean;
};

type ScanMode = "recommended" | "security-api" | "environment" | "ai" | "webhook" | "maintainability" | "custom";

type OutputScanReport = {
  qodfyVersion: string;
  generatedAt: string;
  projectPath: string;
  scanMode: string;
  checks: ScanCheck[];
  score: number;
  stats: ScanReport["stats"];
  issues: Issue[];
};

const CLI_VERSION = "0.3.0";
const DEFAULT_MAX_ISSUES = 5;

const program = new Command();

program
  .name("qodfy")
  .description("Launch readiness scanner for AI-built apps.")
  .version(CLI_VERSION);

program
  .command("scan")
  .description("Scan a project for launch readiness issues.")
  .option("-p, --path <path>", "Project path to scan", process.cwd())
  .option("--max-issues <number>", "Maximum number of issues to display", String(DEFAULT_MAX_ISSUES))
  .option("--prompts", "Show safe copy-paste fix prompts for displayed issues")
  .option("--prompt <issue-id>", "Show the safe AI fix prompt for one issue")
  .option("--checks <checks>", "Comma-separated checks to run")
  .option("--all", "Run all checks without prompting")
  .option("--no-interactive", "Skip interactive prompts and run the recommended scan")
  .option("--json", "Print a machine-readable JSON report")
  .option("--output <file>", "Write the JSON report to a file")
  .option("--report <file>", "Write a human-readable Markdown report to a file")
  .option("--html <file>", "Write a standalone HTML report to a file")
  .action(async (options: ScanCommandOptions) => {
    const outputOptionsResult = validateScanOutputOptions(options);

    if (!outputOptionsResult.ok) {
      printScanError(outputOptionsResult.reason, !isOutputMode(options));
      process.exitCode = 1;
      return;
    }

    const pathResult = await resolveProjectPath(options.path);

    if (!pathResult.ok) {
      printScanError(pathResult.reason, !isOutputMode(options));
      process.exitCode = 1;
      return;
    }

    try {
      const scanModeResult = await resolveScanMode(options);

      if (!scanModeResult.ok) {
        printScanError(scanModeResult.reason, !isOutputMode(options));
        process.exitCode = 1;
        return;
      }

      if (scanModeResult.notice && !isOutputMode(options)) {
        console.log(pc.dim(scanModeResult.notice));
        console.log("");
      }

      if (!isOutputMode(options)) {
        console.log(pc.cyan("Qodfy is scanning your project...\n"));
      }

      const report = await scanProject({
        projectPath: pathResult.projectPath,
        checks: scanModeResult.checks,
        includeLowConfidence: Boolean(scanModeResult.includeLowConfidence)
      });

      const outputReport = createOutputReport(report, scanModeResult);

      if (options.json) {
        const jsonReport = `${JSON.stringify(outputReport, null, 2)}\n`;

        if (options.output) {
          await writeReportFile(options.output, jsonReport);
          console.log(`Qodfy JSON report saved to ${options.output}`);
        } else {
          process.stdout.write(jsonReport);
        }

        return;
      }

      if (options.report) {
        await writeReportFile(options.report, renderMarkdownReport(outputReport));
        console.log(`Qodfy report saved to ${options.report}`);
        return;
      }

      if (options.html) {
        await writeReportFile(options.html, renderHtmlReport(outputReport));
        console.log(`Qodfy HTML report saved to ${options.html}`);
        return;
      }

      if (options.prompt) {
        printPromptFromReport(report, options.prompt);
        return;
      }

      printReport(
        report,
        parseMaxIssues(options.maxIssues),
        Boolean(options.prompts),
        scanModeResult.label,
        Boolean(options.all),
        Boolean(options.all)
      );
    } catch (error) {
      if (isPromptCancelError(error)) {
        console.log("Scan cancelled.");
      } else {
        printScanError(getErrorMessage(error), !isOutputMode(options));
      }
      process.exitCode = 1;
    }
  });

program
  .command("prompt <issue-id>")
  .description("Print the safe AI fix prompt for a specific issue.")
  .option("-p, --path <path>", "Project path to scan", process.cwd())
  .option("--checks <checks>", "Comma-separated checks to search")
  .option("--all", "Search all checks", true)
  .action(async (issueId: string, options: PromptCommandOptions) => {
    const pathResult = await resolveProjectPath(options.path);

    if (!pathResult.ok) {
      printScanError(pathResult.reason);
      process.exitCode = 1;
      return;
    }

    const checksResult = resolvePromptChecks(options);

    if (!checksResult.ok) {
      printPromptError(checksResult.reason);
      process.exitCode = 1;
      return;
    }

    const report: ScanReport = await scanProject({
      projectPath: pathResult.projectPath,
      checks: checksResult.checks,
      includeLowConfidence: true
    });

    const issue = report.issues.find((scanIssue) => scanIssue.id === issueId);

    if (!issue) {
      printPromptError(
        `Issue "${issueId}" was not found in this project scan.\nRun qodfy scan --all to see the current issue IDs.`
      );
      process.exitCode = 1;
      return;
    }

    if (!issue.fixPrompt) {
      printPromptError(`Issue "${issueId}" does not have an AI fix prompt yet.`);
      process.exitCode = 1;
      return;
    }

    printFixPrompt(issue);
  });

const categoryOrder: IssueCategory[] = [
  "security",
  "webhook",
  "ai",
  "api",
  "environment",
  "maintainability",
  "project"
];

const categoryLabels: Record<IssueCategory, string> = {
  security: "Security",
  api: "API",
  webhook: "Webhooks",
  ai: "AI",
  environment: "Environment",
  maintainability: "Maintainability",
  project: "Project"
};

await program.parseAsync();

function validateScanOutputOptions(options: ScanCommandOptions): { ok: true } | { ok: false; reason: string } {
  if (options.output && !options.json) {
    return {
      ok: false,
      reason: "Use --output together with --json, for example: qodfy scan --json --output qodfy-report.json."
    };
  }

  if (options.json && options.report) {
    return {
      ok: false,
      reason: "Use either --json or --report for one scan command, not both."
    };
  }

  if (options.json && options.html) {
    return {
      ok: false,
      reason: "Use either --json or --html for one scan command, not both."
    };
  }

  if (options.report && options.html) {
    return {
      ok: false,
      reason: "Use either --report or --html for one scan command, not both."
    };
  }

  if (options.html && options.output) {
    return {
      ok: false,
      reason: "--output is only used with --json. For HTML, just pass --html <file>."
    };
  }

  if ((options.json || options.report || options.html) && options.prompt) {
    return {
      ok: false,
      reason: "Use qodfy prompt <issue-id> for fix prompts, or run qodfy scan --json/--report/--html for reports."
    };
  }

  return { ok: true };
}

function isOutputMode(options: ScanCommandOptions) {
  return Boolean(options.json || options.output || options.report || options.html);
}

async function resolveScanMode(options: ScanCommandOptions): Promise<ScanModeResult> {
  if (options.checks) {
    const parsedChecks = parseChecks(options.checks);

    if (!parsedChecks.ok) {
      return parsedChecks;
    }

    return {
      ok: true,
      checks: parsedChecks.checks,
      label: getScanModeLabel(parsedChecks.checks)
    };
  }

  if (options.all) {
    return {
      ok: true,
      checks: [...validScanChecks],
      label: "All checks",
      includeLowConfidence: true
    };
  }

  if (options.prompt) {
    return {
      ok: true,
      checks: [...validScanChecks],
      label: "All checks",
      includeLowConfidence: true
    };
  }

  if (isOutputMode(options)) {
    return {
      ok: true,
      checks: [...recommendedScanChecks],
      label: "Recommended launch scan"
    };
  }

  if (options.interactive === false) {
    return {
      ok: true,
      checks: [...recommendedScanChecks],
      label: "Recommended launch scan"
    };
  }

  if (isNonInteractiveTerminal()) {
    return {
      ok: true,
      checks: [...recommendedScanChecks],
      label: "Recommended launch scan",
      notice: "Running recommended scan in non-interactive mode."
    };
  }

  return promptForScanMode();
}

async function promptForScanMode(): Promise<ScanModeResult> {
  console.log(pc.bold("Qodfy Scan"));
  console.log("");

  const mode = await select<ScanMode>({
    message: "Choose scan mode:",
    choices: [
      {
        name: "Recommended launch scan",
        value: "recommended",
        description: "Project setup, API routes, environment, AI, webhooks, and maintainability"
      },
      {
        name: "Security & API routes",
        value: "security-api",
        description: "API authentication, client-side secrets, hardcoded secrets, and webhooks"
      },
      {
        name: "Environment variables",
        value: "environment",
        description: ".env.example and process.env documentation"
      },
      {
        name: "AI route cost risks",
        value: "ai",
        description: "AI-related routes that may need rate limits or usage limits"
      },
      {
        name: "Webhooks",
        value: "webhook",
        description: "Webhook signature verification"
      },
      {
        name: "Maintainability",
        value: "maintainability",
        description: "Large files and maintainability signals"
      },
      {
        name: "Custom selection",
        value: "custom",
        description: "Choose exactly which checks to run"
      }
    ]
  });

  if (mode === "custom") {
    const checks = await checkbox<ScanCheck>({
      message: "Select checks to run:",
      required: true,
      choices: [
        { name: "Project setup", value: "project" },
        { name: "API route authentication", value: "api", checked: true },
        { name: "Environment variables", value: "environment", checked: true },
        { name: "AI route cost risks", value: "ai" },
        { name: "Webhooks", value: "webhook" },
        { name: "Maintainability / large files", value: "maintainability" }
      ]
    });

    return {
      ok: true,
      checks,
      label: `Custom selection: ${checks.join(", ")}`
    };
  }

  return {
    ok: true,
    checks: getChecksForMode(mode),
    label: getScanModeName(mode)
  };
}

function getChecksForMode(mode: Exclude<ScanMode, "custom">): ScanCheck[] {
  if (mode === "recommended") {
    return [...recommendedScanChecks];
  }

  if (mode === "security-api") {
    return ["api", "security", "webhook"];
  }

  if (mode === "environment") {
    return ["environment"];
  }

  if (mode === "ai") {
    return ["ai"];
  }

  if (mode === "webhook") {
    return ["webhook"];
  }

  return ["maintainability"];
}

function getScanModeName(mode: Exclude<ScanMode, "custom">) {
  if (mode === "recommended") {
    return "Recommended launch scan";
  }

  if (mode === "security-api") {
    return "Security & API routes";
  }

  if (mode === "environment") {
    return "Environment variables";
  }

  if (mode === "ai") {
    return "AI route cost risks";
  }

  if (mode === "webhook") {
    return "Webhooks";
  }

  return "Maintainability";
}

function parseChecks(checks: string): ScanModeResult | { ok: true; checks: ScanCheck[] } {
  const selectedChecks = [...new Set(
    checks
      .split(",")
      .map((check) => check.trim().toLowerCase())
      .filter(Boolean)
  )];

  if (selectedChecks.length === 0) {
    return {
      ok: false,
      reason: `No checks were provided. Valid checks: ${validScanChecks.join(", ")}.`
    };
  }

  const invalidChecks = selectedChecks.filter((check) => !isScanCheck(check));

  if (invalidChecks.length > 0) {
    return {
      ok: false,
      reason: `Invalid check${invalidChecks.length === 1 ? "" : "s"}: ${invalidChecks.join(", ")}.\nValid checks: ${validScanChecks.join(", ")}.`
    };
  }

  return {
    ok: true,
    checks: selectedChecks.filter(isScanCheck)
  };
}

function isScanCheck(check: string): check is ScanCheck {
  return validScanChecks.includes(check as ScanCheck);
}

function getScanModeLabel(checks: ScanCheck[]) {
  if (hasSameChecks(checks, recommendedScanChecks)) {
    return "Recommended launch scan";
  }

  if (hasSameChecks(checks, validScanChecks)) {
    return "All checks";
  }

  if (checks.length === 1) {
    const check = checks[0];

    if (check === "environment") {
      return "Environment variables";
    }

    if (check === "api") {
      return "API route authentication";
    }

    if (check === "ai") {
      return "AI route cost risks";
    }

    if (check === "webhook") {
      return "Webhooks";
    }

    if (check === "maintainability") {
      return "Maintainability";
    }

    if (check === "project") {
      return "Project setup";
    }

    return "Security";
  }

  return `Custom selection: ${checks.join(", ")}`;
}

function hasSameChecks(leftChecks: readonly ScanCheck[], rightChecks: readonly ScanCheck[]) {
  const leftSet = new Set(leftChecks);
  const rightSet = new Set(rightChecks);

  return (
    leftSet.size === rightSet.size &&
    [...leftSet].every((check) => rightSet.has(check))
  );
}

function isNonInteractiveTerminal() {
  return Boolean(process.env.CI) || !process.stdin.isTTY || !process.stdout.isTTY;
}

function resolvePromptChecks(options: PromptCommandOptions): ScanModeResult {
  if (options.checks) {
    const parsedChecks = parseChecks(options.checks);

    if (!parsedChecks.ok) {
      return parsedChecks;
    }

    return {
      ok: true,
      checks: parsedChecks.checks,
      label: getScanModeLabel(parsedChecks.checks)
    };
  }

  return {
    ok: true,
    checks: [...validScanChecks],
    label: "All checks"
  };
}

async function resolveProjectPath(projectPath: string): Promise<PathValidationResult> {
  const inputPath = projectPath.trim() || process.cwd();
  const resolvedPath = path.resolve(inputPath);

  try {
    const stats = await fs.stat(resolvedPath);

    if (!stats.isDirectory()) {
      return {
        ok: false,
        reason: `The path "${inputPath}" is not a directory.`
      };
    }

    return {
      ok: true,
      projectPath: resolvedPath
    };
  } catch (error) {
    const code = getErrorCode(error);

    if (code === "ENOENT") {
      return {
        ok: false,
        reason: `The path "${inputPath}" does not exist.`
      };
    }

    if (code === "ENOTDIR") {
      return {
        ok: false,
        reason: `The path "${inputPath}" is not a directory.`
      };
    }

    return {
      ok: false,
      reason: `Qodfy could not access the path "${inputPath}".`
    };
  }
}

function createOutputReport(report: ScanReport, scanMode: ResolvedScanMode): OutputScanReport {
  return {
    qodfyVersion: CLI_VERSION,
    generatedAt: new Date().toISOString(),
    projectPath: report.projectPath,
    scanMode: scanMode.label,
    checks: [...scanMode.checks],
    score: report.score,
    stats: { ...report.stats },
    issues: report.issues
  };
}

async function writeReportFile(outputPath: string, content: string) {
  const resolvedOutputPath = path.resolve(outputPath);

  await fs.mkdir(path.dirname(resolvedOutputPath), { recursive: true });
  await fs.writeFile(resolvedOutputPath, content, "utf8");
}

function renderMarkdownReport(report: OutputScanReport) {
  const projectName = path.basename(report.projectPath) || report.projectPath;
  const statusLabel = getStatusLabel(report.score);
  const criticalCount = countIssuesBySeverity(report.issues, "critical");
  const warningCount = countIssuesBySeverity(report.issues, "warning");
  const infoCount = countIssuesBySeverity(report.issues, "info");

  const lines: string[] = [
    "# Qodfy Launch Readiness Report",
    "",
    `Generated: ${report.generatedAt}`,
    `Project: ${projectName}`,
    `Scan mode: ${report.scanMode}`,
    `Score: ${report.score}/100`,
    `Launch status: ${statusLabel}`,
    "",
    "## Executive Summary",
    "",
    getExecutiveSummary(report),
    "",
    "## Score Breakdown",
    "",
    `- Critical issues: ${criticalCount}`,
    `- Warnings: ${warningCount}`,
    `- Info: ${infoCount}`,
    `- Files scanned: ${report.stats.totalFiles}`,
    `- API routes scanned: ${report.stats.apiRoutes}`,
    `- Scan duration: ${formatDuration(report.stats.durationMs)}`,
    "",
    "## Top Priorities",
    ""
  ];

  const priorities = getTopPriorities(report.issues);

  if (priorities.length === 0) {
    lines.push("No urgent priorities found. Review warnings below before launch.");
  } else {
    for (const [index, priority] of priorities.entries()) {
      lines.push(`${index + 1}. ${priority}`);
    }
  }

  lines.push("", "## What Looks Good", "");

  const observations = getWhatLooksGood(report);

  if (observations.length === 0) {
    lines.push("No positive observations to highlight from this scan.");
  } else {
    for (const observation of observations) {
      lines.push(`- ${observation}`);
    }
  }

  lines.push("", "## Issues by Priority", "");

  if (report.issues.length === 0) {
    lines.push("No issues found.");
    appendMarkdownFooter(lines);
    return `${lines.join("\n").trimEnd()}\n`;
  }

  const sortedIssues = getSortedDisplayIssues(report.issues);
  const severityOrder: IssueSeverity[] = ["critical", "warning", "info"];

  for (const severity of severityOrder) {
    const severityIssues = sortedIssues.filter((issue) => issue.severity === severity);

    if (severityIssues.length === 0) {
      continue;
    }

    lines.push(`**${getSeverityHeading(severity, severityIssues.length)}**`, "");

    for (const category of categoryOrder) {
      const categoryIssues = severityIssues.filter((issue) => issue.category === category);

      if (categoryIssues.length === 0) {
        continue;
      }

      lines.push(`_${categoryLabels[category]}_`, "");

      for (const issue of categoryIssues) {
        appendMarkdownIssue(lines, issue);
      }
    }
  }

  appendMarkdownFooter(lines);

  return `${lines.join("\n").trimEnd()}\n`;
}

function appendMarkdownFooter(lines: string[]) {
  lines.push("", "## Recommended Next Steps", "");
  lines.push("- Fix critical issues first.");
  lines.push("- Review warnings before launch.");
  lines.push("- Re-run Qodfy after changes.");
  lines.push("- Use `qodfy prompt <issue-id>` for focused AI repair prompts.");
  lines.push("", "## Generated by Qodfy", "");
  lines.push("Qodfy scans locally and does not print secret values in reports.");
}

function escapeHtml(value: string): string {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function renderHtmlReport(report: OutputScanReport): string {
  const projectName = path.basename(report.projectPath) || report.projectPath;
  const statusLabel = getStatusLabel(report.score);
  const statusTone = getStatusTone(report.score);
  const criticalCount = countIssuesBySeverity(report.issues, "critical");
  const warningCount = countIssuesBySeverity(report.issues, "warning");
  const infoCount = countIssuesBySeverity(report.issues, "info");
  const executiveSummary = getExecutiveSummary(report);
  const priorities = getTopPriorities(report.issues);
  const observations = getWhatLooksGood(report);
  const sortedIssues = getSortedDisplayIssues(report.issues);
  const severityOrder: IssueSeverity[] = ["critical", "warning", "info"];

  const summaryCards = [
    { label: "Critical issues", value: criticalCount, tone: criticalCount > 0 ? "critical" : "neutral" },
    { label: "Warnings", value: warningCount, tone: warningCount > 0 ? "warning" : "neutral" },
    { label: "Info", value: infoCount, tone: infoCount > 0 ? "info" : "neutral" },
    { label: "Files scanned", value: report.stats.totalFiles, tone: "neutral" },
    { label: "API routes", value: report.stats.apiRoutes, tone: "neutral" },
    { label: "Scan duration", value: formatDuration(report.stats.durationMs), tone: "neutral" }
  ];

  const summaryCardsHtml = summaryCards
    .map((card) =>
      `        <div class="stat-card stat-${card.tone}">
          <div class="stat-label">${escapeHtml(card.label)}</div>
          <div class="stat-value">${escapeHtml(String(card.value))}</div>
        </div>`
    )
    .join("\n");

  const prioritiesHtml = priorities.length === 0
    ? `<p class="muted">No urgent priorities found. Review warnings below before launch.</p>`
    : `<ol class="priority-list">\n${priorities.map((priority) => `          <li>${escapeHtml(priority)}</li>`).join("\n")}\n        </ol>`;

  const observationsHtml = observations.length === 0
    ? `<p class="muted">No positive observations to highlight from this scan.</p>`
    : `<ul class="observation-list">\n${observations.map((observation) => `          <li>${escapeHtml(observation)}</li>`).join("\n")}\n        </ul>`;

  const issueSectionsHtml = report.issues.length === 0
    ? `<p class="muted">No issues found.</p>`
    : severityOrder
        .map((severity) => renderHtmlSeveritySection(severity, sortedIssues.filter((issue) => issue.severity === severity)))
        .filter(Boolean)
        .join("\n");

  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <meta name="generator" content="Qodfy" />
  <title>Qodfy Launch Readiness Report</title>
  <style>${getHtmlReportStyles()}</style>
</head>
<body>
  <main class="page">
    <header class="hero">
      <p class="eyebrow">Qodfy</p>
      <h1>Launch Readiness Report</h1>
      <dl class="hero-meta">
        <div><dt>Project</dt><dd>${escapeHtml(projectName)}</dd></div>
        <div><dt>Path</dt><dd><code>${escapeHtml(report.projectPath)}</code></dd></div>
        <div><dt>Scan mode</dt><dd>${escapeHtml(report.scanMode)}</dd></div>
        <div><dt>Generated</dt><dd>${escapeHtml(report.generatedAt)}</dd></div>
      </dl>
      <div class="score-card score-${statusTone}">
        <div class="score-value">${escapeHtml(String(report.score))}<span class="score-max">/100</span></div>
        <div class="score-status">${escapeHtml(statusLabel)}</div>
      </div>
    </header>

    <section class="stats" aria-label="Scan summary">
${summaryCardsHtml}
    </section>

    <section class="card" aria-labelledby="executive-summary">
      <h2 id="executive-summary">Executive Summary</h2>
      <p>${escapeHtml(executiveSummary)}</p>
    </section>

    <section class="card" aria-labelledby="top-priorities">
      <h2 id="top-priorities">Top Priorities</h2>
      ${prioritiesHtml}
    </section>

    <section class="card" aria-labelledby="what-looks-good">
      <h2 id="what-looks-good">What Looks Good</h2>
      ${observationsHtml}
    </section>

    <section aria-labelledby="issues-by-priority">
      <h2 id="issues-by-priority">Issues by Priority</h2>
      ${issueSectionsHtml}
    </section>

    <section class="card" aria-labelledby="next-steps">
      <h2 id="next-steps">Recommended Next Steps</h2>
      <ul>
        <li>Fix critical issues first.</li>
        <li>Review warnings before launch.</li>
        <li>Re-run Qodfy after changes.</li>
        <li>Use <code>qodfy prompt &lt;issue-id&gt;</code> for focused AI repair prompts.</li>
      </ul>
    </section>

    <footer class="footer">
      <p><strong>Generated by Qodfy.</strong></p>
      <p class="muted">Qodfy scans locally and does not print secret values in reports.</p>
    </footer>
  </main>
</body>
</html>
`;
}

function renderHtmlSeveritySection(severity: IssueSeverity, issues: Issue[]): string {
  if (issues.length === 0) {
    return "";
  }

  const heading =
    severity === "critical" ? "Critical" :
    severity === "warning" ? "Warnings" :
    "Info";

  const groupsHtml = categoryOrder
    .map((category) => {
      const categoryIssues = issues.filter((issue) => issue.category === category);

      if (categoryIssues.length === 0) {
        return "";
      }

      const cardsHtml = categoryIssues.map(renderHtmlIssueCard).join("\n");

      return `      <div class="category-group">
        <h4 class="category-heading">${escapeHtml(categoryLabels[category])}</h4>
${cardsHtml}
      </div>`;
    })
    .filter(Boolean)
    .join("\n");

  return `    <section class="severity-section severity-${severity}" aria-label="${escapeHtml(heading)} issues">
      <h3 class="severity-heading"><span class="severity-dot"></span>${escapeHtml(heading)} <span class="severity-count">(${issues.length})</span></h3>
${groupsHtml}
    </section>`;
}

function renderHtmlIssueCard(issue: Issue): string {
  const evidenceHtml = renderHtmlEvidenceList(issue.evidence);
  const contextHtml = renderHtmlEvidenceList(issue.context);
  const tests = getAfterFixTests(issue);
  const testsHtml = tests.length === 0
    ? `<p class="muted">No specific tests suggested.</p>`
    : `<ul>\n${tests.map((test) => `              <li>${escapeHtml(test)}</li>`).join("\n")}\n            </ul>`;

  const fileLine = issue.file
    ? `<div class="meta-row"><span class="meta-label">File</span><code class="meta-value">${escapeHtml(issue.file)}</code></div>`
    : "";

  const suggestion = issue.suggestion ?? "No specific suggestion provided for this rule yet.";
  const fixPrompt = issue.fixPrompt ?? "No AI fix prompt available for this rule yet.";

  return `        <article class="issue-card issue-${issue.severity}" aria-labelledby="issue-${escapeHtml(issue.id)}-title">
          <header class="issue-header">
            <div class="issue-badges">
              <span class="badge badge-${issue.severity}">${escapeHtml(issue.severity.toUpperCase())}</span>
              <span class="badge badge-confidence badge-confidence-${issue.confidence}">Confidence: ${escapeHtml(issue.confidence)}</span>
              <span class="badge badge-category">${escapeHtml(categoryLabels[issue.category])}</span>
            </div>
            <h4 id="issue-${escapeHtml(issue.id)}-title" class="issue-title">${escapeHtml(issue.title)}</h4>
            <div class="issue-meta">
              <div class="meta-row"><span class="meta-label">ID</span><code class="meta-value">${escapeHtml(issue.id)}</code></div>
              ${fileLine}
            </div>
          </header>

          <section class="issue-section">
            <h5>What Qodfy found</h5>
            <p>${escapeHtml(issue.message)}</p>
          </section>

          <section class="issue-section">
            <h5>Why it matters</h5>
            <p>${escapeHtml(getWhyItMatters(issue))}</p>
          </section>

          <section class="issue-section">
            <h5>Evidence</h5>
            ${evidenceHtml}
          </section>

          <section class="issue-section">
            <h5>Context</h5>
            ${contextHtml}
          </section>

          <section class="issue-section">
            <h5>Suggested fix</h5>
            <p>${escapeHtml(suggestion)}</p>
          </section>

          <section class="issue-section">
            <h5>AI Fix Prompt</h5>
            <pre class="code-block"><code>${escapeHtml(fixPrompt)}</code></pre>
          </section>

          <section class="issue-section">
            <h5>After fixing, test this</h5>
            ${testsHtml}
          </section>
        </article>`;
}

function renderHtmlEvidenceList(items?: IssueEvidence[]): string {
  if (!items || items.length === 0) {
    return `<p class="muted">None.</p>`;
  }

  const listItems = items
    .map((item) => {
      const detail = item.detail ? `: <code>${escapeHtml(item.detail)}</code>` : "";
      return `              <li><strong>${escapeHtml(item.label)}</strong>${detail}</li>`;
    })
    .join("\n");

  return `<ul class="evidence-list">\n${listItems}\n            </ul>`;
}

function getStatusTone(score: number): "ready" | "almost" | "needs-fixes" | "not-ready" {
  if (score >= 90) {
    return "ready";
  }

  if (score >= 75) {
    return "almost";
  }

  if (score >= 50) {
    return "needs-fixes";
  }

  return "not-ready";
}

function getHtmlReportStyles(): string {
  return `
    *, *::before, *::after { box-sizing: border-box; }
    html { -webkit-text-size-adjust: 100%; }
    body {
      margin: 0;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
      background: #f6f7fb;
      color: #1f2330;
      line-height: 1.55;
    }
    code, pre {
      font-family: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, "Liberation Mono", monospace;
    }
    .page {
      max-width: 960px;
      margin: 0 auto;
      padding: 32px 20px 64px;
    }
    .eyebrow {
      margin: 0 0 4px;
      font-size: 12px;
      font-weight: 600;
      letter-spacing: 0.12em;
      text-transform: uppercase;
      color: #5b6478;
    }
    h1 {
      margin: 0 0 16px;
      font-size: 28px;
      font-weight: 700;
      letter-spacing: -0.01em;
    }
    h2 {
      margin: 0 0 12px;
      font-size: 20px;
      font-weight: 700;
      letter-spacing: -0.005em;
    }
    h3 {
      margin: 0 0 12px;
      font-size: 16px;
      font-weight: 700;
    }
    h4 {
      margin: 0 0 8px;
      font-size: 16px;
      font-weight: 600;
    }
    h5 {
      margin: 16px 0 6px;
      font-size: 13px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.06em;
      color: #5b6478;
    }
    p { margin: 0 0 12px; }
    p:last-child { margin-bottom: 0; }
    ul, ol { margin: 0 0 12px; padding-left: 22px; }
    ul li, ol li { margin: 4px 0; }
    .muted { color: #6b7384; }
    .hero {
      background: #ffffff;
      border: 1px solid #e6e8ef;
      border-radius: 16px;
      padding: 24px;
      box-shadow: 0 1px 2px rgba(15, 23, 42, 0.04);
      margin-bottom: 20px;
      display: grid;
      gap: 16px;
    }
    .hero-meta {
      margin: 0;
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 12px 24px;
    }
    .hero-meta div { display: flex; flex-direction: column; gap: 2px; min-width: 0; }
    .hero-meta dt {
      font-size: 11px;
      font-weight: 600;
      letter-spacing: 0.08em;
      text-transform: uppercase;
      color: #5b6478;
    }
    .hero-meta dd {
      margin: 0;
      font-size: 14px;
      color: #1f2330;
      word-break: break-word;
    }
    .hero-meta code {
      font-size: 12px;
      background: #f1f3f8;
      padding: 2px 6px;
      border-radius: 6px;
    }
    .score-card {
      border-radius: 12px;
      padding: 16px 20px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 16px;
      border: 1px solid transparent;
    }
    .score-card .score-value {
      font-size: 36px;
      font-weight: 700;
      letter-spacing: -0.02em;
    }
    .score-card .score-max {
      font-size: 18px;
      font-weight: 500;
      color: #5b6478;
      margin-left: 2px;
    }
    .score-card .score-status {
      font-size: 14px;
      font-weight: 600;
      padding: 6px 10px;
      border-radius: 999px;
      background: rgba(255,255,255,0.6);
    }
    .score-ready { background: #ecfdf5; border-color: #a7f3d0; color: #065f46; }
    .score-ready .score-status { background: #d1fae5; color: #065f46; }
    .score-almost { background: #f0f9ff; border-color: #bae6fd; color: #075985; }
    .score-almost .score-status { background: #e0f2fe; color: #075985; }
    .score-needs-fixes { background: #fffbeb; border-color: #fcd34d; color: #92400e; }
    .score-needs-fixes .score-status { background: #fef3c7; color: #92400e; }
    .score-not-ready { background: #fef2f2; border-color: #fecaca; color: #991b1b; }
    .score-not-ready .score-status { background: #fee2e2; color: #991b1b; }
    .stats {
      display: grid;
      grid-template-columns: repeat(3, minmax(0, 1fr));
      gap: 12px;
      margin-bottom: 20px;
    }
    .stat-card {
      background: #ffffff;
      border: 1px solid #e6e8ef;
      border-radius: 12px;
      padding: 14px 16px;
      box-shadow: 0 1px 2px rgba(15, 23, 42, 0.04);
    }
    .stat-label {
      font-size: 11px;
      font-weight: 600;
      letter-spacing: 0.08em;
      text-transform: uppercase;
      color: #5b6478;
    }
    .stat-value {
      margin-top: 4px;
      font-size: 22px;
      font-weight: 700;
      letter-spacing: -0.01em;
    }
    .stat-critical .stat-value { color: #b91c1c; }
    .stat-warning .stat-value { color: #b45309; }
    .stat-info .stat-value { color: #1d4ed8; }
    .card {
      background: #ffffff;
      border: 1px solid #e6e8ef;
      border-radius: 12px;
      padding: 20px;
      margin-bottom: 16px;
      box-shadow: 0 1px 2px rgba(15, 23, 42, 0.04);
    }
    .priority-list, .observation-list { margin-bottom: 0; }
    .severity-section {
      background: #ffffff;
      border: 1px solid #e6e8ef;
      border-radius: 14px;
      padding: 20px;
      margin-bottom: 16px;
      box-shadow: 0 1px 2px rgba(15, 23, 42, 0.04);
    }
    .severity-heading {
      display: flex;
      align-items: center;
      gap: 10px;
      font-size: 18px;
      margin-bottom: 16px;
    }
    .severity-dot {
      width: 10px;
      height: 10px;
      border-radius: 999px;
      display: inline-block;
      background: #94a3b8;
    }
    .severity-critical .severity-dot { background: #dc2626; }
    .severity-warning .severity-dot { background: #d97706; }
    .severity-info .severity-dot { background: #2563eb; }
    .severity-count { color: #6b7384; font-weight: 500; }
    .category-group { margin-top: 16px; }
    .category-group:first-of-type { margin-top: 0; }
    .category-heading {
      font-size: 12px;
      font-weight: 700;
      letter-spacing: 0.08em;
      text-transform: uppercase;
      color: #5b6478;
      margin-bottom: 10px;
    }
    .issue-card {
      border: 1px solid #e6e8ef;
      border-radius: 12px;
      padding: 18px 20px;
      margin-bottom: 12px;
      background: #fbfbfd;
      border-left-width: 4px;
    }
    .issue-critical { border-left-color: #dc2626; }
    .issue-warning { border-left-color: #d97706; }
    .issue-info { border-left-color: #2563eb; }
    .issue-header { margin-bottom: 8px; }
    .issue-badges {
      display: flex;
      flex-wrap: wrap;
      gap: 6px;
      margin-bottom: 8px;
    }
    .badge {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      font-size: 11px;
      font-weight: 700;
      letter-spacing: 0.04em;
      padding: 3px 8px;
      border-radius: 999px;
      background: #eef0f5;
      color: #1f2330;
      text-transform: uppercase;
    }
    .badge-critical { background: #fee2e2; color: #991b1b; }
    .badge-warning { background: #fef3c7; color: #92400e; }
    .badge-info { background: #dbeafe; color: #1e40af; }
    .badge-confidence {
      background: #eef0f5;
      color: #334155;
      text-transform: none;
      font-weight: 600;
      letter-spacing: 0;
    }
    .badge-confidence-high { background: #dcfce7; color: #166534; }
    .badge-confidence-medium { background: #fef3c7; color: #92400e; }
    .badge-confidence-low { background: #e0e7ff; color: #3730a3; }
    .badge-category {
      background: #eef0f5;
      color: #475569;
      text-transform: none;
      font-weight: 600;
      letter-spacing: 0;
    }
    .issue-title {
      margin: 4px 0 8px;
      font-size: 16px;
      font-weight: 700;
      color: #0f172a;
    }
    .issue-meta {
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 6px 16px;
    }
    .meta-row { display: flex; gap: 6px; align-items: baseline; min-width: 0; }
    .meta-label {
      font-size: 11px;
      font-weight: 700;
      letter-spacing: 0.06em;
      text-transform: uppercase;
      color: #5b6478;
    }
    .meta-value {
      font-size: 12px;
      background: #f1f3f8;
      padding: 2px 6px;
      border-radius: 6px;
      word-break: break-all;
    }
    .issue-section { margin-top: 8px; }
    .issue-section p { margin: 0; }
    .evidence-list { margin: 0; }
    .code-block {
      margin: 0;
      padding: 12px 14px;
      background: #0f172a;
      color: #e2e8f0;
      border-radius: 10px;
      overflow: auto;
      font-size: 12.5px;
      line-height: 1.55;
      white-space: pre-wrap;
      word-break: break-word;
    }
    .footer {
      margin-top: 24px;
      padding: 20px;
      border-radius: 12px;
      background: #ffffff;
      border: 1px solid #e6e8ef;
      text-align: center;
    }
    @media (max-width: 720px) {
      .page { padding: 20px 14px 48px; }
      h1 { font-size: 24px; }
      .hero-meta, .stats, .issue-meta { grid-template-columns: 1fr; }
      .stats { gap: 8px; }
      .score-card { flex-direction: column; align-items: flex-start; }
    }
  `;
}

function appendMarkdownIssue(lines: string[], issue: Issue) {
  lines.push(`### ${issue.title}`);
  lines.push("");
  lines.push(`- ID: \`${issue.id}\``);
  lines.push(`- Severity: ${issue.severity}`);
  lines.push(`- Confidence: ${issue.confidence}`);
  lines.push(`- Category: ${categoryLabels[issue.category]}`);

  if (issue.file) {
    lines.push(`- File: \`${issue.file}\``);
  }

  lines.push("");
  lines.push("#### What Qodfy found");
  lines.push("");
  lines.push(issue.message);
  lines.push("");
  lines.push("#### Why it matters");
  lines.push("");
  lines.push(getWhyItMatters(issue));
  lines.push("");
  lines.push("#### Evidence");
  lines.push("");
  appendMarkdownEvidence(lines, issue.evidence);
  lines.push("");
  lines.push("#### Context");
  lines.push("");
  appendMarkdownEvidence(lines, issue.context);
  lines.push("");
  lines.push("#### Suggested fix");
  lines.push("");
  lines.push(issue.suggestion ?? "No specific suggestion provided for this rule yet.");
  lines.push("");
  lines.push("#### AI Fix Prompt");
  lines.push("");
  lines.push("```txt");
  lines.push(issue.fixPrompt ?? "No AI fix prompt available for this rule yet.");
  lines.push("```");
  lines.push("");
  lines.push("#### After fixing, test this");
  lines.push("");

  for (const test of getAfterFixTests(issue)) {
    lines.push(`- ${test}`);
  }

  lines.push("");
}

function appendMarkdownEvidence(lines: string[], items?: IssueEvidence[]) {
  if (!items || items.length === 0) {
    lines.push("- None");
    return;
  }

  for (const item of items) {
    const detail = item.detail ? `: ${item.detail}` : "";
    lines.push(`- ${item.label}${detail}`);
  }
}

function getStatusLabel(score: number) {
  if (score >= 90) {
    return "Ready with minor review";
  }

  if (score >= 75) {
    return "Almost ready";
  }

  if (score >= 50) {
    return "Needs fixes before launch";
  }

  return "Not ready to launch";
}

function getSeverityHeading(severity: IssueSeverity, count: number) {
  const noun =
    severity === "critical" ? "Critical" :
    severity === "warning" ? "Warnings" :
    "Info";

  return `${noun} (${count})`;
}

function getExecutiveSummary(report: OutputScanReport) {
  const issues = report.issues;
  const criticalCount = countIssuesBySeverity(issues, "critical");
  const warningCount = countIssuesBySeverity(issues, "warning");
  const topRiskCategory = getTopRiskCategory(issues);

  const sentences: string[] = [];

  if (criticalCount > 0) {
    const issueWord = criticalCount === 1 ? "critical issue" : "critical issues";
    sentences.push(
      `Qodfy found ${criticalCount} ${issueWord} that should be fixed before launch.`
    );
  } else if (warningCount > 0) {
    sentences.push(
      "Qodfy found no critical blockers. Review the warnings below before launch."
    );
  } else if (issues.length > 0) {
    sentences.push(
      "Qodfy found no critical or warning blockers. Review the info notes below before launch."
    );
  } else {
    sentences.push(
      "Qodfy did not flag any issues. Do a final manual review and you should be good to launch."
    );
  }

  if (topRiskCategory) {
    sentences.push(`The main area to review is ${topRiskCategory}.`);
  }

  sentences.push(
    `Score: ${report.score}/100. Launch status: ${getStatusLabel(report.score)}.`
  );

  return sentences.join(" ");
}

function getTopRiskCategory(issues: Issue[]): string | null {
  if (issues.length === 0) {
    return null;
  }

  const weights = new Map<IssueCategory, number>();

  for (const issue of issues) {
    const weight =
      issue.severity === "critical" ? 1000 :
      issue.severity === "warning" ? 10 :
      1;

    weights.set(issue.category, (weights.get(issue.category) ?? 0) + weight);
  }

  let topCategory: IssueCategory | null = null;
  let topWeight = 0;
  let topOrder = Number.MAX_SAFE_INTEGER;

  for (const [category, weight] of weights) {
    const order = categoryOrder.indexOf(category);

    if (
      weight > topWeight ||
      (weight === topWeight && order < topOrder)
    ) {
      topWeight = weight;
      topCategory = category;
      topOrder = order;
    }
  }

  if (!topCategory) {
    return null;
  }

  return getCategoryShortName(topCategory);
}

function getCategoryShortName(category: IssueCategory) {
  if (category === "security") {
    return "security";
  }

  if (category === "api") {
    return "API routes";
  }

  if (category === "webhook") {
    return "webhooks";
  }

  if (category === "ai") {
    return "AI routes";
  }

  if (category === "environment") {
    return "environment variables";
  }

  if (category === "maintainability") {
    return "maintainability";
  }

  return "project setup";
}

function getWhatLooksGood(report: OutputScanReport): string[] {
  const observations: string[] = [];
  const issues = report.issues;
  const checks = new Set<ScanCheck>(report.checks);
  const criticalCount = countIssuesBySeverity(issues, "critical");

  if (criticalCount === 0) {
    observations.push("No critical issues found.");
  }

  observations.push("Local source scan completed successfully.");

  if (checks.has("api") && report.stats.apiRoutes > 0) {
    observations.push("API routes were analyzed method by method.");
  }

  const hasPublicReadRouteNote = issues.some(
    (issue) => issue.ruleId === "api-public-read-route"
  );

  if (hasPublicReadRouteNote) {
    observations.push("Public read routes were separated from protected routes.");
  }

  if (checks.has("environment")) {
    const hasEnvIssue = issues.some((issue) => issue.category === "environment");

    if (!hasEnvIssue) {
      observations.push("Environment variable documentation looks complete.");
    }
  }

  if (checks.has("webhook")) {
    const hasWebhookSignatureIssue = issues.some(
      (issue) => issue.ruleId === "webhook-missing-signature-verification"
    );

    if (!hasWebhookSignatureIssue) {
      observations.push("No webhook routes were flagged for missing signature checks.");
    }
  }

  if (checks.has("ai")) {
    const hasAiRateIssue = issues.some(
      (issue) => issue.ruleId === "ai-route-missing-rate-limit"
    );

    if (!hasAiRateIssue && report.stats.aiFiles > 0) {
      observations.push("AI routes were not flagged as missing rate limiting.");
    }
  }

  if (checks.has("security")) {
    const hasSecretIssue = issues.some(
      (issue) =>
        issue.ruleId === "security-hardcoded-secret" ||
        issue.ruleId === "security-client-side-secret"
    );

    if (!hasSecretIssue) {
      observations.push("No hardcoded or client-side secrets were detected.");
    }
  }

  observations.push("Qodfy did not print any secret values in this report.");

  return observations;
}

function getWhyItMatters(issue: Issue): string {
  const ruleExplanation = getWhyItMattersByRuleId(issue.ruleId);

  if (ruleExplanation) {
    return ruleExplanation;
  }

  return getWhyItMattersByCategory(issue.category);
}

function getWhyItMattersByRuleId(ruleId: string): string | null {
  switch (ruleId) {
    case "admin-route-missing-authorization":
      return "This route is authenticated, but admin/debug/private routes often need an extra role or permission check. A normal logged-in user should not be able to access admin-only data or tools.";
    case "public-form-missing-abuse-protection":
      return "Public forms can be abused by bots or repeated submissions. Validation helps data quality, but rate limiting or spam protection helps prevent abuse.";
    case "webhook-missing-signature-verification":
      return "Webhook routes receive external events. Without signature verification, attackers may be able to fake events and trick your app into running real actions.";
    case "environment-variable-missing-from-example":
      return "Missing env documentation makes the project harder to deploy or maintain. Future developers (and future you) will not know which variables are required.";
    case "environment-missing-env-example":
      return "Without a .env.example, anyone setting up this project has to guess which environment variables are required. That guesswork leads to broken deploys and runtime errors.";
    case "ai-route-missing-rate-limit":
      return "AI routes can create real API costs. Rate limiting helps control abuse and unexpected spend, especially if a route is exposed to anonymous users.";
    case "security-hardcoded-secret":
      return "Hardcoded secrets can leak through git history, public deploys, or AI tools that read your code. Rotate any real values and load them from environment variables instead.";
    case "security-client-side-secret":
      return "Secrets used in client-side code are visible to anyone who opens the browser devtools. Move sensitive values and logic to server-only code.";
    case "sensitive-api-route-missing-auth":
      return "API routes that handle sensitive data should verify the caller is authenticated before reading or writing. Without that check, anonymous users may access protected information.";
    case "api-mutation-route-review-auth":
      return "Routes that mutate data without an obvious auth check can let anyone create, update, or delete records. Review the auth path before launch.";
    case "internal-route-missing-protection":
      return "Internal or operational routes (debug, admin, jobs) are often forgotten before launch. Without protection they can expose admin-only behavior to the public.";
    case "api-public-read-route":
      return "This is a public read route. Confirm the data exposed here is safe to share with anonymous visitors and that no sensitive fields are leaking.";
    case "maintainability-large-file":
      return "Large files are harder to review, refactor, and test. Splitting them now reduces future cleanup cost and makes AI tools more reliable on this codebase.";
    case "maintainability-large-file-skipped":
      return "Some files were too large for Qodfy to read fully. Review them manually before launch in case they hide other issues.";
    case "maintainability-file-unreadable":
      return "Files Qodfy could not read may indicate encoding, permission, or generated-output issues that hide real problems from this scan.";
    case "project-missing-package-json":
      return "Without a package.json, Qodfy cannot fully reason about your project. Confirm Qodfy is pointed at the correct project root.";
    case "project-invalid-package-json":
      return "An invalid package.json blocks tooling, installs, and deploys. Fix the JSON before running other launch checks.";
    case "project-next-not-detected":
      return "Qodfy is currently optimized for Next.js apps. If this is a Next.js project, double-check dependencies and folder structure before launch.";
    case "project-missing-readme":
      return "A short README helps anyone (including future you) understand what this project does and how to run it.";
    case "project-source-files-unreadable":
      return "Some source files could not be read. Review them manually so the scan does not silently skip risky areas of the code.";
    default:
      return null;
  }
}

function getWhyItMattersByCategory(category: IssueCategory): string {
  switch (category) {
    case "security":
      return "Security risks can leak data, expose secrets, or grant unwanted access to your app. These should be the first issues you review before launch.";
    case "api":
      return "API routes shape what your app exposes to the internet. Confirm that authentication, input validation, and abuse protection match what each route does.";
    case "webhook":
      return "Webhooks receive events from external systems. Verifying signatures prevents fake or replayed events from being trusted by your app.";
    case "ai":
      return "AI routes have unique cost and abuse risks. Rate limits and usage caps protect your spend and keep the service usable for real users.";
    case "environment":
      return "Environment variables control how your app connects to external services. Missing or undocumented variables cause deploy failures and runtime errors.";
    case "maintainability":
      return "Maintainability signals do not block launch but slow future work. Cleaning them up early reduces friction later.";
    case "project":
      return "Project setup signals affect tooling, deploys, and onboarding. Fixing them early prevents surprises later in the launch.";
  }
}

function getAfterFixTests(issue: Issue): string[] {
  const ruleTests = getAfterFixTestsByRuleId(issue.ruleId);

  if (ruleTests) {
    return ruleTests;
  }

  return getDefaultAfterFixTests();
}

function getAfterFixTestsByRuleId(ruleId: string): string[] | null {
  switch (ruleId) {
    case "admin-route-missing-authorization":
      return [
        "Test as an unauthenticated user.",
        "Test as a normal logged-in user.",
        "Test as an admin/staff user.",
        "Confirm non-admin users receive 403."
      ];
    case "public-form-missing-abuse-protection":
      return [
        "Submit a valid form and confirm it still works.",
        "Submit invalid input and confirm validation returns 400.",
        "Send repeated requests and confirm rate limiting or spam protection behavior.",
        "Confirm no sensitive provider/API error details are exposed."
      ];
    case "webhook-missing-signature-verification":
      return [
        "Test a valid signed webhook.",
        "Test an invalid signature.",
        "Confirm invalid requests are rejected before processing.",
        "Confirm the event is not processed twice."
      ];
    case "environment-missing-env-example":
    case "environment-variable-missing-from-example":
      return [
        "Add the variable name to .env.example without a real value.",
        "Run the app locally with required env values.",
        "Confirm deployment docs or hosting env vars are updated."
      ];
    case "ai-route-missing-rate-limit":
      return [
        "Send a normal AI request.",
        "Send repeated requests and confirm rate limiting.",
        "Confirm rejected requests do not call the AI provider.",
        "Check logs/cost controls after testing."
      ];
    case "sensitive-api-route-missing-auth":
    case "api-mutation-route-review-auth":
      return [
        "Test unauthenticated access.",
        "Test authenticated access.",
        "Confirm unauthorized users receive 401 or 403.",
        "Confirm existing response formats still work."
      ];
    case "internal-route-missing-protection":
      return [
        "Test without the secret/auth guard.",
        "Test with a valid secret/auth guard.",
        "Confirm invalid requests are rejected before internal work runs."
      ];
    case "security-hardcoded-secret":
    case "security-client-side-secret":
      return [
        "Rotate any real secret values that were exposed.",
        "Confirm the secret is loaded from environment variables, not source code.",
        "Re-run Qodfy and confirm the issue no longer appears.",
        "Check git history and remove any committed real values if needed."
      ];
    case "api-public-read-route":
      return [
        "Confirm the data exposed here is safe to share with anonymous users.",
        "Test the route as an anonymous visitor.",
        "Confirm no sensitive fields leak in the response."
      ];
    default:
      return null;
  }
}

function getDefaultAfterFixTests(): string[] {
  return [
    "Re-run Qodfy after the fix.",
    "Test the affected route or file manually.",
    "Confirm existing behavior still works.",
    "Check logs for unexpected errors."
  ];
}

function printReport(
  report: ScanReport,
  maxIssues: number,
  showPrompts: boolean,
  scanModeLabel: string,
  showDetails: boolean,
  showAllIssues: boolean
) {
  console.log(pc.bold("Qodfy Report"));
  console.log("");

  const scoreColor =
    report.score >= 80 ? pc.green :
    report.score >= 60 ? pc.yellow :
    pc.red;

  console.log(`Launch Readiness: ${scoreColor(`${report.score}/100`)}`);
  console.log(`Scan mode: ${scanModeLabel}`);
  console.log("");

  console.log(pc.bold("Stats"));
  console.log(`Files scanned: ${report.stats.totalFiles}`);
  console.log(`API routes: ${report.stats.apiRoutes}`);
  console.log(`AI-related files: ${report.stats.aiFiles}`);
  console.log(`Large files: ${report.stats.largeFiles}`);
  console.log(`Scan duration: ${formatDuration(report.stats.durationMs)}`);
  console.log("");

  printSummary(report.issues);

  if (report.issues.length === 0) {
    console.log(pc.green("No issues found. Your project looks clean."));
    return;
  }

  console.log(pc.bold(showAllIssues ? "Issues" : "Top issues"));
  const displayIssues = getSortedDisplayIssues(report.issues);
  const issueLimit = showAllIssues ? displayIssues.length : maxIssues;
  const issuesToShow = displayIssues.slice(0, issueLimit);

  if (report.issues.length > issueLimit) {
    console.log(`Showing ${issueLimit} of ${report.issues.length} issues.`);
    console.log(`Use --max-issues <number> to show more, or --all for full details.`);
  }

  printGroupedIssues(issuesToShow, showPrompts, showDetails, report.projectPath);

  console.log("");
  console.log(pc.bold("Recommended next step:"));
  console.log("Fix critical issues first, then warnings, then cleanup items.");
  console.log("");
  console.log(pc.bold("Next commands:"));
  const firstPromptIssue = issuesToShow.find((issue) => issue.fixPrompt);

  if (firstPromptIssue) {
    console.log(getPromptCommand(firstPromptIssue.id, report.projectPath));
  }

  console.log("qodfy scan --checks api,environment");
  console.log("qodfy scan --all");
}

function printSummary(issues: Issue[]) {
  const criticalCount = countIssuesBySeverity(issues, "critical");
  const warningCount = countIssuesBySeverity(issues, "warning");
  const infoCount = countIssuesBySeverity(issues, "info");

  console.log(pc.bold("Summary"));
  console.log(`Critical: ${criticalCount}`);
  console.log(`Warnings: ${warningCount}`);
  console.log(`Info: ${infoCount}`);
  console.log("");

  if (issues.length === 0) {
    return;
  }

  console.log(pc.bold("Categories"));

  for (const category of categoryOrder) {
    const count = issues.filter((issue) => issue.category === category).length;

    if (count > 0) {
      console.log(`${categoryLabels[category]}: ${count}`);
    }
  }

  const priorities = getTopPriorities(issues);

  if (priorities.length > 0) {
    console.log("");
    console.log(pc.bold("Top priorities"));

    for (const [index, priority] of priorities.entries()) {
      console.log(`${index + 1}. ${priority}`);
    }
  }

  console.log("");
}

function printGroupedIssues(
  issues: Issue[],
  showPrompts: boolean,
  showDetails: boolean,
  projectPath: string
) {
  for (const category of categoryOrder) {
    const categoryIssues = issues.filter((issue) => issue.category === category);

    if (categoryIssues.length === 0) {
      continue;
    }

    console.log("");
    console.log(pc.bold(categoryLabels[category]));

    for (const issue of categoryIssues) {
      printIssue(issue, showPrompts, showDetails, projectPath);
    }
  }
}

function printIssue(
  issue: Issue,
  showPrompts: boolean,
  showDetails: boolean,
  projectPath: string
) {
  console.log("");
  console.log(`${pc.dim(`[${issue.id}]`)} ${getSeverityLabel(issue.severity)} ${pc.bold(issue.title)}`);
  console.log(pc.dim(`Confidence: ${issue.confidence}`));

  if (issue.file) {
    console.log(pc.dim(`File: ${issue.file}`));
  }

  if (showDetails || showPrompts) {
    console.log(issue.message);
  }

  if ((showDetails || showPrompts) && issue.evidence && issue.evidence.length > 0) {
    printEvidence(issue.evidence);
  }

  if ((showDetails || showPrompts) && issue.context && issue.context.length > 0) {
    printContext(issue.context);
  }

  if ((showDetails || showPrompts) && issue.suggestion) {
    console.log(pc.dim(`Suggestion: ${issue.suggestion}`));
  }

  if (showPrompts && issue.fixPrompt) {
    console.log("");
    console.log(pc.bold("Fix Prompt:"));
    console.log(issue.fixPrompt);
  } else if (issue.fixPrompt) {
    console.log(pc.dim(`Fix: ${getPromptCommand(issue.id, projectPath)}`));
  }
}

function printFixPrompt(issue: Issue) {
  console.log(pc.bold("Qodfy Fix Prompt"));
  console.log("");
  console.log(`${pc.dim(`[${issue.id}]`)} ${getSeverityLabel(issue.severity)} ${pc.bold(issue.title)}`);
  console.log(pc.dim(`Confidence: ${issue.confidence}`));

  if (issue.file) {
    console.log(pc.dim(`File: ${issue.file}`));
  }

  if (issue.evidence && issue.evidence.length > 0) {
    printEvidence(issue.evidence);
  }

  if (issue.context && issue.context.length > 0) {
    printContext(issue.context);
  }

  console.log("");
  console.log(issue.fixPrompt);
}

function printEvidence(evidence: NonNullable<Issue["evidence"]>) {
  console.log("");
  console.log(pc.bold("Evidence:"));

  for (const item of evidence) {
    const detail = item.detail ? ` ${item.detail}` : "";
    console.log(pc.dim(`- ${item.label}${detail}`));
  }
}

function printContext(context: NonNullable<Issue["context"]>) {
  console.log("");
  console.log(pc.bold("Context:"));

  for (const item of context) {
    const detail = item.detail ? ` ${item.detail}` : "";
    console.log(pc.dim(`- ${item.label}${detail}`));
  }
}

function printPromptFromReport(report: ScanReport, issueId: string) {
  const issue = report.issues.find((scanIssue) => scanIssue.id === issueId);

  if (!issue) {
    printPromptError(
      `Issue "${issueId}" was not found in this project scan.\nRun qodfy scan --all to see the current issue IDs.`
    );
    process.exitCode = 1;
    return;
  }

  if (!issue.fixPrompt) {
    printPromptError(`Issue "${issueId}" does not have an AI fix prompt yet.`);
    process.exitCode = 1;
    return;
  }

  printFixPrompt(issue);
}

function getSeverityText(severity: IssueSeverity) {
  if (severity === "critical") {
    return "CRITICAL";
  }

  if (severity === "warning") {
    return "WARNING";
  }

  return "INFO";
}

function getSeverityLabel(severity: IssueSeverity) {
  if (severity === "critical") {
    return pc.red(getSeverityText(severity));
  }

  if (severity === "warning") {
    return pc.yellow(getSeverityText(severity));
  }

  return pc.blue(getSeverityText(severity));
}

function countIssuesBySeverity(issues: Issue[], severity: IssueSeverity) {
  return issues.filter((issue) => issue.severity === severity).length;
}

function getSortedDisplayIssues(issues: Issue[]) {
  return [...issues].sort((leftIssue, rightIssue) => {
    return (
      getSeverityRank(leftIssue.severity) - getSeverityRank(rightIssue.severity) ||
      getConfidenceRank(leftIssue.confidence) - getConfidenceRank(rightIssue.confidence) ||
      categoryOrder.indexOf(leftIssue.category) - categoryOrder.indexOf(rightIssue.category) ||
      leftIssue.ruleId.localeCompare(rightIssue.ruleId) ||
      getIssueNumber(leftIssue.id) - getIssueNumber(rightIssue.id) ||
      (leftIssue.file ?? "").localeCompare(rightIssue.file ?? "") ||
      leftIssue.id.localeCompare(rightIssue.id)
    );
  });
}

function getIssueNumber(issueId: string) {
  const match = issueId.match(/-(\d+)$/);
  return match ? Number.parseInt(match[1], 10) : 0;
}

function getSeverityRank(severity: IssueSeverity) {
  if (severity === "critical") {
    return 0;
  }

  if (severity === "warning") {
    return 1;
  }

  return 2;
}

function getConfidenceRank(confidence: IssueConfidence) {
  if (confidence === "high") {
    return 0;
  }

  if (confidence === "medium") {
    return 1;
  }

  return 2;
}

function getTopPriorities(issues: Issue[]) {
  const priorities: Array<{ ruleIds: string[]; message: string }> = [
    {
      ruleIds: ["security-hardcoded-secret"],
      message: "Remove possible hardcoded secrets and rotate any real exposed values."
    },
    {
      ruleIds: ["webhook-missing-signature-verification"],
      message: "Verify webhook signatures before handling external events."
    },
    {
      ruleIds: ["ai-route-missing-rate-limit"],
      message: "Add cost and abuse protection to AI-related API routes."
    },
    {
      ruleIds: ["security-client-side-secret"],
      message: "Move possible server-only secrets out of client-side code."
    },
    {
      ruleIds: [
        "sensitive-api-route-missing-auth",
        "api-mutation-route-review-auth"
      ],
      message: "Review API routes that may be missing authentication."
    },
    {
      ruleIds: ["internal-route-missing-protection"],
      message: "Protect internal or operational API routes before launch."
    },
    {
      ruleIds: ["admin-route-missing-authorization"],
      message: "Confirm admin/private routes have role or permission checks."
    },
    {
      ruleIds: ["public-form-missing-abuse-protection"],
      message: "Add abuse protection to public form routes."
    },
    {
      ruleIds: [
        "environment-missing-env-example",
        "environment-variable-missing-from-example"
      ],
      message: "Add missing environment variables to .env.example."
    },
    {
      ruleIds: [
        "maintainability-large-file",
        "maintainability-large-file-skipped"
      ],
      message: "Review large files for maintainability before launch."
    },
    {
      ruleIds: [
        "project-missing-package-json",
        "project-invalid-package-json",
        "project-next-not-detected"
      ],
      message: "Confirm Qodfy is scanning the correct project root."
    }
  ];

  return priorities
    .filter((priority) =>
      issues.some((issue) => priority.ruleIds.includes(issue.ruleId))
    )
    .slice(0, 3)
    .map((priority) => priority.message);
}

function getPromptCommand(issueId: string, projectPath: string) {
  const relativeProjectPath = path.relative(process.cwd(), projectPath);
  const promptPath = getPromptPath(projectPath, relativeProjectPath);
  const pathOption = promptPath ? ` --path ${shellQuote(promptPath)}` : "";

  return `qodfy prompt ${issueId}${pathOption}`;
}

function getPromptPath(projectPath: string, relativeProjectPath: string) {
  if (!relativeProjectPath) {
    return "";
  }

  if (!relativeProjectPath.startsWith("..") && !path.isAbsolute(relativeProjectPath)) {
    return relativeProjectPath;
  }

  return projectPath;
}

function shellQuote(value: string) {
  if (/^[A-Za-z0-9_./:-]+$/.test(value)) {
    return value;
  }

  return `'${value.replaceAll("'", "'\\''")}'`;
}

function printScanError(reason: string, useColor = true) {
  console.error(useColor ? pc.red("Qodfy could not scan this project.") : "Qodfy could not scan this project.");
  console.error("");
  console.error(useColor ? pc.bold("Reason:") : "Reason:");
  console.error(reason);
  console.error("");
  console.error(useColor ? pc.bold("Try:") : "Try:");
  console.error("qodfy scan --path ./my-next-app");
}

function printPromptError(reason: string) {
  console.error(pc.red("Qodfy could not create this fix prompt."));
  console.error("");
  console.error(pc.bold("Reason:"));
  console.error(reason);
  console.error("");
  console.error(pc.bold("Try:"));
  console.error("qodfy scan --all");
}

function getErrorMessage(error: unknown) {
  if (error instanceof Error && error.message) {
    return error.message;
  }

  return "An unexpected error occurred while scanning the project.";
}

function isPromptCancelError(error: unknown) {
  return (
    error instanceof Error &&
    (
      error.name === "ExitPromptError" ||
      error.message.includes("User force closed the prompt")
    )
  );
}

function parseMaxIssues(maxIssues: string) {
  const parsedMaxIssues = Number.parseInt(maxIssues, 10);

  if (!Number.isFinite(parsedMaxIssues) || parsedMaxIssues <= 0) {
    return DEFAULT_MAX_ISSUES;
  }

  return parsedMaxIssues;
}

function formatDuration(durationMs: number) {
  if (durationMs < 1000) {
    return `${durationMs}ms`;
  }

  return `${(durationMs / 1000).toFixed(1)}s`;
}

function getErrorCode(error: unknown) {
  if (
    error &&
    typeof error === "object" &&
    "code" in error &&
    typeof error.code === "string"
  ) {
    return error.code;
  }

  return undefined;
}
