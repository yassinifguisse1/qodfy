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
  type IssueSeverity,
  type ScanCheck,
  type ScanReport
} from "@qodfy/core";

type PathValidationResult =
  | { ok: true; projectPath: string }
  | { ok: false; reason: string };

type ScanModeResult =
  | { ok: true; checks: ScanCheck[]; label: string; notice?: string }
  | { ok: false; reason: string };

type ScanCommandOptions = {
  path: string;
  maxIssues: string;
  prompts?: boolean;
  checks?: string;
  all?: boolean;
  interactive?: boolean;
};

type ScanMode = "recommended" | "security-api" | "environment" | "ai" | "webhook" | "maintainability" | "custom";

const DEFAULT_MAX_ISSUES = 20;

const program = new Command();

program
  .name("qodfy")
  .description("Launch readiness scanner for AI-built apps.")
  .version("0.2.1");

program
  .command("scan")
  .description("Scan a project for launch readiness issues.")
  .option("-p, --path <path>", "Project path to scan", process.cwd())
  .option("--max-issues <number>", "Maximum number of issues to display", String(DEFAULT_MAX_ISSUES))
  .option("--prompts", "Show safe copy-paste fix prompts for displayed issues")
  .option("--checks <checks>", "Comma-separated checks to run")
  .option("--all", "Run all checks without prompting")
  .option("--no-interactive", "Skip interactive prompts and run the recommended scan")
  .action(async (options: ScanCommandOptions) => {
    const pathResult = await resolveProjectPath(options.path);

    if (!pathResult.ok) {
      printScanError(pathResult.reason);
      process.exitCode = 1;
      return;
    }

    try {
      const scanModeResult = await resolveScanMode(options);

      if (!scanModeResult.ok) {
        printScanError(scanModeResult.reason);
        process.exitCode = 1;
        return;
      }

      if (scanModeResult.notice) {
        console.log(pc.dim(scanModeResult.notice));
        console.log("");
      }

      console.log(pc.cyan("Qodfy is scanning your project...\n"));

      const report = await scanProject({
        projectPath: pathResult.projectPath,
        checks: scanModeResult.checks
      });

      printReport(
        report,
        parseMaxIssues(options.maxIssues),
        Boolean(options.prompts),
        scanModeResult.label
      );
    } catch (error) {
      if (isPromptCancelError(error)) {
        console.log("Scan cancelled.");
      } else {
        printScanError(getErrorMessage(error));
      }
      process.exitCode = 1;
    }
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
      label: "All checks"
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

function printReport(
  report: ScanReport,
  maxIssues: number,
  showPrompts: boolean,
  scanModeLabel: string
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

  console.log(pc.bold("Issues"));
  const displayIssues = getSortedDisplayIssues(report.issues);
  const issuesToShow = displayIssues.slice(0, maxIssues);

  if (report.issues.length > maxIssues) {
    console.log(`Showing ${maxIssues} of ${report.issues.length} issues.`);
    console.log(`Use --max-issues <number> to show more.`);
  }

  printGroupedIssues(issuesToShow, showPrompts);

  console.log("");
  console.log(pc.bold("Recommended next step:"));
  console.log("Fix critical issues first, then warnings, then cleanup items.");
  console.log("");
  console.log(pc.bold("Next commands:"));
  console.log("qodfy scan --checks api,environment");
  console.log("qodfy scan --prompts --max-issues 5");
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

function printGroupedIssues(issues: Issue[], showPrompts: boolean) {
  for (const category of categoryOrder) {
    const categoryIssues = issues.filter((issue) => issue.category === category);

    if (categoryIssues.length === 0) {
      continue;
    }

    console.log("");
    console.log(pc.bold(categoryLabels[category]));

    for (const issue of categoryIssues) {
      printIssue(issue, showPrompts);
    }
  }
}

function printIssue(issue: Issue, showPrompts: boolean) {
  console.log("");
  console.log(`${pc.dim(`[${issue.id}]`)} ${getSeverityLabel(issue.severity)} ${pc.bold(issue.title)}`);
  console.log(issue.message);

  if (issue.file) {
    console.log(pc.dim(`File: ${issue.file}`));
  }

  if (issue.suggestion) {
    console.log(pc.dim(`Suggestion: ${issue.suggestion}`));
  }

  if (showPrompts && issue.fixPrompt) {
    console.log("");
    console.log(pc.bold("Fix Prompt:"));
    console.log(issue.fixPrompt);
  }
}

function getSeverityLabel(severity: IssueSeverity) {
  if (severity === "critical") {
    return pc.red("CRITICAL");
  }

  if (severity === "warning") {
    return pc.yellow("WARNING");
  }

  return pc.blue("INFO");
}

function countIssuesBySeverity(issues: Issue[], severity: IssueSeverity) {
  return issues.filter((issue) => issue.severity === severity).length;
}

function getSortedDisplayIssues(issues: Issue[]) {
  return [...issues].sort((leftIssue, rightIssue) => {
    return (
      getSeverityRank(leftIssue.severity) - getSeverityRank(rightIssue.severity) ||
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
      ruleIds: ["api-route-missing-auth"],
      message: "Review API routes that may be missing authentication."
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

function printScanError(reason: string) {
  console.error(pc.red("Qodfy could not scan this project."));
  console.error("");
  console.error(pc.bold("Reason:"));
  console.error(reason);
  console.error("");
  console.error(pc.bold("Try:"));
  console.error("qodfy scan --path ./my-next-app");
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
