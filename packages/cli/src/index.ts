#!/usr/bin/env node

import fs from "node:fs/promises";
import path from "node:path";
import { Command } from "commander";
import pc from "picocolors";
import {
  scanProject,
  type Issue,
  type IssueCategory,
  type IssueSeverity,
  type ScanReport
} from "@qodfy/core";

type PathValidationResult =
  | { ok: true; projectPath: string }
  | { ok: false; reason: string };

const program = new Command();

program
  .name("qodfy")
  .description("Launch readiness scanner for AI-built apps.")
  .version("0.2.0");

program
  .command("scan")
  .description("Scan a project for launch readiness issues.")
  .option("-p, --path <path>", "Project path to scan", process.cwd())
  .option("--max-issues <number>", "Maximum number of issues to display", "50")
  .option("--prompts", "Show safe copy-paste fix prompts for displayed issues")
  .action(async (options: { path: string; maxIssues: string; prompts?: boolean }) => {
    const pathResult = await resolveProjectPath(options.path);

    if (!pathResult.ok) {
      printScanError(pathResult.reason);
      process.exitCode = 1;
      return;
    }

    try {
      console.log(pc.cyan("Qodfy is scanning your project...\n"));

      const report = await scanProject(pathResult.projectPath);

      printReport(report, parseMaxIssues(options.maxIssues), Boolean(options.prompts));
    } catch (error) {
      printScanError(getErrorMessage(error));
      process.exitCode = 1;
    }
  });

const categoryOrder: IssueCategory[] = [
  "security",
  "api",
  "webhook",
  "ai",
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

function printReport(report: ScanReport, maxIssues: number, showPrompts: boolean) {
  console.log(pc.bold("Qodfy Report"));
  console.log("");

  const scoreColor =
    report.score >= 80 ? pc.green :
    report.score >= 60 ? pc.yellow :
    pc.red;

  console.log(`Launch Readiness: ${scoreColor(`${report.score}/100`)}`);
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
  const issuesToShow = report.issues.slice(0, maxIssues);

  if (report.issues.length > maxIssues) {
    console.log(`Showing ${maxIssues} of ${report.issues.length} issues.`);
    console.log(`Use --max-issues <number> to show more.`);
  }

  printGroupedIssues(issuesToShow, showPrompts);

  console.log("");
  console.log(pc.bold("Recommended next step:"));
  console.log("Fix critical issues first, then warnings, then cleanup items.");
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

function parseMaxIssues(maxIssues: string) {
  const parsedMaxIssues = Number.parseInt(maxIssues, 10);

  if (!Number.isFinite(parsedMaxIssues) || parsedMaxIssues <= 0) {
    return 50;
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
