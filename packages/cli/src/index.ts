#!/usr/bin/env node

import fs from "node:fs/promises";
import path from "node:path";
import { Command } from "commander";
import pc from "picocolors";
import { scanProject } from "@qodfy/core";

type PathValidationResult =
  | { ok: true; projectPath: string }
  | { ok: false; reason: string };

const program = new Command();

program
  .name("qodfy")
  .description("Launch readiness scanner for AI-built apps.")
  .version("0.1.6");

program
  .command("scan")
  .description("Scan a project for launch readiness issues.")
  .option("-p, --path <path>", "Project path to scan", process.cwd())
  .option("--max-issues <number>", "Maximum number of issues to display", "50")
  .action(async (options: { path: string; maxIssues: string }) => {
    const pathResult = await resolveProjectPath(options.path);

    if (!pathResult.ok) {
      printScanError(pathResult.reason);
      process.exitCode = 1;
      return;
    }

    try {
      console.log(pc.cyan("Qodfy is scanning your project...\n"));

      const report = await scanProject(pathResult.projectPath);

      printReport(report, parseMaxIssues(options.maxIssues));
    } catch (error) {
      printScanError(getErrorMessage(error));
      process.exitCode = 1;
    }
  });

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

function printReport(report: Awaited<ReturnType<typeof scanProject>>, maxIssues: number) {
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

  for (const issue of issuesToShow) {
    const label =
      issue.severity === "critical" ? pc.red("CRITICAL") :
      issue.severity === "warning" ? pc.yellow("WARNING") :
      pc.blue("INFO");

    console.log(`\n${label} ${pc.bold(issue.title)}`);
    console.log(issue.message);

    if (issue.file) {
      console.log(pc.dim(`File: ${issue.file}`));
    }

    if (issue.suggestion) {
      console.log(pc.dim(`Suggestion: ${issue.suggestion}`));
    }
  }

  console.log("");
  console.log(pc.bold("Recommended next step:"));
  console.log("Fix critical issues first, then warnings, then cleanup items.");
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
