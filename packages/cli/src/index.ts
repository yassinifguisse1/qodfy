#!/usr/bin/env node

import { Command } from "commander";
import pc from "picocolors";
import { scanProject } from "@qodfy/core";

const program = new Command();

program
  .name("qodfy")
  .description("Launch readiness scanner for AI-built apps.")
  .version("0.1.1");

program
  .command("scan")
  .description("Scan a project for launch readiness issues.")
  .option("-p, --path <path>", "Project path to scan", process.cwd())
  .action(async (options) => {
    console.log(pc.cyan("Qodfy is scanning your project...\n"));

    const report = await scanProject(options.path);

    printReport(report);
  });

program.parse();

function printReport(report: Awaited<ReturnType<typeof scanProject>>) {
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
  console.log("");

  if (report.issues.length === 0) {
    console.log(pc.green("No issues found. Your project looks clean."));
    return;
  }

  console.log(pc.bold("Issues"));

  for (const issue of report.issues) {
    const label =
      issue.severity === "critical" ? pc.red("CRITICAL") :
      issue.severity === "warning" ? pc.yellow("WARNING") :
      pc.blue("INFO");

    console.log(`\n${label} ${pc.bold(issue.title)}`);
    console.log(issue.message);

    if (issue.file) {
      console.log(pc.dim(`File: ${issue.file}`));
    }
  }

  console.log("");
  console.log(pc.bold("Recommended next step:"));
  console.log("Fix critical issues first, then warnings, then cleanup items.");
}
