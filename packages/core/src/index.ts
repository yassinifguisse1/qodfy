import fs from "node:fs/promises";
import path from "node:path";
import fg from "fast-glob";

export type IssueSeverity = "critical" | "warning" | "info";
export type IssueConfidence = "high" | "medium" | "low";

export type IssueCategory =
  | "security"
  | "environment"
  | "api"
  | "webhook"
  | "ai"
  | "maintainability"
  | "project";

export const validScanChecks = [
  "project",
  "api",
  "environment",
  "ai",
  "webhook",
  "maintainability",
  "security"
] as const;

export type ScanCheck = typeof validScanChecks[number];

export const recommendedScanChecks: ScanCheck[] = [
  "project",
  "api",
  "environment",
  "ai",
  "webhook",
  "maintainability"
];

export type Issue = {
  id: string;
  ruleId: string;
  category: IssueCategory;
  severity: IssueSeverity;
  confidence: IssueConfidence;
  title: string;
  message: string;
  file?: string;
  suggestion?: string;
  fixPrompt?: string;
};

export type ScanReport = {
  projectPath: string;
  isNextProject: boolean;
  score: number;
  issues: Issue[];
  stats: {
    totalFiles: number;
    apiRoutes: number;
    aiFiles: number;
    largeFiles: number;
    durationMs: number;
  };
};

export type ScanOptions = {
  projectPath: string;
  checks?: ScanCheck[];
  includeLowConfidence?: boolean;
};

type SafeReadResult =
  | { ok: true; content: string }
  | { ok: false; reason: string; code?: string };

type SafeJsonResult =
  | { ok: true; data: unknown }
  | { ok: false; reason: string; code?: string };

type SafeStatResult =
  | { ok: true; size: number }
  | { ok: false; reason: string; code?: string };

type WebhookProvider =
  | "stripe"
  | "clerk"
  | "github"
  | "shopify"
  | "resend"
  | "unknown";

type WebhookRouteInfo = {
  provider: WebhookProvider;
  confidence: "high" | "likely";
};

type ApiRouteIntent =
  | "public-read"
  | "public-form"
  | "webhook"
  | "internal"
  | "sensitive-mutation"
  | "unknown";

type IssueInput = Omit<Issue, "id" | "confidence"> & {
  confidence?: IssueConfidence;
};
type AddIssue = (issue: IssueInput) => void;

const sourceFilePatterns = ["**/*.{ts,tsx,js,jsx,mts,cts,mjs,cjs}"];

const ignoredPaths = [
  "node_modules/**",
  ".next/**",
  "dist/**",
  "build/**",
  ".turbo/**",
  ".vercel/**",
  "coverage/**",
  "**/coverage/**",
  ".cache/**",
  "**/.cache/**",
  ".output/**",
  "**/.output/**",
  ".open-next/**",
  "**/.open-next/**",
  "storybook-static/**",
  "**/storybook-static/**",
  "playwright-report/**",
  "**/playwright-report/**",
  "test-results/**",
  "**/test-results/**",
  "**/*.d.ts",
  "**/*.map",
  "generated/**",
  "**/generated/**",
  "__generated__/**",
  "**/__generated__/**"
];

const aiKeywords = [
  "openai",
  "@ai-sdk",
  "ai/react",
  "anthropic",
  "gemini",
  "generateText",
  "streamText",
  "useChat"
];

const ignoredEnvVariables = new Set([
  "CI",
  "HOME",
  "NODE_ENV",
  "PORT",
  "PWD",
  "VERCEL",
  "VERCEL_ENV",
  "VERCEL_URL"
]);

const hardcodedSecretPatterns = [
  {
    label: "OpenAI API key",
    pattern: /\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b/g
  },
  {
    label: "Stripe secret key",
    pattern: /\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b/g
  },
  {
    label: "Stripe webhook secret",
    pattern: /\bwhsec_[A-Za-z0-9]{16,}\b/g
  },
  {
    label: "GitHub token",
    pattern: /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{30,}\b/g
  },
  {
    label: "GitHub fine-grained token",
    pattern: /\bgithub_pat_[A-Za-z0-9_]{40,}\b/g
  },
  {
    label: "Google API key",
    pattern: /\bAIza[A-Za-z0-9_-]{20,}\b/g
  },
  {
    label: "Slack token",
    pattern: /\bxox[baprs]-[A-Za-z0-9-]{20,}\b/g
  },
  {
    label: "private key",
    pattern: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/g
  }
];

const LARGE_FILE_WARNING_BYTES = 40 * 1024;
const LARGE_FILE_REPORT_LIMIT = 10;
const MAX_FILE_SIZE_BYTES = 500 * 1024;

const issueIdPrefixes: Record<string, string> = {
  "project-missing-package-json": "project-missing-package-json",
  "project-invalid-package-json": "project-invalid-package-json",
  "project-next-not-detected": "project-next-not-detected",
  "project-missing-readme": "project-missing-readme",
  "environment-missing-env-example": "environment-missing-env-example",
  "environment-variable-missing-from-example": "environment-variable-missing-from-example",
  "security-client-side-secret": "security-client-side-secret",
  "security-hardcoded-secret": "security-hardcoded-secret",
  "api-route-missing-auth": "security-api-auth",
  "api-public-read-route": "api-public-read-route",
  "api-public-form-abuse-protection": "api-public-form-protection",
  "api-internal-route-protection": "api-internal-route-protection",
  "ai-route-missing-rate-limit": "ai-route-rate-limit",
  "maintainability-large-file": "maintainability-large-file",
  "maintainability-large-file-skipped": "maintainability-large-file-skipped",
  "maintainability-file-unreadable": "maintainability-file-unreadable",
  "project-source-files-unreadable": "project-source-files-unreadable",
  "webhook-missing-signature-verification": "webhook-signature-verification"
};

export async function scanProject(input: string | ScanOptions): Promise<ScanReport> {
  const startTime = Date.now();
  const projectPath = typeof input === "string" ? input : input.projectPath;
  const includeLowConfidence = typeof input === "string"
    ? false
    : Boolean(input.includeLowConfidence);
  const enabledChecks = getEnabledChecks(
    typeof input === "string" ? undefined : input.checks
  );
  const resolvedProjectPath = path.resolve(projectPath);
  const issues: Issue[] = [];
  const addIssue = createIssueFactory(issues);
  const runProjectChecks = hasCheck(enabledChecks, "project");
  const runEnvironmentChecks = hasCheck(enabledChecks, "environment");
  const runApiChecks = hasCheck(enabledChecks, "api") || hasCheck(enabledChecks, "security");
  const runAiChecks = hasCheck(enabledChecks, "ai");
  const runWebhookChecks = hasCheck(enabledChecks, "webhook") || hasCheck(enabledChecks, "security");
  const runMaintainabilityChecks = hasCheck(enabledChecks, "maintainability");
  const runSecurityChecks = hasCheck(enabledChecks, "security");
  const shouldScanSourceFiles = enabledChecks.size > 0 && !onlyHasCheck(enabledChecks, "project");
  const shouldReadSourceContent =
    runEnvironmentChecks ||
    runApiChecks ||
    runAiChecks ||
    runWebhookChecks ||
    runSecurityChecks;

  const packageJsonPath = path.join(resolvedProjectPath, "package.json");
  const hasPackageJson = await fileExists(packageJsonPath);

  let isNextProject = false;

  if (runProjectChecks && !hasPackageJson) {
    addIssue({
      ruleId: "project-missing-package-json",
      category: "project",
      severity: "critical",
      confidence: "high",
      title: "Missing package.json",
      message: "Qodfy could not find a package.json file in this project.",
      suggestion: "Run Qodfy from the project root or pass --path to the app folder.",
      fixPrompt: createProjectRootFixPrompt()
    });
  } else if (runProjectChecks) {
    const packageJsonResult = await safeReadJson(packageJsonPath);

    if (!packageJsonResult.ok) {
      addIssue({
        ruleId: "project-invalid-package-json",
        category: "project",
        severity: "critical",
        confidence: "high",
        title: "Could not read package.json",
        message: packageJsonResult.reason,
        file: "package.json",
        suggestion: "Fix package.json so Qodfy can detect the framework and dependencies.",
        fixPrompt: createPackageJsonFixPrompt()
      });
    } else if (!isPackageJsonObject(packageJsonResult.data)) {
      addIssue({
        ruleId: "project-invalid-package-json",
        category: "project",
        severity: "critical",
        confidence: "high",
        title: "Invalid package.json",
        message: "package.json must contain a JSON object at the top level.",
        file: "package.json",
        suggestion: "Fix package.json so Qodfy can detect the framework and dependencies.",
        fixPrompt: createPackageJsonFixPrompt()
      });
    } else {
      const deps = {
        ...packageJsonResult.data.dependencies,
        ...packageJsonResult.data.devDependencies
      };

      isNextProject = Boolean(deps.next);

      if (!isNextProject) {
        addIssue({
          ruleId: "project-next-not-detected",
          category: "project",
          severity: "warning",
          confidence: "low",
          title: "Next.js not detected",
          message: "This first version of Qodfy is optimized for Next.js projects.",
          suggestion: "If this is a monorepo, scan the Next.js app folder directly.",
          fixPrompt: createNextNotDetectedFixPrompt()
        });
      }
    }
  }

  const envExamplePath = path.join(resolvedProjectPath, ".env.example");
  const hasEnvExample = runEnvironmentChecks
    ? await fileExists(envExamplePath)
    : false;
  let envExampleVariables: Set<string> | null = null;

  if (runEnvironmentChecks && !hasEnvExample) {
    addIssue({
      ruleId: "environment-missing-env-example",
      category: "environment",
      severity: "warning",
      confidence: "medium",
      title: "Missing .env.example",
      message: "Add a .env.example file so future developers know which environment variables are required.",
      suggestion: "Document required variable names only, never real secret values.",
      fixPrompt: createMissingEnvExampleFixPrompt()
    });
  } else if (runEnvironmentChecks) {
    const envExampleResult = await safeReadFile(envExamplePath);

    if (!envExampleResult.ok) {
      addIssue({
        ruleId: "environment-missing-env-example",
        category: "environment",
        severity: "warning",
        confidence: "medium",
        title: "Could not read .env.example",
        message: envExampleResult.reason,
        file: ".env.example",
        suggestion: "Make sure .env.example is readable and contains variable names without real secret values.",
        fixPrompt: createMissingEnvExampleFixPrompt()
      });
    } else {
      envExampleVariables = getEnvExampleVariables(envExampleResult.content);
    }
  }

  const hasReadme = runProjectChecks
    ? await fileExists(path.join(resolvedProjectPath, "README.md"))
    : true;

  if (runProjectChecks && !hasReadme) {
    addIssue({
      ruleId: "project-missing-readme",
      category: "project",
      severity: "info",
      confidence: "low",
      title: "Missing README.md",
      message: "A README helps other developers understand how to run and maintain the project.",
      fixPrompt: createReadmeFixPrompt()
    });
  }

  const files = shouldScanSourceFiles
    ? await getSourceFiles(resolvedProjectPath, addIssue)
    : [];

  const apiRoutes = files.filter((file) => {
    return isApiRoute(file);
  });
  const apiRouteSet = new Set(apiRoutes);

  const missingEnvUsages = new Map<string, Set<string>>();
  const clientSecretWarningKeys = new Set<string>();
  const hardcodedSecretWarningKeys = new Set<string>();
  const largeFileCandidates: Array<{ relativeFile: string; size: number }> = [];
  let aiFiles = 0;
  let largeFiles = 0;

  for (const file of files) {
    const relativeFile = normalizePath(path.relative(resolvedProjectPath, file));
    const statResult = await safeStatFile(file);

    if (!statResult.ok) {
      if (runMaintainabilityChecks) {
        addIssue({
          ruleId: "maintainability-file-unreadable",
          category: "maintainability",
          severity: "info",
          confidence: "low",
          title: "File could not be checked",
          message: statResult.reason,
          file: relativeFile,
          suggestion: "Check file permissions if this file should be included in launch-readiness scans."
        });
      }
      continue;
    }

    if (statResult.size > MAX_FILE_SIZE_BYTES) {
      if (runMaintainabilityChecks) {
        largeFiles++;

        addIssue({
          ruleId: "maintainability-large-file-skipped",
          category: "maintainability",
          severity: "info",
          confidence: "low",
          title: "Large file skipped from deep scan",
          message: "This file is larger than 500KB and was skipped from deep content checks.",
          file: relativeFile,
          suggestion: "Review large generated or bundled files manually.",
          fixPrompt: createLargeFileFixPrompt(relativeFile)
        });
      }
      continue;
    }

    if (runMaintainabilityChecks && statResult.size > LARGE_FILE_WARNING_BYTES) {
      largeFiles++;
      largeFileCandidates.push({
        relativeFile,
        size: statResult.size
      });
    }

    if (!shouldReadSourceContent) {
      continue;
    }

    const fileResult = await safeReadFile(file);

    if (!fileResult.ok) {
      if (runMaintainabilityChecks) {
        addIssue({
          ruleId: "maintainability-file-unreadable",
          category: "maintainability",
          severity: "info",
          confidence: "low",
          title: "File could not be read",
          message: fileResult.reason,
          file: relativeFile,
          suggestion: "Check file permissions if this file should be included in launch-readiness scans."
        });
      }
      continue;
    }

    const content = fileResult.content;

    const usesAI = aiKeywords.some((keyword) =>
      content.toLowerCase().includes(keyword.toLowerCase())
    );

    if (runAiChecks && usesAI) {
      aiFiles++;

      const hasRateLimit =
        content.includes("rateLimit") ||
        content.includes("ratelimit") ||
        content.includes("upstash") ||
        content.includes("limiter");

      if (apiRouteSet.has(file) && !hasRateLimit) {
        addIssue({
          ruleId: "ai-route-missing-rate-limit",
          category: "ai",
          severity: "critical",
          confidence: "high",
          title: "AI route may be missing rate limiting",
          message: "AI routes can create real API costs. Add rate limiting or usage limits before launch.",
          file: relativeFile,
          suggestion: "Add rate limiting, usage limits, or per-user quotas before launch.",
          fixPrompt: createAiRateLimitFixPrompt(relativeFile)
        });
      }
    }

    const webhookRouteInfo = (runWebhookChecks || runApiChecks) && apiRouteSet.has(file)
      ? getWebhookRouteInfo(relativeFile, content)
      : null;

    if (
      webhookRouteInfo &&
      !hasWebhookSignatureVerification(content, webhookRouteInfo.provider)
    ) {
      addIssue({
        ruleId: "webhook-missing-signature-verification",
        category: "webhook",
        severity: webhookRouteInfo.confidence === "high" ? "critical" : "warning",
        confidence: webhookRouteInfo.confidence === "high" ? "high" : "medium",
        title: "Webhook route may be missing signature verification",
        message: "This webhook route appears to handle external events, but Qodfy could not find signature verification before the event is handled.",
        file: relativeFile,
        suggestion: getWebhookSignatureSuggestion(webhookRouteInfo.provider),
        fixPrompt: createWebhookSignatureFixPrompt(relativeFile)
      });
    }

    if (runSecurityChecks) {
      for (const secretMatch of getHardcodedSecretMatches(content)) {
        const warningKey = `${relativeFile}:${secretMatch.label}`;

        if (hardcodedSecretWarningKeys.has(warningKey)) {
          continue;
        }

        hardcodedSecretWarningKeys.add(warningKey);

        addIssue({
          ruleId: "security-hardcoded-secret",
          category: "security",
          severity: "critical",
          confidence: "high",
          title: "Possible hardcoded secret",
          message: `A string literal in ${relativeFile} matches the pattern for ${secretMatch.label}. Qodfy does not print possible secret values.`,
          file: relativeFile,
          suggestion: "Move secrets into environment variables and rotate the value if this is a real secret.",
          fixPrompt: createHardcodedSecretFixPrompt(relativeFile, secretMatch.label)
        });
      }
    }

    if (runApiChecks && apiRouteSet.has(file)) {
      addApiRouteProtectionIssues({
        addIssue,
        content,
        includeLowConfidence,
        relativeFile,
        webhookRouteInfo
      });
    }

    const usedEnvVariables = runEnvironmentChecks || runSecurityChecks
      ? getUsedEnvVariables(content)
      : new Set<string>();

    if (runEnvironmentChecks && envExampleVariables) {
      for (const variableName of usedEnvVariables) {
        if (shouldIgnoreEnvVariable(variableName) || envExampleVariables.has(variableName)) {
          continue;
        }

        const filesUsingVariable = missingEnvUsages.get(variableName) ?? new Set<string>();
        filesUsingVariable.add(relativeFile);
        missingEnvUsages.set(variableName, filesUsingVariable);
      }
    }

    if (runSecurityChecks && isClientSideFile(relativeFile, content)) {
      for (const variableName of usedEnvVariables) {
        if (!variableName.startsWith("NEXT_PUBLIC_") && !shouldIgnoreEnvVariable(variableName)) {
          const warningKey = `${relativeFile}:${variableName}`;

          if (clientSecretWarningKeys.has(warningKey)) {
            continue;
          }

          clientSecretWarningKeys.add(warningKey);

          addIssue({
            ruleId: "security-client-side-secret",
            category: "security",
            severity: "warning",
            confidence: "medium",
            title: "Possible server secret used in client-side code",
            message: `${variableName} appears in a client-side file. Server secrets should not be exposed to the browser.`,
            file: relativeFile,
            suggestion: "Move server-only environment variable access to a server component, API route, or server action.",
            fixPrompt: createClientSideSecretFixPrompt(relativeFile, variableName)
          });
        }
      }
    }
  }

  for (const largeFile of getReportedLargeFiles(largeFileCandidates)) {
    addIssue({
      ruleId: "maintainability-large-file",
      category: "maintainability",
      severity: "info",
      confidence: "low",
      title: "Large file detected",
      message: "This file is larger than the recommended maintainability threshold. Large files can be harder to review, test, and safely modify.",
      file: largeFile.relativeFile,
      suggestion: "Review whether this file mixes UI, state, data fetching, validation, or business logic. If so, split it into smaller components, hooks, or utilities.",
      fixPrompt: createLargeFileFixPrompt(largeFile.relativeFile)
    });
  }

  for (const [variableName, filesUsingVariable] of getSortedMissingEnvUsages(missingEnvUsages)) {
    const files = [...filesUsingVariable].sort();

    addIssue({
      ruleId: "environment-variable-missing-from-example",
      category: "environment",
      severity: "warning",
      confidence: "medium",
      title: "Environment variable missing from .env.example",
      message: getMissingEnvMessage(variableName, files),
      file: files.length === 1 ? files[0] : undefined,
      suggestion: `Add ${variableName}= to .env.example without including a real value.`,
      fixPrompt: createMissingEnvVariableFixPrompt(variableName, files)
    });
  }

  const criticalCount = issues.filter((issue) => issue.severity === "critical").length;
  const warningCount = issues.filter((issue) => issue.severity === "warning").length;
  const warningPenalty = Math.min(warningCount * 5, 50);

  const score = Math.max(0, 100 - criticalCount * 20 - warningPenalty);

  return {
    projectPath: resolvedProjectPath,
    isNextProject,
    score,
    issues,
    stats: {
      totalFiles: files.length,
      apiRoutes: apiRoutes.length,
      aiFiles,
      largeFiles,
      durationMs: Date.now() - startTime
    }
  };
}

function createIssueFactory(issues: Issue[]): AddIssue {
  const issueCounts = new Map<string, number>();

  return (issue: IssueInput) => {
    const currentCount = (issueCounts.get(issue.ruleId) ?? 0) + 1;
    issueCounts.set(issue.ruleId, currentCount);

    issues.push({
      ...issue,
      id: `${getIssueIdPrefix(issue.ruleId, issue.category)}-${currentCount}`,
      confidence: issue.confidence ?? "medium"
    });
  };
}

function getIssueIdPrefix(ruleId: string, category: IssueCategory) {
  return issueIdPrefixes[ruleId] ?? `${category}-${ruleId}`;
}

function getEnabledChecks(checks: ScanCheck[] | undefined) {
  const checksToEnable = checks && checks.length > 0
    ? checks
    : recommendedScanChecks;

  return new Set<ScanCheck>(checksToEnable);
}

function hasCheck(enabledChecks: Set<ScanCheck>, check: ScanCheck) {
  return enabledChecks.has(check);
}

function onlyHasCheck(enabledChecks: Set<ScanCheck>, check: ScanCheck) {
  return enabledChecks.size === 1 && enabledChecks.has(check);
}

async function fileExists(filePath: string) {
  try {
    await fs.access(filePath);
    return true;
  } catch {
    return false;
  }
}

async function safeReadFile(filePath: string): Promise<SafeReadResult> {
  try {
    return {
      ok: true,
      content: await fs.readFile(filePath, "utf-8")
    };
  } catch (error) {
    const code = getErrorCode(error);

    if (code === "ENOENT") {
      return {
        ok: false,
        code,
        reason: "The file disappeared while Qodfy was scanning it."
      };
    }

    if (code === "EACCES" || code === "EPERM") {
      return {
        ok: false,
        code,
        reason: "Qodfy does not have permission to read this file."
      };
    }

    return {
      ok: false,
      code,
      reason: "Qodfy could not read this file."
    };
  }
}

async function safeStatFile(filePath: string): Promise<SafeStatResult> {
  try {
    const stats = await fs.stat(filePath);

    return {
      ok: true,
      size: stats.size
    };
  } catch (error) {
    const code = getErrorCode(error);

    if (code === "ENOENT") {
      return {
        ok: false,
        code,
        reason: "The file disappeared while Qodfy was scanning it."
      };
    }

    if (code === "EACCES" || code === "EPERM") {
      return {
        ok: false,
        code,
        reason: "Qodfy does not have permission to check this file."
      };
    }

    return {
      ok: false,
      code,
      reason: "Qodfy could not check this file."
    };
  }
}

async function safeReadJson(filePath: string): Promise<SafeJsonResult> {
  const fileResult = await safeReadFile(filePath);

  if (!fileResult.ok) {
    return fileResult;
  }

  try {
    return {
      ok: true,
      data: JSON.parse(fileResult.content)
    };
  } catch {
    return {
      ok: false,
      reason: "package.json is not valid JSON."
    };
  }
}

async function getSourceFiles(projectPath: string, addIssue: AddIssue) {
  try {
    const files = await fg(sourceFilePatterns, {
      cwd: projectPath,
      ignore: ignoredPaths,
      absolute: true,
      onlyFiles: true,
      dot: false
    });

    return files.sort((leftFile, rightFile) =>
      normalizePath(leftFile).localeCompare(normalizePath(rightFile))
    );
  } catch {
    addIssue({
      ruleId: "project-source-files-unreadable",
      category: "project",
      severity: "critical",
      confidence: "high",
      title: "Could not scan source files",
      message: "Qodfy could not list source files in this project.",
      suggestion: "Check that the project path exists and is readable.",
      fixPrompt: createProjectRootFixPrompt()
    });

    return [];
  }
}

function getEnvExampleVariables(content: string) {
  const variables = new Set<string>();

  for (const line of content.split(/\r?\n/)) {
    const trimmedLine = line.trim();

    if (!trimmedLine || trimmedLine.startsWith("#")) {
      continue;
    }

    const match = trimmedLine.match(/^(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*(?:=|$)/);

    if (match) {
      variables.add(match[1]);
    }
  }

  return variables;
}

function getUsedEnvVariables(content: string) {
  const variables = new Set<string>();
  const dotAccessPattern = /\bprocess\.env\.([A-Za-z_][A-Za-z0-9_]*)/g;
  const bracketAccessPattern = /\bprocess\.env\[['"`]([A-Za-z_][A-Za-z0-9_]*)['"`]\]/g;
  const destructuredEnvPattern = /\b(?:const|let|var)\s*\{([^}]+)\}\s*=\s*process\.env\b/g;

  for (const match of content.matchAll(dotAccessPattern)) {
    variables.add(match[1]);
  }

  for (const match of content.matchAll(bracketAccessPattern)) {
    variables.add(match[1]);
  }

  for (const match of content.matchAll(destructuredEnvPattern)) {
    for (const variableName of parseDestructuredEnvNames(match[1])) {
      variables.add(variableName);
    }
  }

  return variables;
}

function shouldIgnoreEnvVariable(variableName: string) {
  return ignoredEnvVariables.has(variableName);
}

function getReportedLargeFiles(largeFileCandidates: Array<{ relativeFile: string; size: number }>) {
  return [...largeFileCandidates]
    .sort((a, b) => b.size - a.size)
    .slice(0, LARGE_FILE_REPORT_LIMIT);
}

function getSortedMissingEnvUsages(missingEnvUsages: Map<string, Set<string>>) {
  return [...missingEnvUsages.entries()].sort(([leftVariable], [rightVariable]) =>
    leftVariable.localeCompare(rightVariable)
  );
}

function getMissingEnvMessage(variableName: string, files: string[]) {
  if (files.length === 1) {
    return `${variableName} is used in ${files[0]} but is not documented in .env.example.`;
  }

  return `${variableName} is used in ${files.length} files but is not documented in .env.example. Files: ${formatFileList(files)}.`;
}

function formatFileList(files: string[]) {
  const filesToShow = files.slice(0, 5);
  const remainingCount = files.length - filesToShow.length;

  if (remainingCount <= 0) {
    return filesToShow.join(", ");
  }

  return `${filesToShow.join(", ")} and ${remainingCount} more`;
}

function parseDestructuredEnvNames(destructuredContent: string) {
  const variables: string[] = [];

  for (const part of destructuredContent.split(",")) {
    const variableName = part
      .trim()
      .split(":")[0]
      .split("=")[0]
      .trim();

    if (/^[A-Za-z_][A-Za-z0-9_]*$/.test(variableName)) {
      variables.push(variableName);
    }
  }

  return variables;
}

function getHardcodedSecretMatches(content: string) {
  const matches: Array<{ label: string }> = [];

  for (const secretPattern of hardcodedSecretPatterns) {
    secretPattern.pattern.lastIndex = 0;

    if (secretPattern.pattern.test(content)) {
      matches.push({ label: secretPattern.label });
    }
  }

  return matches;
}

function isClientSideFile(relativeFile: string, content: string) {
  const fileName = path.basename(relativeFile);

  return (
    fileName.includes(".client.") ||
    /(^|\n)\s*["']use client["'];?/.test(content)
  );
}

function isApiRoute(filePath: string) {
  const normalizedFile = normalizePath(filePath);
  const sourceFileExtension = "(?:ts|tsx|js|jsx|mts|cts|mjs|cjs)";

  return (
    new RegExp(`/app/api(?:/.+)?/route\\.${sourceFileExtension}$`).test(normalizedFile) ||
    new RegExp(`/pages/api/.+\\.${sourceFileExtension}$`).test(normalizedFile)
  );
}

function addApiRouteProtectionIssues({
  addIssue,
  content,
  includeLowConfidence,
  relativeFile,
  webhookRouteInfo
}: {
  addIssue: AddIssue;
  content: string;
  includeLowConfidence: boolean;
  relativeFile: string;
  webhookRouteInfo: WebhookRouteInfo | null;
}) {
  const intent = classifyApiRouteIntent(relativeFile, content, webhookRouteInfo);
  const hasAuth = hasAuthOrSessionCheck(content);
  const methods = getHttpMethods(content);

  if (intent === "webhook") {
    return;
  }

  if (intent === "public-read") {
    if (includeLowConfidence) {
      addIssue({
        ruleId: "api-public-read-route",
        category: "api",
        severity: "info",
        confidence: "low",
        title: "Public read API route detected",
        message: "This route appears intentionally public. Authentication may not be required.",
        file: relativeFile,
        suggestion: "Verify that it only exposes public or published data and has appropriate validation, caching, and abuse protection.",
        fixPrompt: createPublicReadRouteFixPrompt(relativeFile)
      });
    }

    return;
  }

  if (intent === "public-form") {
    if (!hasAbuseProtection(content)) {
      addIssue({
        ruleId: "api-public-form-abuse-protection",
        category: "api",
        severity: "warning",
        confidence: "medium",
        title: "Public form route may be missing abuse protection",
        message: "This route appears to accept public submissions. Consider adding rate limiting, validation, or spam protection.",
        file: relativeFile,
        suggestion: "Check for rate limiting, validation, captcha, Turnstile, reCAPTCHA, hCaptcha, or another spam protection pattern.",
        fixPrompt: createPublicFormProtectionFixPrompt(relativeFile)
      });
    }

    return;
  }

  if (intent === "internal") {
    if (!hasInternalRouteProtection(content)) {
      addIssue({
        ruleId: "api-internal-route-protection",
        category: "api",
        severity: "warning",
        confidence: "high",
        title: "Internal API route may be missing protection",
        message: "This route appears internal or operational. Confirm it is protected by auth, a secret token, or server-only access.",
        file: relativeFile,
        suggestion: "Use the project's existing auth pattern or a secret token check for operational routes such as cron, cleanup, or revalidation.",
        fixPrompt: createInternalRouteProtectionFixPrompt(relativeFile)
      });
    }

    return;
  }

  if (intent === "sensitive-mutation") {
    if (!hasAuth) {
      addIssue({
        ruleId: "api-route-missing-auth",
        category: "api",
        severity: "warning",
        confidence: "high",
        title: "Sensitive API route may be missing authentication",
        message: "This route appears to handle user-specific or sensitive operations. Confirm it is protected before launch.",
        file: relativeFile,
        suggestion: "Review the existing project auth/session pattern and apply it if this route handles private data, uploads, payments, or account changes.",
        fixPrompt: createApiAuthFixPrompt(relativeFile)
      });
    }

    return;
  }

  if (hasMutationMethod(methods) && !hasAuth) {
    addIssue({
      ruleId: "api-route-missing-auth",
      category: "api",
      severity: "warning",
      confidence: "medium",
      title: "API mutation route should be reviewed for authentication",
      message: "This route appears to handle a mutation, but Qodfy could not find an auth/session check.",
      file: relativeFile,
      suggestion: "Confirm the route is intentionally public, or add the existing project auth/session check before handling private data.",
      fixPrompt: createApiAuthFixPrompt(relativeFile)
    });
  }
}

function classifyApiRouteIntent(
  relativeFile: string,
  content: string,
  webhookRouteInfo: WebhookRouteInfo | null
): ApiRouteIntent {
  const normalizedFile = relativeFile.toLowerCase();
  const methods = getHttpMethods(content);

  if (webhookRouteInfo || routePathHasAny(normalizedFile, ["webhook", "webhooks", "callback"])) {
    return "webhook";
  }

  if (routePathHasAny(normalizedFile, ["internal", "admin", "cron", "cleanup", "revalidate", "private"])) {
    return "internal";
  }

  if (routePathHasAny(normalizedFile, ["contact", "subscribe", "newsletter", "lead", "inquiry"])) {
    return "public-form";
  }

  if (routePathHasAny(normalizedFile, [
    "upload",
    "checkout",
    "order",
    "orders",
    "invoice",
    "invoices",
    "account",
    "user",
    "users",
    "payment",
    "billing",
    "cart",
    "profile",
    "settings"
  ])) {
    return "sensitive-mutation";
  }

  if (routePathHasAny(normalizedFile, [
    "blog",
    "blogs",
    "post",
    "posts",
    "product",
    "products",
    "search",
    "i18n",
    "category",
    "categories",
    "sitemap",
    "rss"
  ])) {
    return "public-read";
  }

  if (hasMutationMethod(methods)) {
    return "unknown";
  }

  if (methods.size === 0 || isReadOnlyRoute(methods)) {
    return "unknown";
  }

  return "unknown";
}

function routePathHasAny(normalizedFile: string, terms: string[]) {
  return terms.some((term) => {
    const escapedTerm = term.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

    return new RegExp(`(^|[\\/._\\[\\]-])${escapedTerm}([\\/._\\[\\]-]|$)`).test(normalizedFile);
  });
}

function getHttpMethods(content: string) {
  const methods = new Set<string>();
  const exportedMethodPattern = /\bexport\s+(?:async\s+)?(?:function|const)\s+(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\b/g;
  const requestMethodPattern = /\b(?:request|req)\.method\s*(?:={2,3}|!={1,2})\s*["'](GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)["']/g;
  const methodCasePattern = /\bcase\s+["'](GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)["']/g;

  for (const match of content.matchAll(exportedMethodPattern)) {
    methods.add(match[1]);
  }

  for (const match of content.matchAll(requestMethodPattern)) {
    methods.add(match[1]);
  }

  for (const match of content.matchAll(methodCasePattern)) {
    methods.add(match[1]);
  }

  return methods;
}

function hasMutationMethod(methods: Set<string>) {
  return ["POST", "PUT", "PATCH", "DELETE"].some((method) => methods.has(method));
}

function isReadOnlyRoute(methods: Set<string>) {
  return [...methods].every((method) => method === "GET" || method === "HEAD" || method === "OPTIONS");
}

function hasAuthOrSessionCheck(content: string) {
  const normalizedContent = content.toLowerCase();

  return (
    normalizedContent.includes("auth(") ||
    normalizedContent.includes("getserversession") ||
    normalizedContent.includes("currentuser") ||
    normalizedContent.includes("clerkclient") ||
    normalizedContent.includes("session") ||
    normalizedContent.includes("requireauth") ||
    normalizedContent.includes("requireuser") ||
    normalizedContent.includes("requireadmin") ||
    normalizedContent.includes("verifysession") ||
    normalizedContent.includes("getuser") ||
    normalizedContent.includes("jwt") ||
    normalizedContent.includes("authorization") ||
    normalizedContent.includes("bearer") ||
    normalizedContent.includes("cookies()") ||
    normalizedContent.includes("request.cookies") ||
    normalizedContent.includes("middleware")
  );
}

function hasInternalRouteProtection(content: string) {
  const normalizedContent = content.toLowerCase();

  return (
    hasAuthOrSessionCheck(content) ||
    /\bprocess\.env\.[A-Za-z0-9_]*SECRET\b/.test(content) ||
    /\bprocess\.env\[['"`][A-Za-z0-9_]*SECRET['"`]\]/.test(content) ||
    normalizedContent.includes("cron_secret") ||
    normalizedContent.includes("revalidate_secret") ||
    normalizedContent.includes("authorization") ||
    normalizedContent.includes("bearer") ||
    normalizedContent.includes("token")
  );
}

function hasAbuseProtection(content: string) {
  const normalizedContent = content.toLowerCase();

  return (
    normalizedContent.includes("ratelimit") ||
    normalizedContent.includes("rate limit") ||
    normalizedContent.includes("limiter") ||
    normalizedContent.includes("captcha") ||
    normalizedContent.includes("turnstile") ||
    normalizedContent.includes("recaptcha") ||
    normalizedContent.includes("hcaptcha") ||
    normalizedContent.includes("validation") ||
    normalizedContent.includes("validate") ||
    normalizedContent.includes("zod") ||
    normalizedContent.includes("safeparse")
  );
}

function getWebhookRouteInfo(relativeFile: string, content: string): WebhookRouteInfo | null {
  const normalizedFile = relativeFile.toLowerCase();
  const normalizedContent = content.toLowerCase();
  const normalizedRouteContext = `${normalizedFile}\n${normalizedContent}`;

  const pathLooksLikeWebhook =
    /(^|[\/._-])(webhook|webhooks|callback)([\/._-]|$)/.test(normalizedFile);
  const contentStronglySuggestsWebhook =
    normalizedContent.includes("stripe.webhooks") ||
    normalizedContent.includes("constructevent(") ||
    normalizedContent.includes("stripe-signature") ||
    normalizedContent.includes("stripe_webhook_secret") ||
    normalizedContent.includes("clerk_webhook_secret") ||
    normalizedContent.includes("svix") ||
    normalizedContent.includes("x-github-event") ||
    normalizedContent.includes("x-hub-signature") ||
    normalizedContent.includes("x-shopify-hmac-sha256") ||
    (
      /\bresend\b/.test(normalizedContent) &&
      /\bwebhook\b/.test(normalizedContent)
    ) ||
    /\bwebhook_secret\b/.test(normalizedContent) ||
    /\bwebhooksecret\b/.test(normalizedContent) ||
    (
      /\bwebhook\b/.test(normalizedContent) &&
      /\b(signature|secret|event|payload)\b/.test(normalizedContent)
    );

  if (!pathLooksLikeWebhook && !contentStronglySuggestsWebhook) {
    return null;
  }

  const provider = getWebhookProvider(normalizedRouteContext);

  return {
    provider,
    confidence: provider === "unknown" ? "likely" : "high"
  };
}

function getWebhookProvider(normalizedRouteContext: string): WebhookProvider {
  if (
    normalizedRouteContext.includes("stripe-signature") ||
    normalizedRouteContext.includes("stripe_webhook_secret") ||
    normalizedRouteContext.includes("stripe.webhooks") ||
    normalizedRouteContext.includes("constructevent(") ||
    (
      /\bstripe\b/.test(normalizedRouteContext) &&
      /\bwebhook\b/.test(normalizedRouteContext)
    )
  ) {
    return "stripe";
  }

  if (
    /\bresend\b/.test(normalizedRouteContext) &&
    /\bwebhook\b/.test(normalizedRouteContext)
  ) {
    return "resend";
  }

  if (
    normalizedRouteContext.includes("clerk_webhook_secret") ||
    (
      /\bclerk\b/.test(normalizedRouteContext) &&
      /\bwebhook\b/.test(normalizedRouteContext)
    )
  ) {
    return "clerk";
  }

  if (
    normalizedRouteContext.includes("x-github-event") ||
    normalizedRouteContext.includes("x-hub-signature")
  ) {
    return "github";
  }

  if (normalizedRouteContext.includes("x-shopify-hmac-sha256")) {
    return "shopify";
  }

  return "unknown";
}

function hasWebhookSignatureVerification(content: string, provider: WebhookProvider) {
  const normalizedContent = content.toLowerCase();

  if (provider === "stripe") {
    return (
      normalizedContent.includes("stripe.webhooks.constructevent") ||
      normalizedContent.includes("webhooks.constructevent") ||
      normalizedContent.includes("constructevent(")
    );
  }

  if (provider === "clerk") {
    return (
      (
        normalizedContent.includes("new webhook(") ||
        normalizedContent.includes("webhook(") ||
        normalizedContent.includes("svix")
      ) &&
      (
        normalizedContent.includes(".verify(") ||
        normalizedContent.includes("verify(") ||
        normalizedContent.includes("verifywebhook")
      )
    );
  }

  if (provider === "github") {
    return (
      (
        normalizedContent.includes("x-hub-signature") ||
        normalizedContent.includes("x-hub-signature-256")
      ) &&
      hasHmacOrVerifyCall(normalizedContent)
    );
  }

  if (provider === "shopify") {
    return (
      normalizedContent.includes("x-shopify-hmac-sha256") &&
      hasHmacOrVerifyCall(normalizedContent)
    );
  }

  if (provider === "resend") {
    return (
      normalizedContent.includes("verifywebhook") ||
      (
        (
          normalizedContent.includes("new webhook(") ||
          normalizedContent.includes("webhook(") ||
          normalizedContent.includes("svix")
        ) &&
        hasHmacOrVerifyCall(normalizedContent)
      )
    );
  }

  return (
    normalizedContent.includes("constructevent(") ||
    normalizedContent.includes("verifywebhook") ||
    (
      normalizedContent.includes("signature") &&
      hasHmacOrVerifyCall(normalizedContent)
    ) ||
    (
      normalizedContent.includes("webhook") &&
      normalizedContent.includes("verify(")
    )
  );
}

function hasHmacOrVerifyCall(normalizedContent: string) {
  return (
    normalizedContent.includes("verify(") ||
    normalizedContent.includes(".verify(") ||
    normalizedContent.includes("verifywebhook") ||
    normalizedContent.includes("createhmac") ||
    normalizedContent.includes("timingsafeequal") ||
    normalizedContent.includes("subtle.verify")
  );
}

function getWebhookSignatureSuggestion(provider: WebhookProvider) {
  if (provider === "stripe") {
    return "Use stripe.webhooks.constructEvent(...) with the Stripe signature header before handling the event.";
  }

  if (provider === "clerk") {
    return "Verify the event with Svix before handling it.";
  }

  if (provider === "github") {
    return "Verify the GitHub signature using the raw request body, X-Hub-Signature-256 header, and webhook secret.";
  }

  if (provider === "shopify") {
    return "Verify the Shopify HMAC using the raw request body, X-Shopify-Hmac-Sha256 header, and webhook secret.";
  }

  if (provider === "resend") {
    return "Verify the Resend webhook signature before handling the event.";
  }

  return "Verify the provider signature using the raw request body and signature header before trusting the event.";
}

function createApiAuthFixPrompt(file: string) {
  return `Review the API route at ${file}.

Goal:
Determine whether this route should be public or protected.

Instructions:
- Inspect the existing authentication/session pattern used in this project.
- If this route handles private data, user-specific data, uploads, writes, or admin actions, add the existing auth/session check.
- Do not introduce a new auth provider.
- Do not refactor unrelated code.
- Keep the current behavior unchanged.
- If this route is intentionally public, add a short comment explaining why.

Return:
- A short explanation of what you changed.
- The updated code.
- Any edge cases I should test.`;
}

function createPublicReadRouteFixPrompt(file: string) {
  return `Review the public read API route at ${file}.

Goal:
Verify that this route is safe to remain public.

Instructions:
- Confirm it only exposes published, public, or non-sensitive data.
- Check that route params and query values are validated or sanitized.
- Check for appropriate cache headers where useful.
- Check for abuse protection if the route can be called heavily.
- Do not add user authentication unless the route should be private.
- Do not refactor unrelated code.

Return:
- Whether this route appears intentionally public.
- Any low-risk safety improvements.
- Any edge cases I should test.`;
}

function createPublicFormProtectionFixPrompt(file: string) {
  return `Review the public form API route at ${file}.

Goal:
Verify validation, rate limiting, and spam protection.

Instructions:
- Confirm submitted input is validated before it is used.
- Check for rate limiting or another abuse protection pattern.
- Check whether captcha, Turnstile, reCAPTCHA, or hCaptcha is appropriate.
- Do not add user authentication unless the form should be private.
- Do not introduce a new service unless necessary.
- Keep existing behavior unchanged.

Return:
- Whether abuse protection already exists.
- The safest minimal change if protection is missing.
- Any edge cases I should test.`;
}

function createInternalRouteProtectionFixPrompt(file: string) {
  return `Review the internal API route at ${file}.

Goal:
Confirm this operational route is protected before launch.

Instructions:
- Check whether the route is protected by existing auth, a secret token, or server-only access.
- For cron, cleanup, revalidation, or admin routes, prefer the existing project protection pattern.
- Do not introduce a new auth provider.
- Do not change route behavior unless protection is missing.
- If the route is intentionally reachable, add a short comment explaining the protection boundary.

Return:
- Whether protection already exists.
- The safest minimal change if protection is missing.
- Any edge cases I should test.`;
}

function createMissingEnvVariableFixPrompt(variableName: string, files: string[]) {
  return `Update the environment documentation for this project.

The variable ${variableName} is used in ${formatPromptFileList(files)} but is missing from .env.example.

Instructions:
- Add ${variableName}= to .env.example.
- Do not add a real secret value.
- Check if related environment variables used in the same file should also be documented.
- Keep comments clear and safe for public repos.

Return:
- The updated .env.example lines.
- A short explanation.`;
}

function createLargeFileFixPrompt(file: string) {
  return `Review ${file}.

Qodfy detected this as a large file.

Goal:
Suggest a safe refactor plan without changing behavior.

Instructions:
- Identify the main responsibilities inside the file.
- Suggest smaller components, hooks, or utility files that can be extracted.
- Do not rewrite the whole file at once.
- Do not change UI behavior.
- Do not change business logic.
- Prioritize low-risk extractions first.

Return:
- A short responsibility breakdown.
- A step-by-step refactor plan.
- The safest first extraction.`;
}

function createAiRateLimitFixPrompt(file: string) {
  return `Review the AI-related API route at ${file}.

Goal:
Add cost and abuse protection safely.

Instructions:
- Check the existing project patterns for auth, usage limits, or rate limiting.
- If this route can be called by users, add rate limiting or per-user usage protection.
- Do not introduce a new service unless necessary.
- Do not change the AI provider or model behavior.
- Keep the current response format unchanged.
- If the route is intentionally public, explain why and recommend a safe limit.

Return:
- The safest protection approach.
- The updated code.
- Any environment variables required.`;
}

function createWebhookSignatureFixPrompt(file: string) {
  return `Review the webhook API route at ${file}.

Goal:
Verify that webhook signature validation happens before the event is handled.

Instructions:
- Detect which provider this webhook belongs to based on imports, headers, and environment variables.
- Use the provider's existing verification pattern if already present.
- Do not process the webhook event before verification unless required by the provider.
- Do not introduce unrelated changes.
- If verification already exists, explain where it happens.

Return:
- Whether signature verification exists.
- If missing, the safest code change.
- Any test cases to run.`;
}

function createClientSideSecretFixPrompt(file: string, variableName: string) {
  return `Review the client-side file at ${file}.

Qodfy found ${variableName}, which does not start with NEXT_PUBLIC_.

Goal:
Confirm whether this environment variable may be exposed to the browser.

Instructions:
- Check whether this file is a client component or browser-executed code.
- If ${variableName} is server-only, move access to a server component, API route, or server action.
- Do not rename environment variables unless necessary.
- Do not add real secret values.
- Keep existing behavior unchanged.

Return:
- Whether the variable is safe in this file.
- The safest code change if it is not safe.
- Any edge cases I should test.`;
}

function createHardcodedSecretFixPrompt(file: string, secretLabel: string) {
  return `Review ${file} for a possible hardcoded ${secretLabel}.

Goal:
Remove any real secret from source code without changing behavior.

Instructions:
- Do not print or copy the secret value in your response.
- Move the value to an environment variable if it is a real secret.
- Add only the variable name to .env.example.
- Recommend rotating the secret if it may have been committed.
- Do not refactor unrelated code.

Return:
- Whether this looks like a real secret.
- The safest code change.
- Any follow-up security steps.`;
}

function createMissingEnvExampleFixPrompt() {
  return `Create or update .env.example for this project.

Goal:
Document the environment variables required to run and deploy the app.

Instructions:
- Inspect process.env usage in the project.
- Add variable names only.
- Do not add real secret values.
- Use empty placeholders like VARIABLE_NAME=.
- Add short comments only where they help future maintainers.

Return:
- The proposed .env.example content.
- A short explanation of any variables that need manual confirmation.`;
}

function createProjectRootFixPrompt() {
  return `Review how Qodfy is being run for this project.

Goal:
Make sure the scanner is pointed at the correct app root.

Instructions:
- Find the folder that contains the app package.json.
- If this is a monorepo, identify the Next.js app folder.
- Do not move files or refactor the project.
- Recommend the correct qodfy scan --path command.

Return:
- The correct folder to scan.
- The exact command to run.`;
}

function createPackageJsonFixPrompt() {
  return `Review package.json.

Goal:
Make package.json readable so tooling can detect the project correctly.

Instructions:
- Check for invalid JSON syntax.
- Keep existing dependencies and scripts unchanged unless they are malformed.
- Do not upgrade dependencies.
- Do not refactor unrelated files.

Return:
- The corrected package.json change.
- A short explanation.`;
}

function createNextNotDetectedFixPrompt() {
  return `Review this project structure.

Goal:
Determine whether Qodfy is scanning the correct Next.js app folder.

Instructions:
- Check whether this is a monorepo.
- Find the package.json that includes next as a dependency.
- Do not install or remove packages.
- Recommend the correct qodfy scan --path command if needed.

Return:
- Whether this is a Next.js app.
- The exact folder Qodfy should scan.`;
}

function createReadmeFixPrompt() {
  return `Create a practical README for this project.

Goal:
Help developers run, configure, and maintain the app.

Instructions:
- Include setup commands, environment variable documentation, local development, build, and deployment notes.
- Do not include real secret values.
- Keep the README concise and accurate.
- Do not invent features that are not in the project.

Return:
- The README content.
- Any assumptions that need confirmation.`;
}

function formatPromptFileList(files: string[]) {
  if (files.length === 1) {
    return files[0];
  }

  return `${files.length} files: ${formatFileList(files)}`;
}

function isPackageJsonObject(data: unknown): data is {
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
} {
  return typeof data === "object" && data !== null && !Array.isArray(data);
}

function normalizePath(filePath: string) {
  return filePath.split(path.sep).join("/");
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
