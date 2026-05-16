import fs from "node:fs/promises";
import path from "node:path";
import fg from "fast-glob";

export type IssueSeverity = "critical" | "warning" | "info";
export type IssueConfidence = "high" | "medium" | "low";
export type IssueEvidence = {
  label: string;
  detail?: string;
};

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
  evidence?: IssueEvidence[];
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

type ApiRouteMethod = "GET" | "POST" | "PUT" | "PATCH" | "DELETE";

type ApiRouteAnalysis = {
  file: string;
  relativeFile: string;
  methods: ApiRouteMethod[];
  intent: ApiRouteIntent;
  authExpected: boolean | "review";
  confidence: IssueConfidence;
  evidence: IssueEvidence[];
  hasAuth: boolean;
  hasSecretProtection: boolean;
  hasRateLimit: boolean;
  hasValidation: boolean;
  hasCacheHeaders: boolean;
  hasMethodBlocking: boolean;
  hasWebhookVerification: boolean;
  webhookProvider: WebhookProvider;
};

type MaintainabilityFileKind =
  | "react-component"
  | "api-route"
  | "server-action"
  | "typescript-module"
  | "schema-or-validation"
  | "types"
  | "config"
  | "unknown";

type IssueInput = Omit<Issue, "id" | "confidence"> & {
  confidence?: IssueConfidence;
};
type AddIssue = (issue: IssueInput) => void;

const sourceFilePatterns = ["**/*.{ts,tsx,js,jsx,mts,cts,mjs,cjs}"];

const ignoredPaths = [
  "node_modules/**",
  "**/node_modules/**",
  ".next/**",
  "**/.next/**",
  "dist/**",
  "**/dist/**",
  "build/**",
  "**/build/**",
  ".turbo/**",
  "**/.turbo/**",
  ".vercel/**",
  "**/.vercel/**",
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
  "sensitive-api-route-missing-auth": "sensitive-api-route-missing-auth",
  "api-public-read-route": "api-public-read-route",
  "public-form-missing-abuse-protection": "public-form-missing-abuse-protection",
  "internal-route-missing-protection": "internal-route-missing-protection",
  "api-mutation-route-review-auth": "api-mutation-route-review-auth",
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
        const largeFileKind = getMaintainabilityFileKind(relativeFile);

        addIssue({
          ruleId: "maintainability-large-file-skipped",
          category: "maintainability",
          severity: "info",
          confidence: "low",
          title: "Large file skipped from deep scan",
          message: "This file is larger than 500KB and was skipped from deep content checks.",
          file: relativeFile,
          suggestion: "Review large generated or bundled files manually.",
          fixPrompt: createLargeFileFixPrompt(relativeFile, largeFileKind)
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

      const hasRateLimit = hasRateLimitSignal(content);

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

    const apiRouteAnalysis = (runWebhookChecks || runApiChecks) && apiRouteSet.has(file)
      ? analyzeApiRoute({
        file,
        relativeFile,
        content
      })
      : null;

    if (
      runWebhookChecks &&
      apiRouteAnalysis?.intent === "webhook" &&
      !apiRouteAnalysis.hasWebhookVerification
    ) {
      addIssue({
        ruleId: "webhook-missing-signature-verification",
        category: "webhook",
        severity: apiRouteAnalysis.confidence === "high" ? "critical" : "warning",
        confidence: apiRouteAnalysis.confidence,
        title: "Webhook route may be missing signature verification",
        message: "This webhook route appears to handle external events, but Qodfy could not find signature verification before the event is handled.",
        file: relativeFile,
        suggestion: getWebhookSignatureSuggestion(apiRouteAnalysis.webhookProvider),
        fixPrompt: createWebhookSignatureFixPrompt(relativeFile),
        evidence: apiRouteAnalysis.evidence
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

    if (runApiChecks && apiRouteAnalysis) {
      addApiRouteProtectionIssues({
        addIssue,
        includeLowConfidence,
        analysis: apiRouteAnalysis
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
    const largeFileKind = getMaintainabilityFileKind(largeFile.relativeFile);
    const largeFileCopy = getLargeFileIssueCopy(largeFileKind);

    addIssue({
      ruleId: "maintainability-large-file",
      category: "maintainability",
      severity: "info",
      confidence: "low",
      title: largeFileCopy.title,
      message: largeFileCopy.message,
      file: largeFile.relativeFile,
      suggestion: largeFileCopy.suggestion,
      fixPrompt: createLargeFileFixPrompt(largeFile.relativeFile, largeFileKind)
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
    const rawFiles = await fg(sourceFilePatterns, {
      cwd: projectPath,
      ignore: ignoredPaths,
      absolute: true,
      onlyFiles: true,
      dot: false
    });

    const files = rawFiles.filter((file) => {
      const relativeFile = normalizePath(path.relative(projectPath, file));

      return !shouldIgnoreSourceFile(relativeFile);
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

function shouldIgnoreSourceFile(relativeFile: string) {
  const normalizedFile = normalizePath(relativeFile);
  const pathParts = normalizedFile.split("/");
  const ignoredPathParts = new Set([
    "node_modules",
    ".next",
    "dist",
    "build",
    ".turbo",
    ".vercel",
    "coverage",
    ".cache",
    ".output",
    ".open-next",
    "storybook-static",
    "playwright-report",
    "test-results",
    "generated",
    "__generated__"
  ]);

  if (
    normalizedFile.endsWith(".d.ts") ||
    normalizedFile.endsWith(".map")
  ) {
    return true;
  }

  return pathParts.some((pathPart) => ignoredPathParts.has(pathPart));
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
  includeLowConfidence,
  analysis
}: {
  addIssue: AddIssue;
  includeLowConfidence: boolean;
  analysis: ApiRouteAnalysis;
}) {
  if (analysis.intent === "webhook") {
    return;
  }

  if (analysis.intent === "public-read") {
    if (includeLowConfidence) {
      addIssue({
        ruleId: "api-public-read-route",
        category: "api",
        severity: "info",
        confidence: analysis.confidence,
        title: "Public read API route detected",
        message: "This route appears intentionally public. Authentication may not be required.",
        file: analysis.relativeFile,
        suggestion: "Verify that it only exposes public or published data and has appropriate validation, caching, and abuse protection.",
        fixPrompt: createPublicReadRouteFixPrompt(analysis.relativeFile),
        evidence: analysis.evidence
      });
    }

    return;
  }

  if (analysis.intent === "public-form") {
    if (!analysis.hasRateLimit && !analysis.hasValidation) {
      addIssue({
        ruleId: "public-form-missing-abuse-protection",
        category: "api",
        severity: "warning",
        confidence: analysis.confidence,
        title: "Public form route may be missing abuse protection",
        message: "This route appears to accept public submissions. Consider adding rate limiting, validation, or spam protection.",
        file: analysis.relativeFile,
        suggestion: "Check for rate limiting, validation, captcha, Turnstile, reCAPTCHA, hCaptcha, or another spam protection pattern.",
        fixPrompt: createPublicFormProtectionFixPrompt(analysis.relativeFile),
        evidence: analysis.evidence
      });
    }

    return;
  }

  if (analysis.intent === "internal") {
    if (!analysis.hasAuth && !analysis.hasSecretProtection) {
      addIssue({
        ruleId: "internal-route-missing-protection",
        category: "security",
        severity: "warning",
        confidence: analysis.confidence,
        title: "Internal API route may be missing protection",
        message: "This route appears internal or operational. Confirm it is protected by auth, a secret token, or server-only access.",
        file: analysis.relativeFile,
        suggestion: "Use the project's existing auth pattern or a secret token check for operational routes such as cron, cleanup, or revalidation.",
        fixPrompt: createInternalRouteProtectionFixPrompt(analysis.relativeFile),
        evidence: analysis.evidence
      });
    }

    return;
  }

  if (analysis.intent === "sensitive-mutation") {
    if (!analysis.hasAuth) {
      addIssue({
        ruleId: "sensitive-api-route-missing-auth",
        category: "security",
        severity: "warning",
        confidence: analysis.confidence,
        title: "Sensitive API route may be missing authentication",
        message: "This route appears to handle user-specific or sensitive operations. Confirm it is protected before launch.",
        file: analysis.relativeFile,
        suggestion: "Review the existing project auth/session pattern and apply it if this route handles private data, uploads, payments, or account changes.",
        fixPrompt: createApiAuthFixPrompt(analysis.relativeFile),
        evidence: analysis.evidence
      });
    }

    return;
  }

  if (analysis.authExpected === "review" && !analysis.hasAuth) {
    addIssue({
      ruleId: "api-mutation-route-review-auth",
      category: "api",
      severity: "warning",
      confidence: analysis.confidence,
      title: "API mutation route should be reviewed for authentication",
      message: "This route mutates data or handles requests, but Qodfy could not determine whether authentication is required.",
      file: analysis.relativeFile,
      suggestion: "Confirm the route is intentionally public, or add the existing project auth/session check before handling private data.",
      fixPrompt: createApiAuthFixPrompt(analysis.relativeFile),
      evidence: analysis.evidence
    });
  }
}

function analyzeApiRoute({
  file,
  relativeFile,
  content
}: {
  file: string;
  relativeFile: string;
  content: string;
}): ApiRouteAnalysis {
  const normalizedFile = relativeFile.toLowerCase();
  const methods = getRouteHttpMethods(content);
  const evidence: IssueEvidence[] = [];
  const webhookRouteInfo = getWebhookRouteInfo(relativeFile, content);
  const hasAuth = hasAuthOrSessionCheck(content);
  const hasSecretProtection = hasSecretProtectionSignal(content);
  const hasRateLimit = hasRateLimitSignal(content);
  const hasValidation = hasValidationSignal(content);
  const hasCacheHeaders = hasCacheHeaderSignal(content);
  const hasMethodBlocking = hasMethodBlockingSignal(content);
  const webhookProvider = webhookRouteInfo?.provider ?? "unknown";
  const hasWebhookVerification = hasWebhookSignatureVerification(content, webhookProvider);

  if (methods.length > 0) {
    for (const method of methods) {
      evidence.push({ label: "exports", detail: method });
    }
  } else {
    evidence.push({ label: "no exported HTTP method detected" });
  }

  const webhookPathMatch = getRoutePathMatch(normalizedFile, ["webhook", "webhooks", "callback"]);
  const internalPathMatch = getRoutePathMatch(normalizedFile, ["internal", "admin", "cron", "cleanup", "revalidate", "private"]);
  const formPathMatch = getRoutePathMatch(normalizedFile, ["contact", "subscribe", "newsletter", "lead", "inquiry"]);
  const sensitivePathMatch = getRoutePathMatch(normalizedFile, [
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
  ]);
  const publicContentPathMatch = getRoutePathMatch(normalizedFile, [
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
  ]);

  let intent: ApiRouteIntent = "unknown";

  if (webhookRouteInfo || webhookPathMatch) {
    intent = "webhook";
    evidence.push({
      label: webhookPathMatch ? "webhook path detected" : "webhook content detected",
      detail: webhookPathMatch ?? webhookProvider
    });
  } else if (internalPathMatch) {
    intent = "internal";
    evidence.push({ label: "path contains", detail: internalPathMatch });
  } else if (formPathMatch) {
    intent = "public-form";
    evidence.push({ label: "path contains", detail: formPathMatch });
  } else if (hasMutationMethod(methods) && sensitivePathMatch) {
    intent = "sensitive-mutation";
    evidence.push({ label: "path contains", detail: sensitivePathMatch });
  } else if (methods.includes("GET") && publicContentPathMatch && !sensitivePathMatch && !internalPathMatch) {
    intent = "public-read";
    evidence.push({ label: "public content route detected", detail: publicContentPathMatch });
  }

  if (hasAuth) {
    evidence.push({ label: "auth/session check detected" });
  } else {
    evidence.push({ label: "no auth/session check detected" });
  }

  if (hasSecretProtection) {
    evidence.push({ label: "secret token check detected" });
  }

  if (hasRateLimit) {
    evidence.push({ label: "rate limit detected" });
  } else if (intent === "public-form") {
    evidence.push({ label: "no rate limit detected" });
  }

  if (hasValidation) {
    evidence.push({ label: "validation detected" });
  } else if (intent === "public-form") {
    evidence.push({ label: "no validation detected" });
  }

  if (hasCacheHeaders) {
    evidence.push({ label: "cache/public-read safety signal detected" });
  }

  if (hasMethodBlocking) {
    evidence.push({ label: "method blocking detected" });
  }

  if (intent === "webhook") {
    if (hasWebhookVerification) {
      evidence.push({ label: "webhook signature verification detected" });
    } else {
      evidence.push({ label: "no webhook signature verification detected" });
    }
  }

  return {
    file,
    relativeFile,
    methods,
    intent,
    authExpected: getAuthExpectation(intent, methods),
    confidence: getApiRouteConfidence(intent, methods, webhookRouteInfo),
    evidence,
    hasAuth,
    hasSecretProtection,
    hasRateLimit,
    hasValidation,
    hasCacheHeaders,
    hasMethodBlocking,
    hasWebhookVerification,
    webhookProvider
  };
}

function getAuthExpectation(intent: ApiRouteIntent, methods: ApiRouteMethod[]): boolean | "review" {
  if (intent === "internal" || intent === "sensitive-mutation") {
    return true;
  }

  if (intent === "unknown" && hasMutationMethod(methods)) {
    return "review";
  }

  return false;
}

function getApiRouteConfidence(
  intent: ApiRouteIntent,
  methods: ApiRouteMethod[],
  webhookRouteInfo: WebhookRouteInfo | null
): IssueConfidence {
  if (intent === "sensitive-mutation" || intent === "internal") {
    return "high";
  }

  if (intent === "webhook") {
    return webhookRouteInfo?.confidence === "high" ? "high" : "medium";
  }

  if (intent === "public-form" || (intent === "unknown" && hasMutationMethod(methods))) {
    return "medium";
  }

  return "low";
}

function getRoutePathMatch(normalizedFile: string, terms: string[]) {
  return terms.find((term) => {
    const escapedTerm = term.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

    return new RegExp(`(^|[\\/._\\[\\]-])${escapedTerm}([\\/._\\[\\]-]|$)`).test(normalizedFile);
  });
}

function getExportedHttpMethods(content: string): ApiRouteMethod[] {
  const methods = new Set<ApiRouteMethod>();
  const functionExportPattern = /\bexport\s+(?:async\s+)?function\s+(GET|POST|PUT|PATCH|DELETE)\b/g;
  const constExportPattern = /\bexport\s+const\s+(GET|POST|PUT|PATCH|DELETE)\b/g;

  for (const match of content.matchAll(functionExportPattern)) {
    methods.add(match[1] as ApiRouteMethod);
  }

  for (const match of content.matchAll(constExportPattern)) {
    methods.add(match[1] as ApiRouteMethod);
  }

  return [...methods];
}

function getRouteHttpMethods(content: string): ApiRouteMethod[] {
  const methods = new Set<ApiRouteMethod>(getExportedHttpMethods(content));
  const requestMethodPattern = /\b(?:request|req)\.method\s*(?:={2,3}|!={1,2})\s*["'](GET|POST|PUT|PATCH|DELETE)["']/g;
  const methodCasePattern = /\bcase\s+["'](GET|POST|PUT|PATCH|DELETE)["']/g;

  for (const match of content.matchAll(requestMethodPattern)) {
    methods.add(match[1] as ApiRouteMethod);
  }

  for (const match of content.matchAll(methodCasePattern)) {
    methods.add(match[1] as ApiRouteMethod);
  }

  return [...methods];
}

function hasMutationMethod(methods: ApiRouteMethod[]) {
  return ["POST", "PUT", "PATCH", "DELETE"].some((method) =>
    methods.includes(method as ApiRouteMethod)
  );
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

function hasSecretProtectionSignal(content: string) {
  const normalizedContent = content.toLowerCase();

  return (
    /\bprocess\.env\.[A-Za-z0-9_]*SECRET\b/.test(content) ||
    /\bprocess\.env\[['"`][A-Za-z0-9_]*SECRET['"`]\]/.test(content) ||
    normalizedContent.includes("cron_secret") ||
    normalizedContent.includes("revalidate_secret") ||
    normalizedContent.includes("authorization") ||
    normalizedContent.includes("bearer") ||
    normalizedContent.includes("token")
  );
}

function hasRateLimitSignal(content: string) {
  const normalizedContent = content.toLowerCase();

  return (
    normalizedContent.includes("ratelimit") ||
    normalizedContent.includes("rate limit") ||
    normalizedContent.includes("limiter") ||
    normalizedContent.includes("upstash") ||
    normalizedContent.includes("throttle")
  );
}

function hasValidationSignal(content: string) {
  const normalizedContent = content.toLowerCase();

  return (
    normalizedContent.includes("zod") ||
    normalizedContent.includes("schema") ||
    normalizedContent.includes("validate") ||
    normalizedContent.includes("validation") ||
    normalizedContent.includes("sanitize") ||
    normalizedContent.includes("safeparse") ||
    normalizedContent.includes("parse(") ||
    normalizedContent.includes("slugregex") ||
    normalizedContent.includes("isvalid") ||
    normalizedContent.includes("captcha") ||
    normalizedContent.includes("turnstile") ||
    normalizedContent.includes("recaptcha") ||
    normalizedContent.includes("hcaptcha")
  );
}

function hasCacheHeaderSignal(content: string) {
  const normalizedContent = content.toLowerCase();

  return (
    normalizedContent.includes("cache-control") ||
    normalizedContent.includes("s-maxage") ||
    normalizedContent.includes("stale-while-revalidate") ||
    normalizedContent.includes("public") ||
    normalizedContent.includes("published") ||
    normalizedContent.includes("status")
  );
}

function hasMethodBlockingSignal(content: string) {
  const normalizedContent = content.toLowerCase();

  return (
    normalizedContent.includes("method not allowed") ||
    normalizedContent.includes("status: 405") ||
    /\b405\b/.test(normalizedContent)
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

function getMaintainabilityFileKind(relativeFile: string): MaintainabilityFileKind {
  const normalizedFile = normalizePath(relativeFile).toLowerCase();
  const fileName = path.basename(normalizedFile);

  if (
    /(^|\/)app\/api\/.+\/route\.(?:ts|js)$/.test(normalizedFile) ||
    /(^|\/)pages\/api\/.+\.(?:ts|js)$/.test(normalizedFile)
  ) {
    return "api-route";
  }

  if (fileName === "actions.ts" || fileName === "actions.tsx") {
    return "server-action";
  }

  if (
    fileName === "schema.ts" ||
    fileName === "schemas.ts" ||
    fileName === "validation.ts" ||
    fileName === "validator.ts"
  ) {
    return "schema-or-validation";
  }

  if (
    fileName === "types.ts" ||
    fileName === "type.ts" ||
    fileName === "interfaces.ts"
  ) {
    return "types";
  }

  if (
    fileName === "config.ts" ||
    fileName === "config.js" ||
    fileName === "next.config.ts" ||
    fileName === "tailwind.config.ts"
  ) {
    return "config";
  }

  if (normalizedFile.endsWith(".tsx") || normalizedFile.endsWith(".jsx")) {
    return "react-component";
  }

  if (/\.(?:ts|js|mts|cts|mjs|cjs)$/.test(normalizedFile)) {
    return "typescript-module";
  }

  return "unknown";
}

function getLargeFileIssueCopy(kind: MaintainabilityFileKind) {
  if (kind === "react-component") {
    return {
      title: "Large React component detected",
      message: "This component is larger than the recommended maintainability threshold. Large components can be harder to review, test, and safely modify.",
      suggestion: "Review whether this component mixes UI, state, data fetching, validation, or business logic. If so, split it into smaller components, hooks, or utilities."
    };
  }

  if (kind === "typescript-module") {
    return {
      title: "Large TypeScript module detected",
      message: "This module is larger than the recommended maintainability threshold. Large modules can mix business logic, data access, transformations, constants, or helper functions in one place.",
      suggestion: "Review whether this module mixes unrelated responsibilities such as data fetching, filtering, mapping, sorting, constants, types, or business rules. If so, split it into smaller modules while preserving public exports."
    };
  }

  if (kind === "api-route") {
    return {
      title: "Large API route detected",
      message: "This API route is larger than the recommended maintainability threshold. Large route handlers can mix validation, auth, business logic, and response formatting.",
      suggestion: "Review whether this route mixes validation, authentication, business logic, and response formatting. If so, extract reusable helpers without changing route behavior."
    };
  }

  if (kind === "server-action") {
    return {
      title: "Large server action file detected",
      message: "This server action file is larger than the recommended maintainability threshold and may mix validation, data mutations, and business rules.",
      suggestion: "Review whether this file mixes validation, permission checks, mutations, and formatting. If so, extract helpers while preserving action behavior."
    };
  }

  if (kind === "schema-or-validation") {
    return {
      title: "Large schema or validation file detected",
      message: "This schema or validation file is larger than the recommended maintainability threshold and may mix unrelated validation concerns.",
      suggestion: "Review whether related schemas or validators can be grouped into smaller files while preserving exported names and validation behavior."
    };
  }

  if (kind === "types") {
    return {
      title: "Large type definition file detected",
      message: "This type file is larger than the recommended maintainability threshold and may be harder to navigate safely.",
      suggestion: "Review whether types can be split by domain or feature while preserving public exports and imports."
    };
  }

  if (kind === "config") {
    return {
      title: "Large config file detected",
      message: "This config file is larger than the recommended maintainability threshold and may mix unrelated configuration concerns.",
      suggestion: "Review whether configuration values or helper functions can be moved to smaller supporting modules without changing runtime behavior."
    };
  }

  return {
    title: "Large file detected",
    message: "This file is larger than the recommended maintainability threshold. Large files can be harder to review, test, and safely modify.",
    suggestion: "Review whether this file mixes unrelated responsibilities. If so, split it into smaller modules while preserving behavior."
  };
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

function createLargeFileFixPrompt(
  file: string,
  kind: MaintainabilityFileKind = getMaintainabilityFileKind(file)
) {
  if (kind === "react-component") {
    return `Review ${file}.

Qodfy detected this as a large React component.

Goal:
Suggest a safe refactor plan without changing behavior.

Instructions:
- Identify the main responsibilities inside the component.
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

  if (kind === "typescript-module") {
    return `Review ${file}.

Qodfy detected this as a large TypeScript module.

Goal:
Create a safe refactor plan without changing behavior.

Instructions:
- Identify the main responsibilities inside this module.
- Check whether the file mixes unrelated concerns such as data fetching, filtering, mapping, sorting, constants, types, validation, or business rules.
- Suggest smaller TypeScript modules that could be extracted safely.
- Do not rewrite the whole file at once.
- Do not change business logic.
- Do not change public exports unless you also update all imports safely.
- Preserve existing function behavior, return types, and error handling.
- Prioritize the lowest-risk extraction first.

Return:
- Responsibility breakdown.
- Suggested new file/module structure.
- Step-by-step refactor plan.
- The safest first extraction.
- Tests or manual checks to run.`;
  }

  if (kind === "api-route") {
    return `Review the API route at ${file}.

Qodfy detected this as a large API route file.

Goal:
Create a safe refactor plan without changing HTTP behavior.

Instructions:
- Identify where validation, authentication, business logic, and response formatting happen.
- Suggest helper modules that can be extracted without changing the route contract.
- Preserve HTTP methods, status codes, headers, auth checks, validation behavior, and response shape.
- Do not rewrite the whole route at once.
- Do not introduce a new auth provider or validation library.
- Prioritize the lowest-risk extraction first.

Return:
- Responsibility breakdown.
- Suggested helper/module structure.
- Step-by-step refactor plan.
- The safest first extraction.
- Tests or manual checks to run.`;
  }

  if (kind === "server-action") {
    return `Review the server action file at ${file}.

Qodfy detected this as a large server action file.

Goal:
Create a safe refactor plan without changing action behavior.

Instructions:
- Identify validation, permission checks, mutations, cache invalidation, formatting, and error handling.
- Suggest helper modules that can be extracted safely.
- Preserve permissions, validation behavior, data mutations, cache invalidation, return shape, and error handling.
- Do not rewrite the whole file at once.
- Do not change public action names unless you also update every import safely.
- Prioritize the lowest-risk extraction first.

Return:
- Responsibility breakdown.
- Suggested helper/module structure.
- Step-by-step refactor plan.
- The safest first extraction.
- Tests or manual checks to run.`;
  }

  if (kind === "schema-or-validation") {
    return `Review the schema or validation file at ${file}.

Qodfy detected this as a large validation-focused file.

Goal:
Create a safe refactor plan without changing validation behavior.

Instructions:
- Identify related schemas, validators, shared constants, and inferred types.
- Suggest smaller validation modules grouped by feature or domain.
- Do not change validation rules, error messages, inferred types, or public exports unless you also update all imports safely.
- Prioritize the lowest-risk extraction first.

Return:
- Responsibility breakdown.
- Suggested file/module structure.
- Step-by-step refactor plan.
- The safest first extraction.
- Tests or manual checks to run.`;
  }

  if (kind === "types") {
    return `Review the type definition file at ${file}.

Qodfy detected this as a large type file.

Goal:
Create a safe organization plan without changing runtime behavior.

Instructions:
- Identify groups of related types, interfaces, enums, and exported utility types.
- Suggest smaller type modules grouped by domain or feature.
- Do not change type names, public exports, or imports unless you also update all references safely.
- Prioritize the lowest-risk extraction first.

Return:
- Type responsibility breakdown.
- Suggested file/module structure.
- Step-by-step refactor plan.
- The safest first extraction.
- Type-check command to run.`;
  }

  if (kind === "config") {
    return `Review the config file at ${file}.

Qodfy detected this as a large config file.

Goal:
Create a safe simplification plan without changing runtime configuration.

Instructions:
- Identify config sections, constants, plugin setup, and helper functions.
- Suggest supporting modules only if extraction reduces complexity.
- Preserve all existing config values, plugin order, environment behavior, and exports.
- Do not upgrade dependencies or change framework behavior.
- Prioritize the lowest-risk extraction first.

Return:
- Config responsibility breakdown.
- Suggested supporting module structure.
- Step-by-step refactor plan.
- The safest first extraction.
- Build or validation command to run.`;
  }

  return `Review ${file}.

Qodfy detected this as a large file.

Goal:
Create a safe refactor plan without changing behavior.

Instructions:
- Identify the main responsibilities inside the file.
- Suggest smaller files or modules that can be extracted safely.
- Do not rewrite the whole file at once.
- Do not change public exports unless you also update all imports safely.
- Preserve existing behavior, return values, and error handling.
- Prioritize the lowest-risk extraction first.

Return:
- Responsibility breakdown.
- Suggested file/module structure.
- Step-by-step refactor plan.
- The safest first extraction.
- Tests or manual checks to run.`;
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
