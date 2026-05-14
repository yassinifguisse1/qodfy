import fs from "node:fs/promises";
import path from "node:path";
import fg from "fast-glob";

export type IssueSeverity = "critical" | "warning" | "info";

export type Issue = {
  severity: IssueSeverity;
  title: string;
  message: string;
  file?: string;
  suggestion?: string;
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

type SafeReadResult =
  | { ok: true; content: string }
  | { ok: false; reason: string; code?: string };

type SafeJsonResult =
  | { ok: true; data: unknown }
  | { ok: false; reason: string; code?: string };

type SafeStatResult =
  | { ok: true; size: number }
  | { ok: false; reason: string; code?: string };

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

const LARGE_FILE_WARNING_BYTES = 15000;
const MAX_FILE_SIZE_BYTES = 500 * 1024;

export async function scanProject(projectPath: string): Promise<ScanReport> {
  const startTime = Date.now();
  const resolvedProjectPath = path.resolve(projectPath);
  const issues: Issue[] = [];

  const packageJsonPath = path.join(resolvedProjectPath, "package.json");
  const hasPackageJson = await fileExists(packageJsonPath);

  let isNextProject = false;

  if (!hasPackageJson) {
    issues.push({
      severity: "critical",
      title: "Missing package.json",
      message: "Qodfy could not find a package.json file in this project.",
      suggestion: "Run Qodfy from the project root or pass --path to the app folder."
    });
  } else {
    const packageJsonResult = await safeReadJson(packageJsonPath);

    if (!packageJsonResult.ok) {
      issues.push({
        severity: "critical",
        title: "Could not read package.json",
        message: packageJsonResult.reason,
        file: "package.json",
        suggestion: "Fix package.json so Qodfy can detect the framework and dependencies."
      });
    } else if (!isPackageJsonObject(packageJsonResult.data)) {
      issues.push({
        severity: "critical",
        title: "Invalid package.json",
        message: "package.json must contain a JSON object at the top level.",
        file: "package.json",
        suggestion: "Fix package.json so Qodfy can detect the framework and dependencies."
      });
    } else {
      const deps = {
        ...packageJsonResult.data.dependencies,
        ...packageJsonResult.data.devDependencies
      };

      isNextProject = Boolean(deps.next);

      if (!isNextProject) {
        issues.push({
          severity: "warning",
          title: "Next.js not detected",
          message: "This first version of Qodfy is optimized for Next.js projects.",
          suggestion: "If this is a monorepo, scan the Next.js app folder directly."
        });
      }
    }
  }

  const envExamplePath = path.join(resolvedProjectPath, ".env.example");
  const hasEnvExample = await fileExists(envExamplePath);
  let envExampleVariables: Set<string> | null = null;

  if (!hasEnvExample) {
    issues.push({
      severity: "warning",
      title: "Missing .env.example",
      message: "Add a .env.example file so future developers know which environment variables are required.",
      suggestion: "Document required variable names only, never real secret values."
    });
  } else {
    const envExampleResult = await safeReadFile(envExamplePath);

    if (!envExampleResult.ok) {
      issues.push({
        severity: "warning",
        title: "Could not read .env.example",
        message: envExampleResult.reason,
        file: ".env.example",
        suggestion: "Make sure .env.example is readable and contains variable names without real secret values."
      });
    } else {
      envExampleVariables = getEnvExampleVariables(envExampleResult.content);
    }
  }

  const hasReadme = await fileExists(path.join(resolvedProjectPath, "README.md"));

  if (!hasReadme) {
    issues.push({
      severity: "info",
      title: "Missing README.md",
      message: "A README helps other developers understand how to run and maintain the project."
    });
  }

  const files = await getSourceFiles(resolvedProjectPath, issues);

  const apiRoutes = files.filter((file) => {
    return isApiRoute(file);
  });
  const apiRouteSet = new Set(apiRoutes);

  const envExampleWarningKeys = new Set<string>();
  const clientSecretWarningKeys = new Set<string>();
  const hardcodedSecretWarningKeys = new Set<string>();
  let aiFiles = 0;
  let largeFiles = 0;

  for (const file of files) {
    const relativeFile = normalizePath(path.relative(resolvedProjectPath, file));
    const statResult = await safeStatFile(file);

    if (!statResult.ok) {
      issues.push({
        severity: "info",
        title: "File could not be checked",
        message: statResult.reason,
        file: relativeFile
      });
      continue;
    }

    if (statResult.size > MAX_FILE_SIZE_BYTES) {
      largeFiles++;

      issues.push({
        severity: "info",
        title: "Large file skipped from deep scan",
        message: "This file is larger than 500KB and was skipped from deep content checks.",
        file: relativeFile,
        suggestion: "Review large generated or bundled files manually."
      });
      continue;
    }

    const fileResult = await safeReadFile(file);

    if (!fileResult.ok) {
      issues.push({
        severity: "info",
        title: "File could not be read",
        message: fileResult.reason,
        file: relativeFile
      });
      continue;
    }

    const content = fileResult.content;

    if (statResult.size > LARGE_FILE_WARNING_BYTES) {
      largeFiles++;

      issues.push({
        severity: "info",
        title: "Large file detected",
        message: "Large files are harder to maintain and often appear in AI-generated codebases.",
        file: relativeFile,
        suggestion: "Consider splitting this file into smaller modules if it mixes unrelated responsibilities."
      });
    }

    const usesAI = aiKeywords.some((keyword) =>
      content.toLowerCase().includes(keyword.toLowerCase())
    );

    if (usesAI) {
      aiFiles++;

      const hasRateLimit =
        content.includes("rateLimit") ||
        content.includes("ratelimit") ||
        content.includes("upstash") ||
        content.includes("limiter");

      if (apiRouteSet.has(file) && !hasRateLimit) {
        issues.push({
          severity: "critical",
          title: "AI route may be missing rate limiting",
          message: "AI routes can create real API costs. Add rate limiting or usage limits before launch.",
          file: relativeFile,
          suggestion: "Add rate limiting, usage limits, or per-user quotas before launch."
        });
      }
    }

    const isStripeWebhook = isStripeWebhookRoute(relativeFile, content);
    const hasStripeSignatureVerification = hasStripeWebhookSignatureVerification(content);

    if (isStripeWebhook && !hasStripeSignatureVerification) {
      issues.push({
        severity: "critical",
        title: "Stripe webhook may be missing signature verification",
        message: "This Stripe webhook route does not appear to verify the Stripe signature before handling the event.",
        file: relativeFile,
        suggestion: "Use stripe.webhooks.constructEvent with the raw request body, Stripe-Signature header, and STRIPE_WEBHOOK_SECRET."
      });
    }

    for (const secretMatch of getHardcodedSecretMatches(content)) {
      const warningKey = `${relativeFile}:${secretMatch.label}`;

      if (hardcodedSecretWarningKeys.has(warningKey)) {
        continue;
      }

      hardcodedSecretWarningKeys.add(warningKey);

      issues.push({
        severity: "critical",
        title: "Possible hardcoded secret",
        message: `A string literal in ${relativeFile} matches the pattern for ${secretMatch.label}. Qodfy does not print possible secret values.`,
        file: relativeFile,
        suggestion: "Move secrets into environment variables and rotate the value if this is a real secret."
      });
    }

    if (apiRouteSet.has(file)) {
      const hasAuth =
        content.includes("auth(") ||
        content.includes("getServerSession") ||
        content.includes("currentUser") ||
        content.includes("clerkClient") ||
        content.includes("session");

      if (!hasAuth && !isStripeWebhook) {
        issues.push({
          severity: "warning",
          title: "API route may be missing authentication",
          message: "This API route does not appear to contain an auth/session check.",
          file: relativeFile,
          suggestion: "Confirm the route is public, or add an auth/session check before handling user data."
        });
      }
    }

    const usedEnvVariables = getUsedEnvVariables(content);

    if (envExampleVariables) {
      for (const variableName of usedEnvVariables) {
        if (!envExampleVariables.has(variableName)) {
          const warningKey = `${relativeFile}:${variableName}`;

          if (envExampleWarningKeys.has(warningKey)) {
            continue;
          }

          envExampleWarningKeys.add(warningKey);

          issues.push({
            severity: "warning",
            title: "Environment variable missing from .env.example",
            message: `${variableName} is used in ${relativeFile} but is not documented in .env.example.`,
            file: relativeFile,
            suggestion: `Add ${variableName}= to .env.example without including a real value.`
          });
        }
      }
    }

    if (isClientSideFile(relativeFile, content)) {
      for (const variableName of usedEnvVariables) {
        if (!variableName.startsWith("NEXT_PUBLIC_")) {
          const warningKey = `${relativeFile}:${variableName}`;

          if (clientSecretWarningKeys.has(warningKey)) {
            continue;
          }

          clientSecretWarningKeys.add(warningKey);

          issues.push({
            severity: "warning",
            title: "Possible server secret used in client-side code",
            message: `${variableName} appears in a client-side file. Server secrets should not be exposed to the browser.`,
            file: relativeFile,
            suggestion: "Move server-only environment variable access to a server component, API route, or server action."
          });
        }
      }
    }
  }

  const criticalCount = issues.filter((issue) => issue.severity === "critical").length;
  const warningCount = issues.filter((issue) => issue.severity === "warning").length;

  const score = Math.max(0, 100 - criticalCount * 20 - warningCount * 8);

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

async function getSourceFiles(projectPath: string, issues: Issue[]) {
  try {
    return await fg(sourceFilePatterns, {
      cwd: projectPath,
      ignore: ignoredPaths,
      absolute: true,
      onlyFiles: true,
      dot: false
    });
  } catch {
    issues.push({
      severity: "critical",
      title: "Could not scan source files",
      message: "Qodfy could not list source files in this project.",
      suggestion: "Check that the project path exists and is readable."
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
  return (
    filePath.includes(`${path.sep}app${path.sep}api${path.sep}`) ||
    filePath.includes(`${path.sep}pages${path.sep}api${path.sep}`)
  );
}

function isStripeWebhookRoute(relativeFile: string, content: string) {
  const normalizedFile = relativeFile.toLowerCase();
  const normalizedContent = content.toLowerCase();

  return (
    normalizedContent.includes("stripe") &&
    (
      normalizedFile.includes("webhook") ||
      normalizedContent.includes("webhook") ||
      normalizedContent.includes("stripe.webhooks")
    )
  );
}

function hasStripeWebhookSignatureVerification(content: string) {
  return (
    content.includes("stripe.webhooks.constructEvent") ||
    content.includes("webhooks.constructEvent") ||
    content.includes("constructEvent(")
  );
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
