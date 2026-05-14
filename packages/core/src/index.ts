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
  };
};

type SafeReadResult =
  | { ok: true; content: string }
  | { ok: false; reason: string; code?: string };

type SafeJsonResult =
  | { ok: true; data: unknown }
  | { ok: false; reason: string; code?: string };

const sourceFilePatterns = ["**/*.{ts,tsx,js,jsx,mts,cts,mjs,cjs}"];

const ignoredPaths = [
  "node_modules/**",
  ".next/**",
  "dist/**",
  "build/**",
  ".turbo/**",
  ".vercel/**"
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

export async function scanProject(projectPath: string): Promise<ScanReport> {
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
    return (
      file.includes(`${path.sep}app${path.sep}api${path.sep}`) ||
      file.includes(`${path.sep}pages${path.sep}api${path.sep}`)
    );
  });
  const apiRouteSet = new Set(apiRoutes);

  const readableFiles = new Map<string, string>();
  const envExampleWarningKeys = new Set<string>();
  const clientSecretWarningKeys = new Set<string>();
  let aiFiles = 0;
  let largeFiles = 0;

  for (const file of files) {
    const fileResult = await safeReadFile(file);
    const relativeFile = normalizePath(path.relative(resolvedProjectPath, file));

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
    readableFiles.set(file, content);

    if (content.length > 15000) {
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

  for (const route of apiRoutes) {
    const content = readableFiles.get(route);

    if (!content) {
      continue;
    }

    const relativeFile = normalizePath(path.relative(resolvedProjectPath, route));

    const hasAuth =
      content.includes("auth(") ||
      content.includes("getServerSession") ||
      content.includes("currentUser") ||
      content.includes("clerkClient") ||
      content.includes("session");

    if (!hasAuth) {
      issues.push({
        severity: "warning",
        title: "API route may be missing authentication",
        message: "This API route does not appear to contain an auth/session check.",
        file: relativeFile,
        suggestion: "Confirm the route is public, or add an auth/session check before handling user data."
      });
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
      largeFiles
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

  for (const match of content.matchAll(dotAccessPattern)) {
    variables.add(match[1]);
  }

  for (const match of content.matchAll(bracketAccessPattern)) {
    variables.add(match[1]);
  }

  return variables;
}

function isClientSideFile(relativeFile: string, content: string) {
  const fileName = path.basename(relativeFile);

  return (
    fileName.includes(".client.") ||
    /(^|\n)\s*["']use client["'];?/.test(content)
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
