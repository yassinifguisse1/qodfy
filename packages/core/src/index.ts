import path from "node:path";
import fs from "node:fs/promises";
import fg from "fast-glob";

export type IssueSeverity = "critical" | "warning" | "info";

export type Issue = {
  severity: IssueSeverity;
  title: string;
  message: string;
  file?: string;
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

async function fileExists(filePath: string) {
  try {
    await fs.access(filePath);
    return true;
  } catch {
    return false;
  }
}

async function readJson(filePath: string) {
  const content = await fs.readFile(filePath, "utf-8");
  return JSON.parse(content);
}

export async function scanProject(projectPath: string): Promise<ScanReport> {
  const issues: Issue[] = [];

  const packageJsonPath = path.join(projectPath, "package.json");
  const hasPackageJson = await fileExists(packageJsonPath);

  if (!hasPackageJson) {
    issues.push({
      severity: "critical",
      title: "Missing package.json",
      message: "Qodfy could not find a package.json file in this project."
    });
  }

  let isNextProject = false;

  if (hasPackageJson) {
    const packageJson = await readJson(packageJsonPath);
    const deps = {
      ...packageJson.dependencies,
      ...packageJson.devDependencies
    };

    isNextProject = Boolean(deps.next);

    if (!isNextProject) {
      issues.push({
        severity: "warning",
        title: "Next.js not detected",
        message: "This first version of Qodfy is optimized for Next.js projects."
      });
    }
  }

  const envExamplePath = path.join(projectPath, ".env.example");
  const hasEnvExample = await fileExists(envExamplePath);

  if (!hasEnvExample) {
    issues.push({
      severity: "warning",
      title: "Missing .env.example",
      message: "Add a .env.example file so future developers know which environment variables are required."
    });
  }

  const hasReadme = await fileExists(path.join(projectPath, "README.md"));

  if (!hasReadme) {
    issues.push({
      severity: "info",
      title: "Missing README.md",
      message: "A README helps other developers understand how to run and maintain the project."
    });
  }

  const files = await fg(["**/*.{ts,tsx,js,jsx}"], {
    cwd: projectPath,
    ignore: ["node_modules/**", ".next/**", "dist/**", "build/**"],
    absolute: true
  });

  const apiRoutes = files.filter((file) => {
    return (
      file.includes(`${path.sep}app${path.sep}api${path.sep}`) ||
      file.includes(`${path.sep}pages${path.sep}api${path.sep}`)
    );
  });

  const aiKeywords = [
    "openai",
    "@ai-sdk",
    "ai/react",
    "anthropic",
    "gemini",
    "generateText",
    "streamText"
  ];

  let aiFiles = 0;
  let largeFiles = 0;

  for (const file of files) {
    const content = await fs.readFile(file, "utf-8");
    const relativeFile = path.relative(projectPath, file);

    if (content.length > 15000) {
      largeFiles++;

      issues.push({
        severity: "info",
        title: "Large file detected",
        message: "Large files are harder to maintain and often appear in AI-generated codebases.",
        file: relativeFile
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

      if (!hasRateLimit) {
        issues.push({
          severity: "critical",
          title: "AI route may be missing rate limiting",
          message: "AI routes can create real API costs. Add rate limiting or usage limits before launch.",
          file: relativeFile
        });
      }
    }
  }

  for (const route of apiRoutes) {
    const content = await fs.readFile(route, "utf-8");
    const relativeFile = path.relative(projectPath, route);

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
        file: relativeFile
      });
    }
  }

  const criticalCount = issues.filter((issue) => issue.severity === "critical").length;
  const warningCount = issues.filter((issue) => issue.severity === "warning").length;

  const score = Math.max(0, 100 - criticalCount * 20 - warningCount * 8);

  return {
    projectPath,
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