declare module "@qodfy/core" {
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
  export type ScanCheck =
    | "project"
    | "api"
    | "environment"
    | "ai"
    | "webhook"
    | "maintainability"
    | "security";
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
    context?: IssueEvidence[];
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

  export const validScanChecks: readonly ScanCheck[];
  export const recommendedScanChecks: ScanCheck[];
  export function scanProject(input: string | ScanOptions): Promise<ScanReport>;
}
