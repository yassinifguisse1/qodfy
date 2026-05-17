import assert from "node:assert/strict";
import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { after, before, describe, it } from "node:test";
import { scanProject } from "./index.ts";

let fixtureRoot = "";

async function writeFixtureRoute(relativeFile: string, content: string) {
  const filePath = path.join(fixtureRoot, relativeFile);

  await mkdir(path.dirname(filePath), { recursive: true });
  await writeFile(filePath, content);
}

async function scanApiIssues() {
  const report = await scanProject({
    projectPath: fixtureRoot,
    checks: ["api"],
    includeLowConfidence: true
  });

  return report.issues;
}

describe("api handler protection signals", () => {
  before(async () => {
    fixtureRoot = await mkdtemp(path.join(os.tmpdir(), "qodfy-protection-"));
    await writeFile(
      path.join(fixtureRoot, "package.json"),
      JSON.stringify({ private: true, dependencies: { next: "^15.0.0" } }, null, 2)
    );
  });

  after(async () => {
    if (fixtureRoot) {
      await rm(fixtureRoot, { recursive: true, force: true });
    }
  });

  it("still warns when only a comment mentions session", async () => {
    await writeFixtureRoute(
      "app/api/upload/comment-session/route.ts",
      `
        export async function POST(request: Request) {
          // session lookup happens elsewhere
          const formData = await request.formData();
          return Response.json({ ok: true });
        }
      `
    );

    const issues = await scanApiIssues();
    const issue = issues.find((scanIssue) =>
      scanIssue.file === "app/api/upload/comment-session/route.ts"
    );

    assert.equal(issue?.ruleId, "sensitive-api-route-missing-auth");
    assert.match(
      issue.evidence?.map((item) => item.label).join(" ") ?? "",
      /possible auth-related signal detected/
    );
  });

  it("still warns when Authorization is mentioned without a guard", async () => {
    await writeFixtureRoute(
      "app/api/upload/authorization-only/route.ts",
      `
        export async function POST(request: Request) {
          const authorization = request.headers.get("Authorization");
          const formData = await request.formData();
          return Response.json({ authorization });
        }
      `
    );

    const issues = await scanApiIssues();
    const issue = issues.find((scanIssue) =>
      scanIssue.file === "app/api/upload/authorization-only/route.ts"
    );

    assert.equal(issue?.ruleId, "sensitive-api-route-missing-auth");
    assert.match(
      issue.evidence?.map((item) => item.label).join(" ") ?? "",
      /possible auth-related signal detected/
    );
  });

  it("does not warn when helper result is guarded with 401", async () => {
    await writeFixtureRoute(
      "app/api/upload/protected/route.ts",
      `
        import { getStaffUserAdminOrManager } from "@/lib/auth/staff";

        export async function POST(request: Request) {
          const staff = await getStaffUserAdminOrManager();

          if (!staff) {
            return Response.json({ error: "Unauthorized" }, { status: 401 });
          }

          const formData = await request.formData();
          return Response.json({ ok: true });
        }
      `
    );

    const issues = await scanApiIssues();
    const issue = issues.find((scanIssue) =>
      scanIssue.file === "app/api/upload/protected/route.ts"
    );

    assert.equal(issue, undefined);
  });

  it("does not warn when requireAdmin runs before sensitive work", async () => {
    await writeFixtureRoute(
      "app/api/upload/require-admin/route.ts",
      `
        export async function POST(request: Request) {
          await requireAdmin();
          const formData = await request.formData();
          return Response.json({ ok: true });
        }
      `
    );

    const issues = await scanApiIssues();
    const issue = issues.find((scanIssue) =>
      scanIssue.file === "app/api/upload/require-admin/route.ts"
    );

    assert.equal(issue, undefined);
  });

  it("still warns when internal route only reads an authorization token", async () => {
    await writeFixtureRoute(
      "app/api/internal/cleanup/token-only/route.ts",
      `
        export async function POST(request: Request) {
          const token = request.headers.get("authorization");
          await cleanupOldOrders();
          return Response.json({ ok: Boolean(token) });
        }
      `
    );

    const issues = await scanApiIssues();
    const issue = issues.find((scanIssue) =>
      scanIssue.file === "app/api/internal/cleanup/token-only/route.ts"
    );

    assert.equal(issue?.ruleId, "internal-route-missing-protection");
    assert.match(
      issue.evidence?.map((item) => item.label).join(" ") ?? "",
      /possible secret\/token signal detected/
    );
  });

  it("does not warn when internal route compares authorization token with CRON_SECRET", async () => {
    await writeFixtureRoute(
      "app/api/internal/cleanup/cron-secret/route.ts",
      `
        export async function POST(request: Request) {
          const token = request.headers.get("authorization");

          if (token !== process.env.CRON_SECRET) {
            return Response.json({ error: "Unauthorized" }, { status: 401 });
          }

          await cleanupOldOrders();
          return Response.json({ ok: true });
        }
      `
    );

    const issues = await scanApiIssues();
    const issue = issues.find((scanIssue) =>
      scanIssue.file === "app/api/internal/cleanup/cron-secret/route.ts"
    );

    assert.equal(issue, undefined);
  });

  it("still warns when internal route only checks token presence", async () => {
    await writeFixtureRoute(
      "app/api/internal/cleanup/token-presence/route.ts",
      `
        export async function POST(request: Request) {
          const token = request.headers.get("authorization");

          if (!token) {
            return Response.json({ error: "Unauthorized" }, { status: 401 });
          }

          await cleanupOldOrders();
          return Response.json({ ok: true });
        }
      `
    );

    const issues = await scanApiIssues();
    const issue = issues.find((scanIssue) =>
      scanIssue.file === "app/api/internal/cleanup/token-presence/route.ts"
    );

    assert.equal(issue?.ruleId, "internal-route-missing-protection");
  });

  it("does not warn when revalidate route checks query secret against REVALIDATE_SECRET", async () => {
    await writeFixtureRoute(
      "app/api/revalidate/route.ts",
      `
        export async function POST(request: Request) {
          if (request.nextUrl.searchParams.get("secret") !== process.env.REVALIDATE_SECRET) {
            return Response.json({ error: "Unauthorized" }, { status: 401 });
          }

          revalidatePath("/");
          return Response.json({ ok: true });
        }
      `
    );

    const issues = await scanApiIssues();
    const issue = issues.find((scanIssue) =>
      scanIssue.file === "app/api/revalidate/route.ts"
    );

    assert.equal(issue, undefined);
  });

  it("still warns when internal route only comments CRON_SECRET", async () => {
    await writeFixtureRoute(
      "app/api/internal/cleanup/comment-secret/route.ts",
      `
        export async function POST() {
          // CRON_SECRET is configured in production
          await cleanupOldOrders();
          return Response.json({ ok: true });
        }
      `
    );

    const issues = await scanApiIssues();
    const issue = issues.find((scanIssue) =>
      scanIssue.file === "app/api/internal/cleanup/comment-secret/route.ts"
    );

    assert.equal(issue?.ruleId, "internal-route-missing-protection");
    assert.match(
      issue.evidence?.map((item) => item.label).join(" ") ?? "",
      /possible secret\/token signal detected/
    );
  });

  it("does not warn on public blog GET routes", async () => {
    await writeFixtureRoute(
      "app/api/blog/[slug]/route.ts",
      `
        export async function GET() {
          const posts = await getPublishedPosts();
          return Response.json({ posts });
        }
      `
    );

    const issues = await scanApiIssues();
    const issue = issues.find((scanIssue) =>
      scanIssue.file === "app/api/blog/[slug]/route.ts" &&
      scanIssue.ruleId !== "api-public-read-route"
    );

    assert.equal(issue, undefined);
  });
});
