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

  it("does not warn when a local helper validates Authorization against CRON_SECRET", async () => {
    await writeFixtureRoute(
      "app/api/internal/cleanup/local-helper-secret/route.ts",
      `
        function isAuthorized(request: Request) {
          const token = request.headers.get("authorization");
          return token === \`Bearer \${process.env.CRON_SECRET}\`;
        }

        export async function POST(request: Request) {
          if (!isAuthorized(request)) {
            return Response.json({ error: "Unauthorized" }, { status: 401 });
          }

          await cleanupOldOrders();
          return Response.json({ ok: true });
        }
      `
    );

    const issues = await scanApiIssues();
    const issue = issues.find((scanIssue) =>
      scanIssue.file === "app/api/internal/cleanup/local-helper-secret/route.ts"
    );

    assert.equal(issue, undefined);
  });

  it("still warns when a local helper only returns Boolean(token)", async () => {
    await writeFixtureRoute(
      "app/api/internal/cleanup/local-helper-boolean/route.ts",
      `
        function isAuthorized(request: Request) {
          const token = request.headers.get("authorization");
          return Boolean(token);
        }

        export async function POST(request: Request) {
          if (!isAuthorized(request)) {
            return Response.json({ error: "Unauthorized" }, { status: 401 });
          }

          await cleanupOldOrders();
          return Response.json({ ok: true });
        }
      `
    );

    const issues = await scanApiIssues();
    const issue = issues.find((scanIssue) =>
      scanIssue.file === "app/api/internal/cleanup/local-helper-boolean/route.ts"
    );

    assert.equal(issue?.ruleId, "internal-route-missing-protection");
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

  it("does not warn when revalidate route checks body secret before side effects", async () => {
    await writeFixtureRoute(
      "app/api/revalidate/body-secret/route.ts",
      `
        export async function POST(request: Request) {
          const body = await request.json();
          const { secret, slug } = body;

          if (secret !== process.env.REVALIDATE_SECRET) {
            return Response.json({ message: "Invalid token" }, { status: 401 });
          }

          revalidateTag("blog-posts");
          revalidatePath(slug ?? "/blog");
          return Response.json({ revalidated: true });
        }
      `
    );

    const issues = await scanApiIssues();
    const issue = issues.find((scanIssue) =>
      scanIssue.file === "app/api/revalidate/body-secret/route.ts"
    );

    assert.equal(issue, undefined);
  });

  it("warns when revalidate route parses input but has no secret guard before side effects", async () => {
    await writeFixtureRoute(
      "app/api/revalidate/unprotected-body/route.ts",
      `
        export async function POST(request: Request) {
          const body = await request.json();
          revalidatePath(body.slug ?? "/");
          return Response.json({ revalidated: true });
        }
      `
    );

    const issues = await scanApiIssues();
    const issue = issues.find((scanIssue) =>
      scanIssue.file === "app/api/revalidate/unprotected-body/route.ts"
    );

    assert.equal(issue?.ruleId, "internal-route-missing-protection");
    assert.match(
      issue.evidence?.map((item) => item.label).join(" ") ?? "",
      /input parsing request\.json detected/
    );
    assert.match(
      issue.evidence?.map((item) => item.label).join(" ") ?? "",
      /sensitive side effect revalidatePath detected/
    );
  });

  it("does not warn when GET revalidate route checks query secret before side effects", async () => {
    await writeFixtureRoute(
      "app/api/revalidate/query-secret/route.ts",
      `
        export async function GET(request: Request) {
          const secret = request.nextUrl.searchParams.get("secret");

          if (secret !== process.env.REVALIDATE_SECRET) {
            return Response.json({ message: "Invalid token" }, { status: 401 });
          }

          revalidatePath("/");
          return Response.json({ revalidated: true });
        }
      `
    );

    const issues = await scanApiIssues();
    const issue = issues.find((scanIssue) =>
      scanIssue.file === "app/api/revalidate/query-secret/route.ts"
    );

    assert.equal(issue, undefined);
  });

  it("warns when GET revalidate route has side effects without a secret guard", async () => {
    await writeFixtureRoute(
      "app/api/revalidate/unprotected-query/route.ts",
      `
        export async function GET() {
          revalidatePath("/");
          return Response.json({ revalidated: true });
        }
      `
    );

    const issues = await scanApiIssues();
    const issue = issues.find((scanIssue) =>
      scanIssue.file === "app/api/revalidate/unprotected-query/route.ts"
    );

    assert.equal(issue?.ruleId, "internal-route-missing-protection");
  });

  it("warns when admin debug route has auth but no authorization check", async () => {
    await writeFixtureRoute(
      "app/api/admin/debug/route.ts",
      `
        export async function POST() {
          const { userId } = await auth();

          if (!userId) {
            return Response.json({ error: "Unauthorized" }, { status: 401 });
          }

          await runDebugJob();
          return Response.json({ ok: true });
        }
      `
    );

    const issues = await scanApiIssues();
    const issue = issues.find((scanIssue) =>
      scanIssue.file === "app/api/admin/debug/route.ts" &&
      scanIssue.ruleId === "admin-route-missing-authorization"
    );

    assert.equal(issue?.ruleId, "admin-route-missing-authorization");
    assert.match(
      issue.evidence?.map((item) => item.label).join(" ") ?? "",
      /no admin\/staff\/role\/permission check detected/
    );
  });

  it("does not warn when admin debug route has auth and role check", async () => {
    await writeFixtureRoute(
      "app/api/admin/debug/with-role/route.ts",
      `
        export async function POST() {
          const { userId } = await auth();

          if (!userId) {
            return Response.json({ error: "Unauthorized" }, { status: 401 });
          }

          const user = await getUser(userId);

          if (user.role !== "ADMIN") {
            return Response.json({ error: "Forbidden" }, { status: 403 });
          }

          await runDebugJob();
          return Response.json({ ok: true });
        }
      `
    );

    const issues = await scanApiIssues();
    const issue = issues.find((scanIssue) =>
      scanIssue.file === "app/api/admin/debug/with-role/route.ts"
    );

    assert.equal(issue, undefined);
  });

  it("does not warn when destructured session user is guarded with 401", async () => {
    await writeFixtureRoute(
      "app/api/upload/destructured-session/route.ts",
      `
        export async function POST(request: Request) {
          const { user } = await getSession();

          if (!user) {
            return Response.json({ error: "Unauthorized" }, { status: 401 });
          }

          const formData = await request.formData();
          return Response.json({ ok: true });
        }
      `
    );

    const issues = await scanApiIssues();
    const issue = issues.find((scanIssue) =>
      scanIssue.file === "app/api/upload/destructured-session/route.ts"
    );

    assert.equal(issue, undefined);
  });

  it("does not treat rate-limit header helpers before auth as sensitive side effects", async () => {
    await writeFixtureRoute(
      "app/api/account/addresses/[id]/route.ts",
      `
        export async function PATCH(request: Request) {
          const rateLimitResult = rateLimit(request);

          if (!rateLimitResult.success) {
            const headers = createRateLimitHeaders(rateLimitResult);
            return Response.json({ error: "Too many requests" }, { status: 429, headers });
          }

          const { userId } = await auth();

          if (!userId) {
            return Response.json({ error: "Unauthorized" }, { status: 401 });
          }

          const body = await request.json();
          await updateAddress(userId, body);
          const headers = createRateLimitHeaders(rateLimitResult);
          return Response.json({ ok: true }, { headers });
        }

        export async function DELETE(request: Request) {
          const rateLimitResult = rateLimit(request);

          if (!rateLimitResult.success) {
            const headers = createRateLimitHeaders(rateLimitResult);
            return Response.json({ error: "Too many requests" }, { status: 429, headers });
          }

          const { userId } = await auth();

          if (!userId) {
            return Response.json({ error: "Unauthorized" }, { status: 401 });
          }

          await deleteAddress(userId);
          return new Response(null, { status: 204 });
        }
      `
    );

    const issues = await scanApiIssues();
    const issue = issues.find((scanIssue) =>
      scanIssue.file === "app/api/account/addresses/[id]/route.ts"
    );

    assert.equal(issue, undefined);
  });

  it("does not warn when admin POST handler only returns 405", async () => {
    await writeFixtureRoute(
      "app/api/admin/categories/post-blocked/route.ts",
      `
        export async function POST() {
          return Response.json({ error: "Method not allowed" }, { status: 405 });
        }
      `
    );

    const issues = await scanApiIssues();
    const issue = issues.find((scanIssue) =>
      scanIssue.file === "app/api/admin/categories/post-blocked/route.ts"
    );

    assert.equal(issue, undefined);
  });

  it("does not warn when admin PUT handler only returns 405", async () => {
    await writeFixtureRoute(
      "app/api/admin/categories/put-blocked/route.ts",
      `
        export async function PUT() {
          return Response.json({ error: "Method not allowed" }, { status: 405 });
        }
      `
    );

    const issues = await scanApiIssues();
    const issue = issues.find((scanIssue) =>
      scanIssue.file === "app/api/admin/categories/put-blocked/route.ts"
    );

    assert.equal(issue, undefined);
  });

  it("does not warn when admin DELETE handler only returns 405", async () => {
    await writeFixtureRoute(
      "app/api/admin/categories/delete-blocked/route.ts",
      `
        export async function DELETE() {
          return Response.json({ error: "Method not allowed" }, { status: 405 });
        }
      `
    );

    const issues = await scanApiIssues();
    const issue = issues.find((scanIssue) =>
      scanIssue.file === "app/api/admin/categories/delete-blocked/route.ts"
    );

    assert.equal(issue, undefined);
  });

  it("does not warn for blocked POST when another admin handler is protected", async () => {
    await writeFixtureRoute(
      "app/api/admin/categories/get-protected-post-blocked/route.ts",
      `
        export async function GET() {
          await requireAdmin();
          return Response.json({ ok: true });
        }

        export async function POST() {
          return Response.json({ error: "Method not allowed" }, { status: 405 });
        }
      `
    );

    const issues = await scanApiIssues();
    const issue = issues.find((scanIssue) =>
      scanIssue.file === "app/api/admin/categories/get-protected-post-blocked/route.ts"
    );

    assert.equal(issue, undefined);
  });

  it("still warns when admin POST handler performs mutation without protection", async () => {
    await writeFixtureRoute(
      "app/api/admin/categories/create/route.ts",
      `
        export async function POST(request: Request) {
          const body = await request.json();
          await db.category.create({ data: body });
          return Response.json({ ok: true });
        }
      `
    );

    const issues = await scanApiIssues();
    const issue = issues.find((scanIssue) =>
      scanIssue.file === "app/api/admin/categories/create/route.ts"
    );

    assert.equal(issue?.ruleId, "internal-route-missing-protection");
  });

  it("does not warn when sensitive account PATCH handler only returns 405", async () => {
    await writeFixtureRoute(
      "app/api/account/patch-blocked/route.ts",
      `
        export async function PATCH() {
          return Response.json({ error: "Method not allowed" }, { status: 405 });
        }
      `
    );

    const issues = await scanApiIssues();
    const issue = issues.find((scanIssue) =>
      scanIssue.file === "app/api/account/patch-blocked/route.ts"
    );

    assert.equal(issue, undefined);
  });

  it("warns when upload route has no auth before storage side effect", async () => {
    await writeFixtureRoute(
      "app/api/upload/unprotected-storage/route.ts",
      `
        export async function POST(request: Request) {
          const formData = await request.formData();
          const file = formData.get("file");
          await uploadToR2(file);
          return Response.json({ ok: true });
        }
      `
    );

    const issues = await scanApiIssues();
    const issue = issues.find((scanIssue) =>
      scanIssue.file === "app/api/upload/unprotected-storage/route.ts"
    );

    assert.equal(issue?.ruleId, "sensitive-api-route-missing-auth");
    assert.match(
      issue.evidence?.map((item) => item.label).join(" ") ?? "",
      /sensitive side effect uploadToR2 detected/
    );
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

  it("creates a review warning for unknown POST mutation without auth", async () => {
    await writeFixtureRoute(
      "app/api/tasks/route.ts",
      `
        export async function POST(request: Request) {
          const payload = await request.json();
          return Response.json({ ok: true, payload });
        }
      `
    );

    const issues = await scanApiIssues();
    const issue = issues.find((scanIssue) =>
      scanIssue.file === "app/api/tasks/route.ts"
    );

    assert.equal(issue?.ruleId, "api-mutation-route-review-auth");
    assert.equal(issue?.confidence, "medium");
  });

  it("detects basic public form validation without saying validation is missing", async () => {
    await writeFixtureRoute(
      "app/api/subscribe/basic-validation/route.ts",
      `
        export async function POST(req: Request) {
          const { email } = await req.json();

          if (!email || typeof email !== "string") {
            return Response.json({ error: "Email is required" }, { status: 400 });
          }

          return Response.json({ ok: true });
        }
      `
    );

    const issues = await scanApiIssues();
    const issue = issues.find((scanIssue) =>
      scanIssue.file === "app/api/subscribe/basic-validation/route.ts"
    );
    const evidenceLabels = issue?.evidence?.map((item) => item.label).join(" ") ?? "";

    assert.equal(issue?.ruleId, "public-form-missing-abuse-protection");
    assert.match(evidenceLabels, /public submission endpoint detected/);
    assert.match(evidenceLabels, /basic validation detected/);
    assert.match(evidenceLabels, /no rate limit detected/);
    assert.doesNotMatch(evidenceLabels, /no validation detected/);
    assert.doesNotMatch(evidenceLabels, /no access-control guard detected/);
  });

  it("detects schema validation on public form routes", async () => {
    await writeFixtureRoute(
      "app/api/subscribe/schema-validation/route.ts",
      `
        const SubscribeSchema = {
          safeParse(value: unknown) {
            return { success: Boolean(value), data: value };
          }
        };

        export async function POST(req: Request) {
          const body = await req.json();
          const parsed = SubscribeSchema.safeParse(body);

          if (!parsed.success) {
            return Response.json({ error: "Invalid email" }, { status: 400 });
          }

          return Response.json({ ok: true });
        }
      `
    );

    const issues = await scanApiIssues();
    const issue = issues.find((scanIssue) =>
      scanIssue.file === "app/api/subscribe/schema-validation/route.ts"
    );
    const evidenceLabels = issue?.evidence?.map((item) => item.label).join(" ") ?? "";

    assert.equal(issue?.ruleId, "public-form-missing-abuse-protection");
    assert.match(evidenceLabels, /schema validation detected/);
  });

  it("does not warn when public form route has basic validation and rate limiting", async () => {
    await writeFixtureRoute(
      "app/api/subscribe/rate-limited-validation/route.ts",
      `
        export async function POST(req: Request) {
          const rateLimitResult = rateLimit(req);

          if (!rateLimitResult.success) {
            return Response.json({ error: "Too many requests" }, { status: 429 });
          }

          const { email } = await req.json();

          if (!email || typeof email !== "string") {
            return Response.json({ error: "Email is required" }, { status: 400 });
          }

          return Response.json({ ok: true });
        }
      `
    );

    const issues = await scanApiIssues();
    const issue = issues.find((scanIssue) =>
      scanIssue.file === "app/api/subscribe/rate-limited-validation/route.ts"
    );

    assert.equal(issue, undefined);
  });

  it("warns when public contact route has no validation and no rate limiting", async () => {
    await writeFixtureRoute(
      "app/api/contact/no-protection/route.ts",
      `
        export async function POST(req: Request) {
          const body = await req.json();
          await sendContactEmail(body);
          return Response.json({ ok: true });
        }
      `
    );

    const issues = await scanApiIssues();
    const issue = issues.find((scanIssue) =>
      scanIssue.file === "app/api/contact/no-protection/route.ts"
    );
    const evidenceLabels = issue?.evidence?.map((item) => item.label).join(" ") ?? "";

    assert.equal(issue?.ruleId, "public-form-missing-abuse-protection");
    assert.match(evidenceLabels, /public submission endpoint detected/);
    assert.match(evidenceLabels, /no validation detected/);
    assert.match(evidenceLabels, /no rate limit detected/);
    assert.match(evidenceLabels, /email\/send side effect detected/);
    assert.doesNotMatch(evidenceLabels, /no access-control guard detected/);
  });

  it("ignores commented-out exported handlers", async () => {
    await writeFixtureRoute(
      "app/api/subscribe/commented-export/route.ts",
      `
        // export async function POST(req: Request) {
        //   return Response.json({ ok: true });
        // }

        export async function POST(req: Request) {
          const { email } = await req.json();

          if (!email || typeof email !== "string") {
            return Response.json({ error: "Email is required" }, { status: 400 });
          }

          return Response.json({ ok: true });
        }
      `
    );

    const issues = await scanApiIssues();
    const matchingIssues = issues.filter((scanIssue) =>
      scanIssue.file === "app/api/subscribe/commented-export/route.ts"
    );

    assert.equal(matchingIssues.length, 1);
    assert.equal(matchingIssues[0]?.ruleId, "public-form-missing-abuse-protection");
  });
});
