import { Router, type Request, type Response } from "express";
import { createHmac, timingSafeEqual } from "node:crypto";
import { and, eq } from "drizzle-orm";
import type { Db } from "@paperclipai/db";
import { issues } from "@paperclipai/db";
import { issueService, logActivity } from "../services/index.js";

const SENTRY_REPLAY_WINDOW_MS = 5 * 60 * 1000;
const SENTRY_ORIGIN_KIND = "sentry_webhook";

interface SentryEnv {
  secret: string;
  companyId: string;
  goalId: string | null;
  assigneeAgentId: string | null;
}

function readSentryEnv(): SentryEnv | null {
  const secret = process.env.SENTRY_WEBHOOK_SECRET?.trim();
  const companyId = process.env.SENTRY_WEBHOOK_COMPANY_ID?.trim();
  if (!secret || !companyId) return null;
  return {
    secret,
    companyId,
    goalId: process.env.SENTRY_WEBHOOK_GOAL_ID?.trim() || null,
    assigneeAgentId: process.env.SENTRY_WEBHOOK_ASSIGNEE_AGENT_ID?.trim() || null,
  };
}

function constantTimeEqual(a: string, b: string): boolean {
  const ab = Buffer.from(a);
  const bb = Buffer.from(b);
  if (ab.length !== bb.length) return false;
  try {
    return timingSafeEqual(ab, bb);
  } catch {
    return false;
  }
}

function verifySentrySignature(rawBody: Buffer, signatureHeader: unknown, secret: string): boolean {
  if (typeof signatureHeader !== "string" || signatureHeader.length === 0) return false;
  const expected = createHmac("sha256", secret).update(rawBody).digest("hex");
  return constantTimeEqual(signatureHeader, expected);
}

function parseTimestamp(headerValue: unknown): number | null {
  if (typeof headerValue !== "string") return null;
  const ms = Number(headerValue);
  if (!Number.isFinite(ms)) return null;
  return ms < 1e12 ? ms * 1000 : ms;
}

function isWithinReplayWindow(timestampMs: number | null, nowMs: number): boolean {
  if (timestampMs === null) return true;
  return Math.abs(nowMs - timestampMs) <= SENTRY_REPLAY_WINDOW_MS;
}

function priorityFromSentryLevel(level: unknown): string {
  if (typeof level !== "string") return "medium";
  const normalized = level.toLowerCase();
  if (normalized === "fatal" || normalized === "error") return "high";
  if (normalized === "warning") return "medium";
  return "low";
}

function redactedPayloadSummary(payload: Record<string, unknown>): Record<string, unknown> {
  const data = (payload.data as Record<string, unknown> | undefined) ?? {};
  const issueData = (data.issue as Record<string, unknown> | undefined) ?? {};
  const eventData = (data.event as Record<string, unknown> | undefined) ?? {};
  return {
    action: payload.action,
    project: payload.project,
    sentryIssueId: issueData.id ?? eventData.issue_id ?? null,
    sentryEventId: eventData.event_id ?? null,
    title: issueData.title ?? eventData.title ?? null,
    level: issueData.level ?? eventData.level ?? null,
    count: issueData.count ?? null,
  };
}

export function webhookRoutes(db: Db) {
  const router = Router();
  const issueSvc = issueService(db);

  router.post("/webhooks/sentry", async (req: Request, res: Response) => {
    const env = readSentryEnv();
    if (!env) {
      res.status(503).json({
        error: "sentry_webhook_not_configured",
        message: "SENTRY_WEBHOOK_SECRET and SENTRY_WEBHOOK_COMPANY_ID env vars are not set on the server.",
      });
      return;
    }

    const rawBody = (req as unknown as { rawBody?: Buffer }).rawBody;
    if (!rawBody || rawBody.length === 0) {
      res.status(400).json({ error: "empty_body" });
      return;
    }

    const signatureHeader = req.header("sentry-hook-signature");
    if (!verifySentrySignature(rawBody, signatureHeader, env.secret)) {
      res.status(401).json({ error: "invalid_signature" });
      return;
    }

    const timestampMs = parseTimestamp(req.header("sentry-hook-timestamp"));
    if (!isWithinReplayWindow(timestampMs, Date.now())) {
      res.status(401).json({ error: "stale_signature" });
      return;
    }

    const payload = req.body as Record<string, unknown>;
    const data = (payload?.data as Record<string, unknown> | undefined) ?? {};
    const sentryIssue = (data.issue as Record<string, unknown> | undefined) ?? {};
    const sentryEvent = (data.event as Record<string, unknown> | undefined) ?? {};

    const sentryEventId =
      (typeof sentryEvent.event_id === "string" && sentryEvent.event_id) ||
      (typeof sentryIssue.id === "string" && `issue:${sentryIssue.id}`) ||
      null;

    if (!sentryEventId) {
      res.status(400).json({ error: "missing_event_identity" });
      return;
    }

    const existing = await db
      .select({ id: issues.id, identifier: issues.identifier })
      .from(issues)
      .where(
        and(
          eq(issues.companyId, env.companyId),
          eq(issues.originKind, SENTRY_ORIGIN_KIND),
          eq(issues.originId, sentryEventId),
        ),
      )
      .limit(1)
      .then((rows) => rows[0] ?? null);

    if (existing) {
      res.status(200).json({
        ok: true,
        deduplicated: true,
        issueId: existing.id,
        identifier: existing.identifier,
      });
      return;
    }

    const sentryTitle =
      (typeof sentryIssue.title === "string" && sentryIssue.title) ||
      (typeof sentryEvent.title === "string" && sentryEvent.title) ||
      "Sentry incident";
    const sentryLevel = sentryIssue.level ?? sentryEvent.level;
    const sentryUrl =
      (typeof sentryIssue.web_url === "string" && sentryIssue.web_url) ||
      (typeof sentryIssue.permalink === "string" && sentryIssue.permalink) ||
      (typeof payload.project_url === "string" && (payload.project_url as string)) ||
      null;
    const projectName =
      typeof payload.project === "string" ? (payload.project as string) :
      typeof payload.project_name === "string" ? (payload.project_name as string) : null;

    const description = [
      `**Source:** Sentry${projectName ? ` (project: ${projectName})` : ""}`,
      sentryUrl ? `**Sentry URL:** ${sentryUrl}` : null,
      `**Level:** ${sentryLevel ?? "unknown"}`,
      `**Sentry event id:** \`${sentryEventId}\``,
      `**Hook action:** ${payload.action ?? "unknown"}`,
    ]
      .filter(Boolean)
      .join("\n");

    const created = await issueSvc.create(env.companyId, {
      title: `[Sentry] ${String(sentryTitle).slice(0, 200)}`,
      description,
      status: "todo",
      priority: priorityFromSentryLevel(sentryLevel),
      goalId: env.goalId ?? undefined,
      assigneeAgentId: env.assigneeAgentId ?? undefined,
      originKind: SENTRY_ORIGIN_KIND,
      originId: sentryEventId,
    });

    await logActivity(db, {
      companyId: env.companyId,
      actorType: "system",
      actorId: "sentry-webhook",
      action: "issue.created",
      entityType: "issue",
      entityId: created.id,
      details: redactedPayloadSummary(payload),
    });

    res.status(201).json({
      ok: true,
      deduplicated: false,
      issueId: created.id,
      identifier: created.identifier,
    });
  });

  return router;
}
