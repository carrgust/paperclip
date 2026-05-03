import { Router } from "express";
import { and, eq, sql } from "drizzle-orm";
import type { Db } from "@paperclipai/db";
import { issues } from "@paperclipai/db";
import { createGoalSchema, updateGoalSchema } from "@paperclipai/shared";
import { trackGoalCreated } from "@paperclipai/shared/telemetry";
import { validate } from "../middleware/validate.js";
import { goalService, logActivity } from "../services/index.js";
import { assertCompanyAccess, getActorInfo } from "./authz.js";
import { getTelemetryClient } from "../telemetry.js";

const TERMINAL_GOAL_STATUSES = ["achieved", "cancelled"] as const;
type TerminalGoalStatus = (typeof TERMINAL_GOAL_STATUSES)[number];

function isTerminalGoalStatus(value: unknown): value is TerminalGoalStatus {
  return typeof value === "string" && (TERMINAL_GOAL_STATUSES as readonly string[]).includes(value);
}

export function goalRoutes(db: Db) {
  const router = Router();
  const svc = goalService(db);

  router.get("/companies/:companyId/goals", async (req, res) => {
    const companyId = req.params.companyId as string;
    assertCompanyAccess(req, companyId);
    const result = await svc.list(companyId);
    res.json(result);
  });

  router.get("/goals/:id", async (req, res) => {
    const id = req.params.id as string;
    const goal = await svc.getById(id);
    if (!goal) {
      res.status(404).json({ error: "Goal not found" });
      return;
    }
    assertCompanyAccess(req, goal.companyId);
    res.json(goal);
  });

  router.post("/companies/:companyId/goals", validate(createGoalSchema), async (req, res) => {
    const companyId = req.params.companyId as string;
    assertCompanyAccess(req, companyId);
    const goal = await svc.create(companyId, req.body);
    const actor = getActorInfo(req);
    await logActivity(db, {
      companyId,
      actorType: actor.actorType,
      actorId: actor.actorId,
      agentId: actor.agentId,
      action: "goal.created",
      entityType: "goal",
      entityId: goal.id,
      details: { title: goal.title },
    });
    const telemetryClient = getTelemetryClient();
    if (telemetryClient) {
      trackGoalCreated(telemetryClient, { goalLevel: goal.level });
    }
    res.status(201).json(goal);
  });

  router.patch("/goals/:id", validate(updateGoalSchema), async (req, res) => {
    const id = req.params.id as string;
    const existing = await svc.getById(id);
    if (!existing) {
      res.status(404).json({ error: "Goal not found" });
      return;
    }
    assertCompanyAccess(req, existing.companyId);

    // Wave 1.2 — invariant: block transitions to achieved/archived while
    // active issues remain linked. Prevents the "achieved goal carries live work"
    // anti-pattern that pollutes inboxes and dashboards.
    const requestedStatus = (req.body as { status?: unknown }).status;
    if (
      isTerminalGoalStatus(requestedStatus) &&
      existing.status !== requestedStatus
    ) {
      const blockers = await db
        .select({
          id: issues.id,
          identifier: issues.identifier,
          status: issues.status,
          title: issues.title,
        })
        .from(issues)
        .where(
          and(
            eq(issues.goalId, id),
            sql`${issues.status} NOT IN ('done', 'cancelled')`,
          ),
        )
        .limit(50);
      if (blockers.length > 0) {
        res.status(422).json({
          error: "goal_invariant_violation",
          code: "active_issues_block_terminal_transition",
          message: `Cannot transition goal to '${requestedStatus}' while ${blockers.length} active issue(s) remain linked. Move or close them first.`,
          requestedStatus,
          activeIssueCount: blockers.length,
          blockers,
        });
        return;
      }
    }

    const goal = await svc.update(id, req.body);
    if (!goal) {
      res.status(404).json({ error: "Goal not found" });
      return;
    }

    const actor = getActorInfo(req);
    await logActivity(db, {
      companyId: goal.companyId,
      actorType: actor.actorType,
      actorId: actor.actorId,
      agentId: actor.agentId,
      action: "goal.updated",
      entityType: "goal",
      entityId: goal.id,
      details: req.body,
    });

    res.json(goal);
  });

  router.delete("/goals/:id", async (req, res) => {
    const id = req.params.id as string;
    const existing = await svc.getById(id);
    if (!existing) {
      res.status(404).json({ error: "Goal not found" });
      return;
    }
    assertCompanyAccess(req, existing.companyId);
    const goal = await svc.remove(id);
    if (!goal) {
      res.status(404).json({ error: "Goal not found" });
      return;
    }

    const actor = getActorInfo(req);
    await logActivity(db, {
      companyId: goal.companyId,
      actorType: actor.actorType,
      actorId: actor.actorId,
      agentId: actor.agentId,
      action: "goal.deleted",
      entityType: "goal",
      entityId: goal.id,
    });

    res.json(goal);
  });

  return router;
}
