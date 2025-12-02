import { Router } from "express";
import { ComplianceWebhookService } from "../services/compliance-webhooks";
import { z } from "zod";

const router = Router();

function requireAuth(req: any, res: any, next: any) {
  if (!req.isAuthenticated || !req.isAuthenticated()) {
    return res.status(401).json({ message: "Unauthorized" });
  }
  res.set("Cache-Control", "no-cache, no-store, must-revalidate, private");
  next();
}

function requireRole(allowedRoles: string[]) {
  return (req: any, res: any, next: any) => {
    if (!req.user || !allowedRoles.includes(req.user.role)) {
      return res.status(403).json({ message: "Insufficient permissions" });
    }
    next();
  };
}

const webhookSchema = z.object({
  url: z.string().url(),
  events: z.array(z.enum(["compliance_alert", "remediation_action", "audit_log"])).min(1),
  isActive: z.boolean().default(true),
  secret: z.string().optional(),
  retries: z.number().int().min(0).max(5).default(3),
});

/**
 * POST /api/compliance-webhooks/register
 * Register a new webhook
 */
router.post("/register", requireAuth, requireRole(["admin"]), async (req, res) => {
  try {
    const validation = webhookSchema.safeParse(req.body);
    if (!validation.success) {
      return res.status(400).json({ success: false, errors: validation.error.errors });
    }

    const webhook = ComplianceWebhookService.registerWebhook({
      tenantId: req.body.tenantId,
      ...validation.data,
    });

    res.json({ success: true, webhook });
  } catch (error) {
    console.error("Error registering webhook:", error);
    res.status(500).json({ success: false, error: "Failed to register webhook" });
  }
});

/**
 * GET /api/compliance-webhooks/tenant/:tenantId
 * Get all webhooks for tenant
 */
router.get("/tenant/:tenantId", requireAuth, requireRole(["admin", "operator"]), (req, res) => {
  try {
    const { tenantId } = req.params;
    const webhooks = ComplianceWebhookService.getWebhooks(tenantId);
    res.json({ success: true, webhooks });
  } catch (error) {
    console.error("Error fetching webhooks:", error);
    res.status(500).json({ success: false, error: "Failed to fetch webhooks" });
  }
});

/**
 * PUT /api/compliance-webhooks/:webhookId
 * Update webhook configuration
 */
router.put("/:webhookId", requireAuth, requireRole(["admin"]), async (req, res) => {
  try {
    const { webhookId } = req.params;

    const webhook = ComplianceWebhookService.updateWebhook(webhookId, req.body);
    if (!webhook) {
      return res.status(404).json({ success: false, error: "Webhook not found" });
    }

    res.json({ success: true, webhook });
  } catch (error) {
    console.error("Error updating webhook:", error);
    res.status(500).json({ success: false, error: "Failed to update webhook" });
  }
});

/**
 * DELETE /api/compliance-webhooks/:webhookId
 * Delete webhook
 */
router.delete("/:webhookId", requireAuth, requireRole(["admin"]), (req, res) => {
  try {
    const { webhookId } = req.params;

    const success = ComplianceWebhookService.deleteWebhook(webhookId);
    if (!success) {
      return res.status(404).json({ success: false, error: "Webhook not found" });
    }

    res.json({ success: true });
  } catch (error) {
    console.error("Error deleting webhook:", error);
    res.status(500).json({ success: false, error: "Failed to delete webhook" });
  }
});

/**
 * POST /api/compliance-webhooks/:webhookId/test
 * Test webhook delivery
 */
router.post("/:webhookId/test", requireAuth, requireRole(["admin"]), async (req, res) => {
  try {
    const { webhookId } = req.params;
    const webhooks = Array.from(new Map(Object.entries({}))); // Get all webhooks
    
    // Find webhook by ID (simplified)
    const allWebhooks = ComplianceWebhookService.getWebhooks(req.body.tenantId);
    const webhook = allWebhooks.find((w) => w.id === webhookId);

    if (!webhook) {
      return res.status(404).json({ success: false, error: "Webhook not found" });
    }

    const testSuccess = await ComplianceWebhookService.testWebhook(webhook);
    res.json({ success: true, testPassed: testSuccess });
  } catch (error) {
    console.error("Error testing webhook:", error);
    res.status(500).json({ success: false, error: "Failed to test webhook" });
  }
});

/**
 * GET /api/compliance-webhooks/:webhookId/history
 * Get webhook delivery history
 */
router.get("/:webhookId/history", requireAuth, requireRole(["admin", "operator"]), (req, res) => {
  try {
    const { webhookId } = req.params;
    const history = ComplianceWebhookService.getWebhookHistory(webhookId);
    res.json({ success: true, history });
  } catch (error) {
    console.error("Error fetching webhook history:", error);
    res.status(500).json({ success: false, error: "Failed to fetch webhook history" });
  }
});

export default router;
