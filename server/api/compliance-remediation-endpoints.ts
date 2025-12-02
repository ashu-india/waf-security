import { Router } from "express";
import { ComplianceRemediationService } from "../services/compliance-remediation";

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

/**
 * POST /api/compliance-remediation/generate
 * Generate remediation actions for low compliance
 */
router.post("/generate", requireAuth, requireRole(["admin"]), async (req, res) => {
  try {
    const { tenantId, frameworkId, complianceScore } = req.body;

    if (!tenantId || !frameworkId || complianceScore === undefined) {
      return res.status(400).json({ success: false, error: "Missing required fields" });
    }

    const actions = await ComplianceRemediationService.generateRemediationActions(
      tenantId,
      frameworkId,
      complianceScore
    );

    res.json({ success: true, actions });
  } catch (error) {
    console.error("Error generating remediation actions:", error);
    res.status(500).json({ success: false, error: "Failed to generate remediation actions" });
  }
});

/**
 * POST /api/compliance-remediation/execute
 * Execute a remediation action
 */
router.post("/execute", requireAuth, requireRole(["admin"]), async (req, res) => {
  try {
    const action = req.body;

    const success = await ComplianceRemediationService.executeRemediationAction(action);

    if (success) {
      res.json({ success: true, action });
    } else {
      res.status(500).json({ success: false, error: "Remediation execution failed", action });
    }
  } catch (error) {
    console.error("Error executing remediation:", error);
    res.status(500).json({ success: false, error: "Failed to execute remediation action" });
  }
});

/**
 * GET /api/compliance-remediation/tenant/:tenantId/history
 * Get remediation history for tenant
 */
router.get("/tenant/:tenantId/history", requireAuth, requireRole(["admin", "operator"]), async (req, res) => {
  try {
    const { tenantId } = req.params;
    const history = await ComplianceRemediationService.getRemediationHistory(tenantId);
    res.json({ success: true, history });
  } catch (error) {
    console.error("Error fetching remediation history:", error);
    res.status(500).json({ success: false, error: "Failed to fetch remediation history" });
  }
});

/**
 * POST /api/compliance-remediation/schedule
 * Schedule automated remediation for tenant
 */
router.post("/schedule", requireAuth, requireRole(["admin"]), async (req, res) => {
  try {
    const { tenantId } = req.body;

    if (!tenantId) {
      return res.status(400).json({ success: false, error: "Tenant ID required" });
    }

    await ComplianceRemediationService.scheduleAutomatedRemediation(tenantId);
    res.json({ success: true, message: "Automated remediation scheduled" });
  } catch (error) {
    console.error("Error scheduling remediation:", error);
    res.status(500).json({ success: false, error: "Failed to schedule remediation" });
  }
});

export default router;
