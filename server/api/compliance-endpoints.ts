import { Router } from "express";
import { ComplianceVerificationService } from "../services/compliance-verification";

const router = Router();

// Middleware for auth validation
function requireAuth(req: any, res: any, next: any) {
  if (!req.isAuthenticated || !req.isAuthenticated()) {
    return res.status(401).json({ message: "Unauthorized" });
  }
  res.set("Cache-Control", "no-cache, no-store, must-revalidate, private");
  res.set("Pragma", "no-cache");
  res.set("Expires", "0");
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
 * GET /api/compliance/frameworks
 * Get all compliance frameworks with rule counts
 */
router.get("/frameworks", requireAuth, requireRole(["admin", "operator"]), async (req, res) => {
  try {
    const frameworks = await ComplianceVerificationService.getAllFrameworks();
    res.json({ success: true, frameworks });
  } catch (error) {
    console.error("Error fetching frameworks:", error);
    res.status(500).json({ success: false, error: "Failed to fetch frameworks" });
  }
});

/**
 * GET /api/compliance/framework/:frameworkId/rules
 * Get compliance rules for a specific framework
 */
router.get("/framework/:frameworkId/rules", requireAuth, requireRole(["admin", "operator"]), async (req, res) => {
  try {
    const { frameworkId } = req.params;
    const rules = await ComplianceVerificationService.getFrameworkRules(frameworkId);
    res.json({ success: true, ...rules });
  } catch (error) {
    console.error("Error fetching framework rules:", error);
    res.status(500).json({ success: false, error: "Failed to fetch framework rules" });
  }
});

/**
 * POST /api/compliance/verify-rule
 * Verify a specific compliance rule status for a tenant
 */
router.post("/verify-rule", requireAuth, requireRole(["admin", "operator"]), async (req, res) => {
  try {
    const { tenantId, ruleId } = req.body;
    
    if (!tenantId || !ruleId) {
      return res.status(400).json({ success: false, error: "Missing tenantId or ruleId" });
    }

    const status = await ComplianceVerificationService.verifyComplianceRule(tenantId, ruleId);
    res.json({ success: true, status });
  } catch (error) {
    console.error("Error verifying compliance rule:", error);
    res.status(500).json({ success: false, error: "Failed to verify compliance rule" });
  }
});

/**
 * GET /api/compliance/tenant/:tenantId/framework/:frameworkId
 * Get compliance status for a framework within a tenant
 */
router.get("/tenant/:tenantId/framework/:frameworkId", requireAuth, requireRole(["admin", "operator"]), async (req, res) => {
  try {
    const { tenantId, frameworkId } = req.params;
    const status = await ComplianceVerificationService.getFrameworkComplianceStatus(tenantId, frameworkId);
    res.json({ success: true, status });
  } catch (error) {
    console.error("Error fetching framework compliance status:", error);
    res.status(500).json({ success: false, error: "Failed to fetch compliance status" });
  }
});

/**
 * GET /api/compliance/tenant/:tenantId/status
 * Get overall compliance status for a tenant across all frameworks
 */
router.get("/tenant/:tenantId/status", requireAuth, requireRole(["admin", "operator"]), async (req, res) => {
  try {
    const { tenantId } = req.params;
    const status = await ComplianceVerificationService.getTenantComplianceStatus(tenantId);
    res.json({ success: true, status });
  } catch (error) {
    console.error("Error fetching tenant compliance status:", error);
    res.status(500).json({ success: false, error: "Failed to fetch tenant compliance status" });
  }
});

/**
 * POST /api/compliance/audit-log
 * Log a compliance audit event
 */
router.post("/audit-log", requireAuth, requireRole(["admin"]), async (req, res) => {
  try {
    const { tenantId, frameworkId, action, details } = req.body;
    const userId = (req.user as any).id;

    if (!tenantId || !frameworkId || !action) {
      return res.status(400).json({ 
        success: false, 
        error: "Missing required fields: tenantId, frameworkId, action" 
      });
    }

    await ComplianceVerificationService.logComplianceAudit(
      tenantId,
      frameworkId,
      userId,
      action,
      details || ""
    );

    res.json({ success: true, message: "Audit logged" });
  } catch (error) {
    console.error("Error logging compliance audit:", error);
    res.status(500).json({ success: false, error: "Failed to log audit" });
  }
});

/**
 * GET /api/compliance/tenant/:tenantId/audit-trail
 * Get compliance audit trail for a tenant
 */
router.get("/tenant/:tenantId/audit-trail", requireAuth, requireRole(["admin", "operator"]), async (req, res) => {
  try {
    const { tenantId } = req.params;
    const limit = parseInt((req.query.limit as string) || "100");
    
    const audits = await ComplianceVerificationService.getComplianceAuditTrail(tenantId, limit);
    res.json({ success: true, audits });
  } catch (error) {
    console.error("Error fetching compliance audit trail:", error);
    res.status(500).json({ success: false, error: "Failed to fetch audit trail" });
  }
});

/**
 * GET /api/compliance/tenant/:tenantId/framework/:frameworkId/trends
 * Get compliance score trends for a framework
 */
router.get("/tenant/:tenantId/framework/:frameworkId/trends", requireAuth, requireRole(["admin", "operator"]), async (req, res) => {
  try {
    const { tenantId, frameworkId } = req.params;
    const days = parseInt((req.query.days as string) || "30");
    
    const trends = await ComplianceVerificationService.getComplianceTrends(tenantId, frameworkId, days);
    res.json({ success: true, trends });
  } catch (error) {
    console.error("Error fetching compliance trends:", error);
    res.status(500).json({ success: false, error: "Failed to fetch trends" });
  }
});

export default router;
