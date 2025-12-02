import { Router } from "express";
import { ComplianceDashboardService } from "../services/compliance-dashboard";

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
 * GET /api/compliance-dashboard/tenant/:tenantId/overview
 * Get dashboard overview for a tenant
 */
router.get("/tenant/:tenantId/overview", requireAuth, requireRole(["admin", "operator", "viewer"]), async (req, res) => {
  try {
    const { tenantId } = req.params;
    const dashboard = await ComplianceDashboardService.getTenantDashboardOverview(tenantId);
    res.json({ success: true, dashboard });
  } catch (error) {
    console.error("Error fetching dashboard overview:", error);
    res.status(500).json({ success: false, error: "Failed to fetch dashboard overview" });
  }
});

/**
 * GET /api/compliance-dashboard/metrics
 * Get system-wide compliance metrics
 */
router.get("/metrics", requireAuth, requireRole(["admin", "operator"]), async (req, res) => {
  try {
    const metrics = await ComplianceDashboardService.getSystemMetrics();
    res.json({ success: true, metrics });
  } catch (error) {
    console.error("Error fetching metrics:", error);
    res.status(500).json({ success: false, error: "Failed to fetch metrics" });
  }
});

/**
 * GET /api/compliance-dashboard/tenant/:tenantId/framework-comparison
 * Compare frameworks for a tenant
 */
router.get(
  "/tenant/:tenantId/framework-comparison",
  requireAuth,
  requireRole(["admin", "operator"]),
  async (req, res) => {
    try {
      const { tenantId } = req.params;
      const comparison = await ComplianceDashboardService.getFrameworkComparison(tenantId);
      res.json({ success: true, comparison });
    } catch (error) {
      console.error("Error fetching framework comparison:", error);
      res.status(500).json({ success: false, error: "Failed to fetch framework comparison" });
    }
  }
);

/**
 * GET /api/compliance-dashboard/rule-coverage
 * Get rule coverage analysis across all tenants
 */
router.get(
  "/rule-coverage",
  requireAuth,
  requireRole(["admin", "operator"]),
  async (req, res) => {
    try {
      const { frameworkId } = req.query;
      const coverage = await ComplianceDashboardService.getRuleCoverageAnalysis(
        (frameworkId as string) || undefined
      );
      res.json({ success: true, coverage });
    } catch (error) {
      console.error("Error fetching rule coverage:", error);
      res.status(500).json({ success: false, error: "Failed to fetch rule coverage" });
    }
  }
);

/**
 * GET /api/compliance-dashboard/tenant/:tenantId/report
 * Generate compliance report for tenant
 */
router.get(
  "/tenant/:tenantId/report",
  requireAuth,
  requireRole(["admin", "operator"]),
  async (req, res) => {
    try {
      const { tenantId } = req.params;
      const report = await ComplianceDashboardService.generateComplianceReport(tenantId);
      res.json({ success: true, report });
    } catch (error) {
      console.error("Error generating compliance report:", error);
      res.status(500).json({ success: false, error: "Failed to generate compliance report" });
    }
  }
);

export default router;
