import { Router } from "express";
import { ComplianceMonitoringService } from "../services/compliance-monitoring";

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
 * GET /api/compliance-monitoring/tenant/:tenantId/status
 * Get real-time compliance status for all frameworks
 */
router.get("/tenant/:tenantId/status", requireAuth, requireRole(["admin", "operator"]), async (req, res) => {
  try {
    const { tenantId } = req.params;
    const statuses = await ComplianceMonitoringService.getTenantComplianceStatusAll(tenantId);
    res.json({ success: true, statuses });
  } catch (error) {
    console.error("Error fetching compliance status:", error);
    res.status(500).json({ success: false, error: "Failed to fetch compliance status" });
  }
});

/**
 * GET /api/compliance-monitoring/tenant/:tenantId/framework/:frameworkId/status
 * Get real-time compliance status for a specific framework
 */
router.get(
  "/tenant/:tenantId/framework/:frameworkId/status",
  requireAuth,
  requireRole(["admin", "operator", "viewer"]),
  async (req, res) => {
    try {
      const { tenantId, frameworkId } = req.params;
      const status = await ComplianceMonitoringService.checkComplianceStatus(tenantId, frameworkId);
      if (!status) {
        return res.status(404).json({ success: false, error: "Framework not found" });
      }
      res.json({ success: true, status });
    } catch (error) {
      console.error("Error fetching framework status:", error);
      res.status(500).json({ success: false, error: "Failed to fetch framework status" });
    }
  }
);

/**
 * GET /api/compliance-monitoring/tenant/:tenantId/alerts
 * Get all active alerts for tenant
 */
router.get("/tenant/:tenantId/alerts", requireAuth, requireRole(["admin", "operator"]), async (req, res) => {
  try {
    const { tenantId } = req.params;
    const alerts = await ComplianceMonitoringService.getTenantAlerts(tenantId);
    res.json({ success: true, alerts });
  } catch (error) {
    console.error("Error fetching alerts:", error);
    res.status(500).json({ success: false, error: "Failed to fetch alerts" });
  }
});

/**
 * GET /api/compliance-monitoring/tenant/:tenantId/framework/:frameworkId/alerts
 * Get alerts for specific framework
 */
router.get(
  "/tenant/:tenantId/framework/:frameworkId/alerts",
  requireAuth,
  requireRole(["admin", "operator"]),
  async (req, res) => {
    try {
      const { tenantId, frameworkId } = req.params;
      const alerts = await ComplianceMonitoringService.getFrameworkAlerts(tenantId, frameworkId);
      res.json({ success: true, alerts });
    } catch (error) {
      console.error("Error fetching framework alerts:", error);
      res.status(500).json({ success: false, error: "Failed to fetch framework alerts" });
    }
  }
);

/**
 * POST /api/compliance-monitoring/alert/:alertId/read
 * Mark alert as read
 */
router.post("/alert/:alertId/read", requireAuth, requireRole(["admin", "operator"]), async (req, res) => {
  try {
    const { alertId } = req.params;
    const success = ComplianceMonitoringService.markAlertAsRead(alertId);
    if (!success) {
      return res.status(404).json({ success: false, error: "Alert not found" });
    }
    res.json({ success: true });
  } catch (error) {
    console.error("Error marking alert as read:", error);
    res.status(500).json({ success: false, error: "Failed to mark alert as read" });
  }
});

/**
 * DELETE /api/compliance-monitoring/tenant/:tenantId/framework/:frameworkId/alerts
 * Clear alerts for framework
 */
router.delete(
  "/tenant/:tenantId/framework/:frameworkId/alerts",
  requireAuth,
  requireRole(["admin"]),
  async (req, res) => {
    try {
      const { tenantId, frameworkId } = req.params;
      ComplianceMonitoringService.clearFrameworkAlerts(tenantId, frameworkId);
      res.json({ success: true });
    } catch (error) {
      console.error("Error clearing alerts:", error);
      res.status(500).json({ success: false, error: "Failed to clear alerts" });
    }
  }
);

/**
 * SSE endpoint: GET /api/compliance-monitoring/stream/:tenantId
 * Stream real-time compliance status and alerts
 */
router.get("/stream/:tenantId", requireAuth, requireRole(["admin", "operator"]), (req, res) => {
  const { tenantId } = req.params;

  res.setHeader("Content-Type", "text/event-stream");
  res.setHeader("Cache-Control", "no-cache");
  res.setHeader("Connection", "keep-alive");
  res.setHeader("Access-Control-Allow-Origin", "*");

  const emitter = ComplianceMonitoringService.getEventEmitter();

  // Send initial connection message
  res.write(`data: ${JSON.stringify({ type: "connected", tenantId })}\n\n`);

  // Send compliance alert events
  const handleAlert = (data: any) => {
    if (data.tenantId === tenantId) {
      res.write(`data: ${JSON.stringify({ type: "compliance-alert", ...data })}\n\n`);
    }
  };

  emitter.on("compliance-alert", handleAlert);

  // Periodic status update (every 30 seconds)
  const statusInterval = setInterval(async () => {
    try {
      const statuses = await ComplianceMonitoringService.getTenantComplianceStatusAll(tenantId);
      res.write(`data: ${JSON.stringify({ type: "status-update", statuses })}\n\n`);
    } catch (error) {
      console.error("Error sending status update:", error);
    }
  }, 30000);

  // Cleanup on client disconnect
  req.on("close", () => {
    emitter.removeListener("compliance-alert", handleAlert);
    clearInterval(statusInterval);
    res.end();
  });
});

export default router;
