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
 * POST /api/tenant-compliance/select-framework
 * Add compliance framework to tenant
 */
router.post(
  "/select-framework",
  requireAuth,
  requireRole(["admin"]),
  async (req, res) => {
    try {
      const { tenantId, frameworkId } = req.body;

      if (!tenantId || !frameworkId) {
        return res
          .status(400)
          .json({ success: false, error: "Missing tenantId or frameworkId" });
      }

      const { TenantCompliance, ComplianceFramework } = await import(
        "../models"
      );

      // Check if framework exists
      const framework = await ComplianceFramework.findByPk(frameworkId);
      if (!framework) {
        return res
          .status(404)
          .json({ success: false, error: "Framework not found" });
      }

      // Check if already selected
      const existing = await TenantCompliance.findOne({
        where: { tenantId, complianceFrameworkId: frameworkId },
      });

      if (existing) {
        return res.status(400).json({
          success: false,
          error: "Framework already selected for this tenant",
        });
      }

      // Add framework selection
      await TenantCompliance.create({
        tenantId,
        complianceFrameworkId: frameworkId,
        complianceStatus: "pending_assessment",
      } as any);

      // Log compliance audit
      await ComplianceVerificationService.logComplianceAudit(
        tenantId,
        frameworkId,
        (req.user as any).id,
        "framework_selected",
        `Tenant selected ${framework.name} compliance framework`
      );

      res.json({
        success: true,
        message: `${framework.name} framework selected`,
      });
    } catch (error) {
      console.error("Error selecting compliance framework:", error);
      res
        .status(500)
        .json({ success: false, error: "Failed to select framework" });
    }
  }
);

/**
 * DELETE /api/tenant-compliance/deselect-framework
 * Remove compliance framework from tenant
 */
router.delete(
  "/deselect-framework",
  requireAuth,
  requireRole(["admin"]),
  async (req, res) => {
    try {
      const { tenantId, frameworkId } = req.body;

      if (!tenantId || !frameworkId) {
        return res
          .status(400)
          .json({ success: false, error: "Missing tenantId or frameworkId" });
      }

      const { TenantCompliance, ComplianceFramework } = await import(
        "../models"
      );

      // Check if framework exists
      const framework = await ComplianceFramework.findByPk(frameworkId);
      if (!framework) {
        return res
          .status(404)
          .json({ success: false, error: "Framework not found" });
      }

      // Remove framework selection
      const result = await TenantCompliance.destroy({
        where: { tenantId, complianceFrameworkId: frameworkId },
      });

      if (result === 0) {
        return res.status(404).json({
          success: false,
          error: "Framework not selected for this tenant",
        });
      }

      // Log compliance audit
      await ComplianceVerificationService.logComplianceAudit(
        tenantId,
        frameworkId,
        (req.user as any).id,
        "framework_deselected",
        `Tenant deselected ${framework.name} compliance framework`
      );

      res.json({
        success: true,
        message: `${framework.name} framework deselected`,
      });
    } catch (error) {
      console.error("Error deselecting compliance framework:", error);
      res
        .status(500)
        .json({ success: false, error: "Failed to deselect framework" });
    }
  }
);

/**
 * GET /api/tenant-compliance/:tenantId/frameworks
 * Get frameworks selected by tenant
 */
router.get(
  "/:tenantId/frameworks",
  requireAuth,
  requireRole(["admin", "operator"]),
  async (req, res) => {
    try {
      const { tenantId } = req.params;
      const { TenantCompliance, ComplianceFramework } = await import(
        "../models"
      );

      const tenantFrameworks = await TenantCompliance.findAll({
        where: { tenantId },
        include: [
          {
            model: ComplianceFramework,
            as: "framework",
            attributes: ["id", "name", "description"],
            required: false,
          },
        ],
        attributes: ["complianceFrameworkId", "complianceStatus", "createdAt"],
      });

      const frameworks = tenantFrameworks.map((tf: any) => ({
        frameworkId: tf.complianceFrameworkId,
        framework: tf.framework
          ? {
              id: tf.framework.id,
              name: tf.framework.name,
              description: tf.framework.description,
            }
          : null,
        status: tf.complianceStatus,
        selectedAt: tf.createdAt,
      }));

      res.json({ success: true, frameworks });
    } catch (error) {
      console.error("Error fetching tenant frameworks:", error);
      res
        .status(500)
        .json({ success: false, error: "Failed to fetch frameworks" });
    }
  }
);

/**
 * GET /api/tenant-compliance/:tenantId/available-frameworks
 * Get frameworks not yet selected by tenant
 */
router.get(
  "/:tenantId/available-frameworks",
  requireAuth,
  requireRole(["admin", "operator"]),
  async (req, res) => {
    try {
      const { tenantId } = req.params;
      const { TenantCompliance, ComplianceFramework } = await import(
        "../models"
      );

      // Get all frameworks
      const allFrameworks = await ComplianceFramework.findAll({
        attributes: ["id", "name", "description"],
      });

      // Get selected frameworks for this tenant
      const selectedFrameworks = await TenantCompliance.findAll({
        where: { tenantId },
        attributes: ["complianceFrameworkId"],
      });

      const selectedIds = selectedFrameworks.map(
        (sf: any) => sf.complianceFrameworkId
      );

      // Filter available frameworks
      const available = allFrameworks
        .filter((f: any) => !selectedIds.includes(f.id))
        .map((f: any) => ({
          id: f.id,
          name: f.name,
          description: f.description,
        }));

      res.json({ success: true, available });
    } catch (error) {
      console.error("Error fetching available frameworks:", error);
      res
        .status(500)
        .json({ success: false, error: "Failed to fetch available frameworks" });
    }
  }
);

/**
 * PATCH /api/tenant-compliance/:tenantId/framework/:frameworkId/status
 * Update compliance status for framework
 */
router.patch(
  "/:tenantId/framework/:frameworkId/status",
  requireAuth,
  requireRole(["admin"]),
  async (req, res) => {
    try {
      const { tenantId, frameworkId } = req.params;
      const { status } = req.body;

      if (!status || !["pending_assessment", "compliant", "non_compliant"].includes(status)) {
        return res.status(400).json({
          success: false,
          error: "Invalid status value",
        });
      }

      const { TenantCompliance, ComplianceFramework } = await import(
        "../models"
      );

      const tenantCompliance = await TenantCompliance.findOne({
        where: { tenantId, complianceFrameworkId: frameworkId },
      });

      if (!tenantCompliance) {
        return res.status(404).json({
          success: false,
          error: "Framework not selected for this tenant",
        });
      }

      await tenantCompliance.update({ complianceStatus: status } as any);

      // Log compliance audit
      const framework = await ComplianceFramework.findByPk(frameworkId);
      await ComplianceVerificationService.logComplianceAudit(
        tenantId,
        frameworkId,
        (req.user as any).id,
        "status_updated",
        `Compliance status updated to ${status}`
      );

      res.json({
        success: true,
        message: "Compliance status updated",
      });
    } catch (error) {
      console.error("Error updating compliance status:", error);
      res
        .status(500)
        .json({ success: false, error: "Failed to update status" });
    }
  }
);

/**
 * GET /api/tenant-compliance/:tenantId/summary
 * Get compliance summary for tenant across selected frameworks
 */
router.get(
  "/:tenantId/summary",
  requireAuth,
  requireRole(["admin", "operator"]),
  async (req, res) => {
    try {
      const { tenantId } = req.params;

      // Get overall compliance status
      const status =
        await ComplianceVerificationService.getTenantComplianceStatus(tenantId);

      res.json({ success: true, summary: status });
    } catch (error) {
      console.error("Error fetching compliance summary:", error);
      res
        .status(500)
        .json({ success: false, error: "Failed to fetch compliance summary" });
    }
  }
);

export default router;
