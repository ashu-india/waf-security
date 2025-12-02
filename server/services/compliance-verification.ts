import { ComplianceRule, ComplianceFramework, TenantCompliance, WafRule, Policy, User, ComplianceAudit } from "../models";
import sequelize from "../db";
import { Op } from "sequelize";

export interface ComplianceStatus {
  ruleId: string;
  ruleName: string;
  category: string;
  severity: "mandatory" | "recommended" | "optional";
  status: "compliant" | "non_compliant" | "partial" | "not_applicable";
  evidence: string;
  wafRuleId: number;
  mappedWafRuleName?: string;
  lastChecked: Date;
}

export interface ComplianceFrameworkStatus {
  frameworkId: string;
  frameworkName: string;
  totalRules: number;
  compliantRules: number;
  partialRules: number;
  nonCompliantRules: number;
  complianceScore: number; // 0-100
  mandatoryCompliance: number; // % of mandatory rules compliant
  ruleStatuses: ComplianceStatus[];
  lastAssessment: Date;
}

export interface TenantComplianceStatus {
  tenantId: string;
  tenantName: string;
  frameworkStatuses: ComplianceFrameworkStatus[];
  overallScore: number; // Average across frameworks
  riskLevel: "low" | "medium" | "high" | "critical";
  lastUpdated: Date;
}

export class ComplianceVerificationService {
  /**
   * Get all compliance frameworks with rule counts
   */
  static async getAllFrameworks() {
    try {
      const frameworks = await ComplianceFramework.findAll({
        include: [
          {
            model: ComplianceRule,
            as: "rules",
            attributes: ["id"],
            required: false,
          },
        ],
      });

      return frameworks.map((fw: any) => ({
        id: fw.id,
        name: fw.name,
        description: fw.description || "",
        ruleCount: fw.rules?.length || 0,
      }));
    } catch (error) {
      console.error("Error fetching frameworks:", error);
      throw error;
    }
  }

  /**
   * Get compliance rules for a specific framework
   */
  static async getFrameworkRules(frameworkId: string) {
    try {
      const framework = await ComplianceFramework.findByPk(frameworkId, {
        include: [
          {
            model: ComplianceRule,
            as: "rules",
            include: [
              {
                model: WafRule,
                as: "wafRule",
                attributes: ["id", "name", "pattern"],
                required: false,
              },
            ],
          },
        ],
      });

      if (!framework) {
        throw new Error("Framework not found");
      }

      return {
        framework: {
          id: framework.id,
          name: framework.name,
          description: framework.description || "",
        },
        rules: (framework as any).rules.map((rule: any) => ({
          id: rule.complianceRuleId,
          description: rule.description,
          category: rule.mappedCategory,
          severity: rule.severity,
          proof: rule.proof,
          wafRuleId: rule.wafRuleId,
          wafRuleName: rule.wafRule?.name,
        })),
      };
    } catch (error) {
      console.error("Error fetching framework rules:", error);
      throw error;
    }
  }

  /**
   * Verify a specific compliance rule status for a tenant
   */
  static async verifyComplianceRule(
    tenantId: string,
    ruleId: string
  ): Promise<ComplianceStatus> {
    try {
      // Get the compliance rule
      const rule = await ComplianceRule.findOne({
        where: { complianceRuleId: ruleId },
        include: [
          {
            model: WafRule,
            as: "wafRule",
            attributes: ["id", "name"],
            required: false,
          },
        ],
      });

      if (!rule) {
        throw new Error("Compliance rule not found");
      }

      // Get tenant's policies
      const policies = await Policy.findAll({
        where: { tenantId },
        attributes: ["id", "enabled", "rules"],
      });

      // Check if WAF rule is enabled in any policy
      let ruleEnabled = false;
      for (const policy of policies) {
        if (policy.enabled && (policy as any).rules) {
          const policyRules = JSON.parse((policy as any).rules || "[]");
          if (policyRules.includes((rule as any).wafRuleId)) {
            ruleEnabled = true;
            break;
          }
        }
      }

      const status: ComplianceStatus = {
        ruleId: rule.complianceRuleId,
        ruleName: rule.description,
        category: rule.mappedCategory,
        severity: rule.severity as "mandatory" | "recommended" | "optional",
        status: ruleEnabled ? "compliant" : "non_compliant",
        evidence: rule.proof,
        wafRuleId: (rule as any).wafRuleId,
        mappedWafRuleName: (rule as any).wafRule?.name,
        lastChecked: new Date(),
      };

      return status;
    } catch (error) {
      console.error("Error verifying compliance rule:", error);
      throw error;
    }
  }

  /**
   * Get compliance status for a framework within a tenant
   */
  static async getFrameworkComplianceStatus(
    tenantId: string,
    frameworkId: string
  ): Promise<ComplianceFrameworkStatus> {
    try {
      // Get framework and its rules
      const framework = await ComplianceFramework.findByPk(frameworkId, {
        include: [
          {
            model: ComplianceRule,
            as: "rules",
            include: [
              {
                model: WafRule,
                as: "wafRule",
                attributes: ["id", "name"],
                required: false,
              },
            ],
          },
        ],
      });

      if (!framework) {
        throw new Error("Framework not found");
      }

      // Get tenant's enabled policies
      const policies = await Policy.findAll({
        where: { tenantId, enabled: true },
        attributes: ["id", "rules"],
      });

      const enabledRuleIds = new Set<number>();
      for (const policy of policies) {
        const policyRules = JSON.parse((policy as any).rules || "[]");
        policyRules.forEach((ruleId: number) => enabledRuleIds.add(ruleId));
      }

      // Verify each rule
      const ruleStatuses: ComplianceStatus[] = [];
      let compliantCount = 0;
      let partialCount = 0;
      let mandatoryCompliant = 0;
      let mandatoryTotal = 0;

      for (const rule of (framework as any).rules || []) {
        const isEnabled = enabledRuleIds.has(rule.wafRuleId);
        const status = isEnabled ? "compliant" : "non_compliant";

        ruleStatuses.push({
          ruleId: rule.complianceRuleId,
          ruleName: rule.description,
          category: rule.mappedCategory,
          severity: rule.severity,
          status: status as any,
          evidence: rule.proof,
          wafRuleId: rule.wafRuleId,
          mappedWafRuleName: rule.wafRule?.name,
          lastChecked: new Date(),
        });

        if (status === "compliant") compliantCount++;
        if (rule.severity === "mandatory") {
          mandatoryTotal++;
          if (status === "compliant") mandatoryCompliant++;
        }
      }

      const totalRules = ruleStatuses.length;
      const complianceScore =
        totalRules > 0 ? Math.round((compliantCount / totalRules) * 100) : 0;
      const mandatoryCompliance =
        mandatoryTotal > 0
          ? Math.round((mandatoryCompliant / mandatoryTotal) * 100)
          : 100;

      return {
        frameworkId: framework.id,
        frameworkName: framework.name,
        totalRules,
        compliantRules: compliantCount,
        partialRules: partialCount,
        nonCompliantRules: totalRules - compliantCount - partialCount,
        complianceScore,
        mandatoryCompliance,
        ruleStatuses,
        lastAssessment: new Date(),
      };
    } catch (error) {
      console.error("Error calculating framework compliance:", error);
      throw error;
    }
  }

  /**
   * Get overall compliance status for a tenant across all selected frameworks
   */
  static async getTenantComplianceStatus(
    tenantId: string
  ): Promise<TenantComplianceStatus> {
    try {
      // Get tenant info from database via sequelize models
      const tenantModel = sequelize.models.Tenant as any;
      if (!tenantModel) throw new Error("Tenant model not found");
      
      const tenant = await tenantModel.findByPk(tenantId);
      if (!tenant) throw new Error("Tenant not found");

      // Get tenant's selected frameworks
      const tenantCompliance = await TenantCompliance.findAll({
        where: { tenantId },
        attributes: ["complianceFrameworkId"],
      });

      const frameworkIds = tenantCompliance.map(
        (tc: any) => tc.complianceFrameworkId
      );

      // Get compliance status for each framework
      const frameworkStatuses: ComplianceFrameworkStatus[] = [];
      let totalScore = 0;

      for (const frameworkId of frameworkIds) {
        const status = await this.getFrameworkComplianceStatus(
          tenantId,
          frameworkId
        );
        frameworkStatuses.push(status);
        totalScore += status.complianceScore;
      }

      const overallScore =
        frameworkStatuses.length > 0
          ? Math.round(totalScore / frameworkStatuses.length)
          : 0;

      // Determine risk level
      let riskLevel: "low" | "medium" | "high" | "critical" = "low";
      if (overallScore < 50) riskLevel = "critical";
      else if (overallScore < 65) riskLevel = "high";
      else if (overallScore < 80) riskLevel = "medium";

      return {
        tenantId,
        tenantName: tenant.name,
        frameworkStatuses,
        overallScore,
        riskLevel,
        lastUpdated: new Date(),
      };
    } catch (error) {
      console.error("Error calculating tenant compliance:", error);
      throw error;
    }
  }

  /**
   * Log compliance audit event
   */
  static async logComplianceAudit(
    tenantId: string,
    frameworkId: string,
    userId: string,
    action: string,
    details: string
  ) {
    try {
      const user = await User.findByPk(userId);
      const framework = await ComplianceFramework.findByPk(frameworkId);

      await ComplianceAudit.create({
        tenantId,
        complianceFrameworkId: frameworkId,
        userId,
        action,
        details,
        userEmail: user?.email || "unknown",
        frameworkName: framework?.name || "unknown",
      } as any);

      console.log(
        `✅ Compliance audit logged: ${action} for ${framework?.name}`
      );
    } catch (error) {
      console.error("Error logging compliance audit:", error);
    }
  }

  /**
   * Get compliance audit trail for a tenant
   */
  static async getComplianceAuditTrail(
    tenantId: string,
    limit: number = 100
  ) {
    try {
      const audits = await ComplianceAudit.findAll({
        where: { tenantId },
        order: [["createdAt", "DESC"]],
        limit,
        attributes: [
          "id",
          "action",
          "details",
          "userEmail",
          "frameworkName",
          "createdAt",
        ],
      });

      return audits;
    } catch (error) {
      console.error("Error fetching compliance audit trail:", error);
      throw error;
    }
  }

  /**
   * Calculate compliance score trends over time
   */
  static async getComplianceTrends(
    tenantId: string,
    frameworkId: string,
    days: number = 30
  ) {
    try {
      // This would require storing historical compliance scores
      // For now, return current snapshot
      const status = await this.getFrameworkComplianceStatus(
        tenantId,
        frameworkId
      );

      return {
        currentScore: status.complianceScore,
        trend: "stable", // placeholder
        lastAssessment: status.lastAssessment,
      };
    } catch (error) {
      console.error("Error calculating compliance trends:", error);
      throw error;
    }
  }
}
