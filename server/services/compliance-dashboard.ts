import { ComplianceRule, ComplianceFramework, TenantCompliance, WafRule, Policy } from "../models";
import sequelize from "../db";

export interface ComplianceDashboardData {
  tenantId: string;
  tenantName: string;
  overallScore: number;
  riskLevel: "low" | "medium" | "high" | "critical";
  selectedFrameworks: number;
  totalRules: number;
  compliantRules: number;
  nonCompliantRules: number;
  trends: Array<{date: string; score: number}>;
  frameworkBreakdown: Array<{
    frameworkName: string;
    score: number;
    totalRules: number;
    compliantRules: number;
  }>;
}

export interface ComplianceMetrics {
  totalFrameworks: number;
  totalRules: number;
  avgComplianceScore: number;
  tenantsAboveThreshold: number;
  criticalRiskTenants: number;
  mandatoryRulesCovered: number;
  complianceTrendDirection: "improving" | "declining" | "stable";
}

export interface RuleComplianceDetail {
  ruleId: string;
  description: string;
  category: string;
  severity: string;
  compliantTenants: number;
  nonCompliantTenants: number;
  overallCoverage: number; // percentage
}

export class ComplianceDashboardService {
  /**
   * Get dashboard overview data for a tenant
   */
  static async getTenantDashboardOverview(tenantId: string) {
    try {
      const tenantModel = sequelize.models.Tenant as any;
      const tenant = await tenantModel.findByPk(tenantId);
      if (!tenant) throw new Error("Tenant not found");

      // Get selected frameworks
      const selectedFrameworks = await TenantCompliance.findAll({
        where: { tenantId },
        include: [
          {
            model: ComplianceFramework,
            as: "framework",
            attributes: ["id", "name"],
            required: false,
          },
        ],
      });

      let totalRules = 0;
      let compliantRules = 0;
      const frameworkBreakdown = [];

      // Get policies for tenant
      const policies = await Policy.findAll({
        where: { tenantId, enabled: true },
        attributes: ["rules"],
      });

      const enabledWafRuleIds = new Set<number>();
      for (const policy of policies) {
        const policyRules = JSON.parse((policy as any).rules || "[]");
        policyRules.forEach((ruleId: number) => enabledWafRuleIds.add(ruleId));
      }

      // Calculate per-framework stats
      for (const sf of selectedFrameworks) {
        const framework = (sf as any).framework;
        const rules = await ComplianceRule.findAll({
          where: { complianceFrameworkId: framework.id },
        });

        let frameworkCompliant = 0;
        for (const rule of rules) {
          totalRules++;
          if (enabledWafRuleIds.has((rule as any).wafRuleId)) {
            compliantRules++;
            frameworkCompliant++;
          }
        }

        frameworkBreakdown.push({
          frameworkName: framework.name,
          score: rules.length > 0 ? Math.round((frameworkCompliant / rules.length) * 100) : 0,
          totalRules: rules.length,
          compliantRules: frameworkCompliant,
        });
      }

      const overallScore = totalRules > 0 ? Math.round((compliantRules / totalRules) * 100) : 0;

      let riskLevel: "low" | "medium" | "high" | "critical" = "low";
      if (overallScore < 50) riskLevel = "critical";
      else if (overallScore < 65) riskLevel = "high";
      else if (overallScore < 80) riskLevel = "medium";

      const dashboard: ComplianceDashboardData = {
        tenantId,
        tenantName: tenant.name,
        overallScore,
        riskLevel,
        selectedFrameworks: selectedFrameworks.length,
        totalRules,
        compliantRules,
        nonCompliantRules: totalRules - compliantRules,
        trends: [], // Placeholder for now
        frameworkBreakdown,
      };

      return dashboard;
    } catch (error) {
      console.error("Error fetching dashboard overview:", error);
      throw error;
    }
  }

  /**
   * Get system-wide compliance metrics
   */
  static async getSystemMetrics() {
    try {
      const tenantModel = sequelize.models.Tenant as any;
      
      // Get all tenants with compliance data
      const allTenants = await tenantModel.findAll({
        attributes: ["id"],
      });

      let totalScore = 0;
      let criticalCount = 0;
      let aboveThresholdCount = 0;

      for (const tenant of allTenants) {
        const dashboard = await this.getTenantDashboardOverview(tenant.id);
        totalScore += dashboard.overallScore;
        if (dashboard.riskLevel === "critical") criticalCount++;
        if (dashboard.overallScore >= 80) aboveThresholdCount++;
      }

      const totalFrameworks = await ComplianceFramework.count();
      const totalRules = await ComplianceRule.count();

      const metrics: ComplianceMetrics = {
        totalFrameworks,
        totalRules,
        avgComplianceScore: allTenants.length > 0 ? Math.round(totalScore / allTenants.length) : 0,
        tenantsAboveThreshold: aboveThresholdCount,
        criticalRiskTenants: criticalCount,
        mandatoryRulesCovered: await ComplianceRule.count({ where: { severity: "mandatory" } }),
        complianceTrendDirection: "stable",
      };

      return metrics;
    } catch (error) {
      console.error("Error fetching system metrics:", error);
      throw error;
    }
  }

  /**
   * Get comparison data between frameworks for a tenant
   */
  static async getFrameworkComparison(tenantId: string) {
    try {
      const selectedFrameworks = await TenantCompliance.findAll({
        where: { tenantId },
        include: [
          {
            model: ComplianceFramework,
            as: "framework",
            attributes: ["id", "name"],
            required: false,
          },
        ],
      });

      const policies = await Policy.findAll({
        where: { tenantId, enabled: true },
        attributes: ["rules"],
      });

      const enabledWafRuleIds = new Set<number>();
      for (const policy of policies) {
        const policyRules = JSON.parse((policy as any).rules || "[]");
        policyRules.forEach((ruleId: number) => enabledWafRuleIds.add(ruleId));
      }

      const comparison = [];

      for (const sf of selectedFrameworks) {
        const framework = (sf as any).framework;
        const rules = await ComplianceRule.findAll({
          where: { complianceFrameworkId: framework.id },
          attributes: ["severity"],
        });

        let mandatory = 0;
        let recommended = 0;
        let mandatoryCovered = 0;
        let recommendedCovered = 0;

        for (const rule of rules) {
          if (rule.severity === "mandatory") {
            mandatory++;
            if (enabledWafRuleIds.has((rule as any).wafRuleId)) mandatoryCovered++;
          } else if (rule.severity === "recommended") {
            recommended++;
            if (enabledWafRuleIds.has((rule as any).wafRuleId)) recommendedCovered++;
          }
        }

        comparison.push({
          framework: framework.name,
          totalRules: rules.length,
          mandatoryRules: mandatory,
          mandatoryCompliance: mandatory > 0 ? Math.round((mandatoryCovered / mandatory) * 100) : 100,
          recommendedRules: recommended,
          recommendedCompliance: recommended > 0 ? Math.round((recommendedCovered / recommended) * 100) : 100,
          overallCompliance: rules.length > 0 ? Math.round(((mandatoryCovered + recommendedCovered) / rules.length) * 100) : 0,
        });
      }

      return comparison;
    } catch (error) {
      console.error("Error fetching framework comparison:", error);
      throw error;
    }
  }

  /**
   * Get rule-level compliance coverage across all tenants
   */
  static async getRuleCoverageAnalysis(frameworkId?: string) {
    try {
      const whereClause = frameworkId ? { complianceFrameworkId: frameworkId } : {};
      
      const rules = await ComplianceRule.findAll({
        where: whereClause,
        include: [
          {
            model: ComplianceFramework,
            as: "framework",
            attributes: ["name"],
            required: false,
          },
        ],
      });

      const tenantModel = sequelize.models.Tenant as any;
      const allTenants = await tenantModel.findAll({ attributes: ["id"] });

      const coverage: RuleComplianceDetail[] = [];

      for (const rule of rules) {
        let compliantTenants = 0;
        let nonCompliantTenants = 0;

        for (const tenant of allTenants) {
          const policies = await Policy.findAll({
            where: { tenantId: tenant.id, enabled: true },
            attributes: ["rules"],
          });

          let isCompliant = false;
          for (const policy of policies) {
            const policyRules = JSON.parse((policy as any).rules || "[]");
            if (policyRules.includes((rule as any).wafRuleId)) {
              isCompliant = true;
              break;
            }
          }

          if (isCompliant) compliantTenants++;
          else nonCompliantTenants++;
        }

        const totalTenants = compliantTenants + nonCompliantTenants;
        coverage.push({
          ruleId: rule.complianceRuleId,
          description: rule.description,
          category: rule.mappedCategory,
          severity: rule.severity,
          compliantTenants,
          nonCompliantTenants,
          overallCoverage: totalTenants > 0 ? Math.round((compliantTenants / totalTenants) * 100) : 0,
        });
      }

      return coverage;
    } catch (error) {
      console.error("Error fetching rule coverage analysis:", error);
      throw error;
    }
  }

  /**
   * Export compliance report for tenant
   */
  static async generateComplianceReport(tenantId: string) {
    try {
      const dashboard = await this.getTenantDashboardOverview(tenantId);
      const comparison = await this.getFrameworkComparison(tenantId);

      return {
        generatedAt: new Date(),
        tenant: {
          id: dashboard.tenantId,
          name: dashboard.tenantName,
        },
        summary: {
          overallScore: dashboard.overallScore,
          riskLevel: dashboard.riskLevel,
          selectedFrameworks: dashboard.selectedFrameworks,
          totalRules: dashboard.totalRules,
          compliantRules: dashboard.compliantRules,
          nonCompliantRules: dashboard.nonCompliantRules,
        },
        frameworkDetails: comparison,
      };
    } catch (error) {
      console.error("Error generating compliance report:", error);
      throw error;
    }
  }
}
