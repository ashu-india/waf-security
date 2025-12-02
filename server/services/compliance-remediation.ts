import { Policy, ComplianceRule, TenantCompliance } from "../models";
import sequelize from "../db";

export interface RemediationAction {
  id: string;
  tenantId: string;
  frameworkId: string;
  type: "enable_rule" | "update_policy" | "enforce_strict" | "manual_review";
  status: "pending" | "in_progress" | "completed" | "failed";
  description: string;
  affectedRules: number[];
  executedAt?: Date;
  result?: string;
  createdAt: Date;
}

export class ComplianceRemediationService {
  /**
   * Generate remediation actions for low compliance
   */
  static async generateRemediationActions(
    tenantId: string,
    frameworkId: string,
    complianceScore: number
  ): Promise<RemediationAction[]> {
    try {
      const actions: RemediationAction[] = [];

      if (complianceScore < 50) {
        // Critical: Enforce strict mode
        actions.push(await this.createRemediationAction(tenantId, frameworkId, "enforce_strict"));
      } else if (complianceScore < 65) {
        // High: Enable missing rules
        actions.push(await this.createRemediationAction(tenantId, frameworkId, "enable_rule"));
      } else if (complianceScore < 80) {
        // Medium: Update policy
        actions.push(await this.createRemediationAction(tenantId, frameworkId, "update_policy"));
      }

      return actions;
    } catch (error) {
      console.error("Error generating remediation actions:", error);
      throw error;
    }
  }

  /**
   * Create a single remediation action
   */
  private static async createRemediationAction(
    tenantId: string,
    frameworkId: string,
    type: "enable_rule" | "update_policy" | "enforce_strict" | "manual_review"
  ): Promise<RemediationAction> {
    const framework = await sequelize.models.ComplianceFramework.findByPk(frameworkId);
    const frameworkName = (framework as any)?.name || frameworkId;

    let description = "";
    let affectedRules: number[] = [];

    switch (type) {
      case "enable_rule":
        description = `Auto-enable missing compliance rules for ${frameworkName}`;
        affectedRules = await this.getMissingRuleIds(tenantId, frameworkId);
        break;
      case "update_policy":
        description = `Update security policy to meet ${frameworkName} requirements`;
        break;
      case "enforce_strict":
        description = `Enforce strict compliance mode for ${frameworkName} - CRITICAL`;
        break;
      case "manual_review":
        description = `Manual review required for ${frameworkName} compliance`;
        break;
    }

    return {
      id: `action-${Date.now()}`,
      tenantId,
      frameworkId,
      type,
      status: "pending",
      description,
      affectedRules,
      createdAt: new Date(),
    };
  }

  /**
   * Execute remediation action
   */
  static async executeRemediationAction(action: RemediationAction): Promise<boolean> {
    try {
      action.status = "in_progress";

      switch (action.type) {
        case "enable_rule":
          await this.enableMissingRules(action.tenantId, action.frameworkId, action.affectedRules);
          action.result = `Enabled ${action.affectedRules.length} compliance rules`;
          break;

        case "update_policy":
          await this.updateTenantPolicy(action.tenantId, action.frameworkId);
          action.result = "Security policy updated with compliance rules";
          break;

        case "enforce_strict":
          await this.enforceStrictMode(action.tenantId, action.frameworkId);
          action.result = "Strict compliance mode activated";
          break;

        case "manual_review":
          action.result = "Flagged for manual compliance review";
          break;
      }

      action.status = "completed";
      action.executedAt = new Date();
      return true;
    } catch (error) {
      console.error("Error executing remediation action:", error);
      action.status = "failed";
      action.result = `Failed: ${error instanceof Error ? error.message : "Unknown error"}`;
      return false;
    }
  }

  /**
   * Get missing rule IDs for framework
   */
  private static async getMissingRuleIds(tenantId: string, frameworkId: string): Promise<number[]> {
    const rules = await sequelize.models.ComplianceRule.findAll({
      where: { complianceFrameworkId: frameworkId },
    });

    const policies = await Policy.findAll({
      where: { tenantId, enabled: true },
      attributes: ["rules"],
    });

    const enabledRuleIds = new Set<number>();
    for (const policy of policies) {
      const policyRules = JSON.parse((policy as any).rules || "[]");
      policyRules.forEach((ruleId: number) => enabledRuleIds.add(ruleId));
    }

    const missingRules: number[] = [];
    for (const rule of rules) {
      if (!enabledRuleIds.has((rule as any).wafRuleId)) {
        missingRules.push((rule as any).wafRuleId);
      }
    }

    return missingRules;
  }

  /**
   * Enable missing compliance rules in policy
   */
  private static async enableMissingRules(
    tenantId: string,
    frameworkId: string,
    ruleIds: number[]
  ): Promise<void> {
    const policy = await Policy.findOne({
      where: { tenantId, enabled: true },
    });

    if (!policy) return;

    const currentRules = JSON.parse((policy as any).rules || "[]");
    const uniqueRules = new Set([...currentRules, ...ruleIds]);
    (policy as any).rules = JSON.stringify(Array.from(uniqueRules));
    await policy.save();
  }

  /**
   * Update tenant policy with compliance rules
   */
  private static async updateTenantPolicy(tenantId: string, frameworkId: string): Promise<void> {
    const complianceRules = await sequelize.models.ComplianceRule.findAll({
      where: { complianceFrameworkId: frameworkId, severity: "mandatory" },
    });

    const mandatoryRuleIds = complianceRules.map((r: any) => r.wafRuleId);

    const policy = await Policy.findOne({
      where: { tenantId, enabled: true },
    });

    if (policy) {
      const currentRules = JSON.parse((policy as any).rules || "[]");
      const updatedRules = Array.from(new Set([...currentRules, ...mandatoryRuleIds]));
      (policy as any).rules = JSON.stringify(updatedRules);
      await policy.save();
    }
  }

  /**
   * Enforce strict compliance mode
   */
  private static async enforceStrictMode(tenantId: string, frameworkId: string): Promise<void> {
    const complianceRules = await sequelize.models.ComplianceRule.findAll({
      where: { complianceFrameworkId: frameworkId },
    });

    const allRuleIds = complianceRules.map((r: any) => r.wafRuleId);

    // Create or update strict compliance policy
    let policy = await Policy.findOne({
      where: { tenantId, name: "Strict Compliance Policy" },
    });

    if (!policy) {
      policy = await Policy.create({
        tenantId,
        name: "Strict Compliance Policy",
        enabled: true,
        rules: JSON.stringify(allRuleIds),
      });
    } else {
      (policy as any).rules = JSON.stringify(allRuleIds);
      await policy.save();
    }
  }

  /**
   * Get remediation history
   */
  static async getRemediationHistory(tenantId: string): Promise<RemediationAction[]> {
    // This would normally be stored in DB, but for now we return recent actions
    return [];
  }

  /**
   * Schedule automated remediation based on compliance schedule
   */
  static async scheduleAutomatedRemediation(tenantId: string): Promise<void> {
    // Could be extended to use node-cron for scheduled remediation
    console.log(`Scheduling automated remediation for tenant ${tenantId}`);
  }
}
