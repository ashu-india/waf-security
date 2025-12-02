import { TenantCompliance, ComplianceFramework, ComplianceRule, Policy } from "../models";
import sequelize from "../db";
import { EventEmitter } from "events";

export interface ComplianceAlert {
  id: string;
  tenantId: string;
  frameworkId: string;
  frameworkName: string;
  severity: "low" | "medium" | "high" | "critical";
  type: "compliance_drop" | "threshold_breach" | "rule_violation" | "audit_overdue";
  message: string;
  previousScore: number;
  currentScore: number;
  threshold: number;
  isRead: boolean;
  createdAt: Date;
}

export interface ComplianceStatus {
  tenantId: string;
  frameworkId: string;
  frameworkName: string;
  score: number;
  riskLevel: "low" | "medium" | "high" | "critical";
  status: "compliant" | "at_risk" | "non_compliant";
  lastCheck: Date;
  alerts: ComplianceAlert[];
}

// In-memory alert storage for real-time monitoring
const activeAlerts = new Map<string, ComplianceAlert[]>();
const complianceMonitorEmitter = new EventEmitter();

export class ComplianceMonitoringService {
  private static readonly SCORE_DROP_THRESHOLD = 15; // Alert if score drops > 15%
  private static readonly LOW_SCORE_THRESHOLD = 65; // Alert if overall score < 65%
  private static readonly CRITICAL_SCORE_THRESHOLD = 50; // Critical alert if < 50%

  /**
   * Check compliance status and generate alerts
   */
  static async checkComplianceStatus(tenantId: string, frameworkId: string) {
    try {
      const framework = await ComplianceFramework.findByPk(frameworkId);
      if (!framework) return null;

      const tenantFramework = await TenantCompliance.findOne({
        where: { tenantId, complianceFrameworkId: frameworkId },
      });

      if (!tenantFramework) return null;

      // Calculate current compliance score
      const rules = await ComplianceRule.findAll({
        where: { complianceFrameworkId: frameworkId },
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

      let compliantCount = 0;
      for (const rule of rules) {
        if (enabledWafRuleIds.has((rule as any).wafRuleId)) {
          compliantCount++;
        }
      }

      const currentScore = rules.length > 0 ? Math.round((compliantCount / rules.length) * 100) : 0;

      // Generate alerts if needed
      await this.generateAlerts(tenantId, frameworkId, (framework as any).name, currentScore);

      const status: ComplianceStatus = {
        tenantId,
        frameworkId,
        frameworkName: (framework as any).name,
        score: currentScore,
        riskLevel: this.getRiskLevel(currentScore),
        status: this.getComplianceStatus(currentScore),
        lastCheck: new Date(),
        alerts: activeAlerts.get(`${tenantId}:${frameworkId}`) || [],
      };

      return status;
    } catch (error) {
      console.error("Error checking compliance status:", error);
      throw error;
    }
  }

  /**
   * Generate alerts based on compliance score changes
   */
  private static async generateAlerts(
    tenantId: string,
    frameworkId: string,
    frameworkName: string,
    currentScore: number
  ) {
    const alertKey = `${tenantId}:${frameworkId}`;
    const existingAlerts = activeAlerts.get(alertKey) || [];

    // Check for critical threshold breach
    if (currentScore < this.CRITICAL_SCORE_THRESHOLD && !existingAlerts.some(a => a.type === "threshold_breach")) {
      this.addAlert({
        tenantId,
        frameworkId,
        frameworkName,
        severity: "critical",
        type: "threshold_breach",
        message: `Critical: ${frameworkName} compliance at ${currentScore}%, below critical threshold of ${this.CRITICAL_SCORE_THRESHOLD}%`,
        currentScore,
        threshold: this.CRITICAL_SCORE_THRESHOLD,
      });
    }

    // Check for low threshold breach
    if (currentScore < this.LOW_SCORE_THRESHOLD && !existingAlerts.some(a => a.type === "compliance_drop")) {
      this.addAlert({
        tenantId,
        frameworkId,
        frameworkName,
        severity: "high",
        type: "compliance_drop",
        message: `High: ${frameworkName} compliance at ${currentScore}%, below threshold of ${this.LOW_SCORE_THRESHOLD}%`,
        currentScore,
        threshold: this.LOW_SCORE_THRESHOLD,
      });
    }

    // Check for medium risk
    if (currentScore < 80 && currentScore >= this.LOW_SCORE_THRESHOLD) {
      if (!existingAlerts.some(a => a.type === "rule_violation")) {
        this.addAlert({
          tenantId,
          frameworkId,
          frameworkName,
          severity: "medium",
          type: "rule_violation",
          message: `Medium: ${frameworkName} compliance at ${currentScore}%, review pending rules`,
          currentScore,
          threshold: 80,
        });
      }
    }

    // Emit alert event for real-time updates
    if (activeAlerts.has(alertKey)) {
      complianceMonitorEmitter.emit("compliance-alert", {
        tenantId,
        frameworkId,
        alerts: activeAlerts.get(alertKey),
      });
    }
  }

  /**
   * Add alert to active alerts
   */
  private static addAlert(data: {
    tenantId: string;
    frameworkId: string;
    frameworkName: string;
    severity: "low" | "medium" | "high" | "critical";
    type: "compliance_drop" | "threshold_breach" | "rule_violation" | "audit_overdue";
    message: string;
    currentScore: number;
    threshold: number;
    previousScore?: number;
  }) {
    const alertKey = `${data.tenantId}:${data.frameworkId}`;
    const alert: ComplianceAlert = {
      id: `alert-${Date.now()}`,
      tenantId: data.tenantId,
      frameworkId: data.frameworkId,
      frameworkName: data.frameworkName,
      severity: data.severity,
      type: data.type,
      message: data.message,
      previousScore: data.previousScore || 0,
      currentScore: data.currentScore,
      threshold: data.threshold,
      isRead: false,
      createdAt: new Date(),
    };

    const alerts = activeAlerts.get(alertKey) || [];
    alerts.push(alert);
    activeAlerts.set(alertKey, alerts);
  }

  /**
   * Get all active alerts for a tenant
   */
  static async getTenantAlerts(tenantId: string) {
    const alerts: ComplianceAlert[] = [];
    for (const [key, alertList] of activeAlerts.entries()) {
      if (key.startsWith(tenantId)) {
        alerts.push(...alertList);
      }
    }
    return alerts.sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime());
  }

  /**
   * Get alerts for a specific framework
   */
  static async getFrameworkAlerts(tenantId: string, frameworkId: string) {
    const alertKey = `${tenantId}:${frameworkId}`;
    return activeAlerts.get(alertKey) || [];
  }

  /**
   * Mark alert as read
   */
  static markAlertAsRead(alertId: string) {
    for (const [, alerts] of activeAlerts.entries()) {
      const alert = alerts.find(a => a.id === alertId);
      if (alert) {
        alert.isRead = true;
        return true;
      }
    }
    return false;
  }

  /**
   * Clear alerts for a framework
   */
  static clearFrameworkAlerts(tenantId: string, frameworkId: string) {
    const alertKey = `${tenantId}:${frameworkId}`;
    activeAlerts.delete(alertKey);
  }

  /**
   * Get real-time compliance status for all tenant frameworks
   */
  static async getTenantComplianceStatusAll(tenantId: string) {
    const frameworks = await TenantCompliance.findAll({
      where: { tenantId },
    });

    const statuses: ComplianceStatus[] = [];
    for (const tf of frameworks) {
      const status = await this.checkComplianceStatus(tenantId, (tf as any).complianceFrameworkId);
      if (status) {
        statuses.push(status);
      }
    }

    return statuses;
  }

  /**
   * Get event emitter for real-time updates
   */
  static getEventEmitter() {
    return complianceMonitorEmitter;
  }

  /**
   * Helper: determine risk level
   */
  private static getRiskLevel(score: number): "low" | "medium" | "high" | "critical" {
    if (score < 50) return "critical";
    if (score < 65) return "high";
    if (score < 80) return "medium";
    return "low";
  }

  /**
   * Helper: determine compliance status
   */
  private static getComplianceStatus(score: number): "compliant" | "at_risk" | "non_compliant" {
    if (score >= 80) return "compliant";
    if (score >= 65) return "at_risk";
    return "non_compliant";
  }
}
