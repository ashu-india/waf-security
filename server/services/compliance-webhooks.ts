export interface WebhookConfig {
  id: string;
  tenantId: string;
  url: string;
  events: string[]; // compliance_alert, remediation_action, audit_log
  isActive: boolean;
  secret?: string;
  retries: number;
  createdAt: Date;
}

export interface WebhookPayload {
  event: string;
  tenantId: string;
  timestamp: Date;
  data: any;
  signature?: string;
}

const webhooks = new Map<string, WebhookConfig>();
const webhookHistory = new Map<string, any[]>();

export class ComplianceWebhookService {
  /**
   * Register a webhook
   */
  static registerWebhook(config: Omit<WebhookConfig, "id" | "createdAt">): WebhookConfig {
    const webhook: WebhookConfig = {
      ...config,
      id: `webhook-${Date.now()}`,
      createdAt: new Date(),
    };

    webhooks.set(webhook.id, webhook);
    webhookHistory.set(webhook.id, []);
    return webhook;
  }

  /**
   * Get webhooks for tenant
   */
  static getWebhooks(tenantId: string): WebhookConfig[] {
    const result: WebhookConfig[] = [];
    for (const webhook of webhooks.values()) {
      if (webhook.tenantId === tenantId) {
        result.push(webhook);
      }
    }
    return result;
  }

  /**
   * Update webhook
   */
  static updateWebhook(webhookId: string, updates: Partial<WebhookConfig>): WebhookConfig | null {
    const webhook = webhooks.get(webhookId);
    if (!webhook) return null;

    const updated = { ...webhook, ...updates };
    webhooks.set(webhookId, updated);
    return updated;
  }

  /**
   * Delete webhook
   */
  static deleteWebhook(webhookId: string): boolean {
    return webhooks.delete(webhookId);
  }

  /**
   * Send webhook event
   */
  static async sendWebhookEvent(tenantId: string, event: string, data: any): Promise<void> {
    const tenantWebhooks = this.getWebhooks(tenantId);

    for (const webhook of tenantWebhooks) {
      if (!webhook.isActive || !webhook.events.includes(event)) {
        continue;
      }

      const payload: WebhookPayload = {
        event,
        tenantId,
        timestamp: new Date(),
        data,
      };

      // Add signature if secret is configured
      if (webhook.secret) {
        const crypto = require("crypto");
        payload.signature = crypto
          .createHmac("sha256", webhook.secret)
          .update(JSON.stringify(payload))
          .digest("hex");
      }

      await this.sendWithRetries(webhook, payload);
    }
  }

  /**
   * Send webhook with retry logic
   */
  private static async sendWithRetries(webhook: WebhookConfig, payload: WebhookPayload): Promise<void> {
    let lastError: Error | null = null;

    for (let attempt = 0; attempt <= webhook.retries; attempt++) {
      try {
        const response = await fetch(webhook.url, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "X-Webhook-Signature": payload.signature || "",
          },
          body: JSON.stringify(payload),
          signal: AbortSignal.timeout(10000),
        });

        // Log success
        this.logWebhookEvent(webhook.id, {
          event: payload.event,
          status: "success",
          statusCode: response.status,
          timestamp: new Date(),
        });

        return;
      } catch (error) {
        lastError = error as Error;

        // Log attempt
        this.logWebhookEvent(webhook.id, {
          event: payload.event,
          status: "failed",
          attempt: attempt + 1,
          error: lastError.message,
          timestamp: new Date(),
        });

        // Wait before retry
        if (attempt < webhook.retries) {
          await new Promise((resolve) => setTimeout(resolve, 1000 * (attempt + 1)));
        }
      }
    }

    console.error(`Webhook delivery failed after ${webhook.retries + 1} attempts:`, lastError?.message);
  }

  /**
   * Log webhook event for history/debugging
   */
  private static logWebhookEvent(webhookId: string, event: any): void {
    const history = webhookHistory.get(webhookId) || [];
    history.push(event);

    // Keep only last 100 events
    if (history.length > 100) {
      history.shift();
    }

    webhookHistory.set(webhookId, history);
  }

  /**
   * Get webhook delivery history
   */
  static getWebhookHistory(webhookId: string): any[] {
    return webhookHistory.get(webhookId) || [];
  }

  /**
   * Test webhook
   */
  static async testWebhook(webhook: WebhookConfig): Promise<boolean> {
    const testPayload: WebhookPayload = {
      event: "test",
      tenantId: webhook.tenantId,
      timestamp: new Date(),
      data: { message: "Webhook test from compliance system" },
    };

    try {
      const response = await fetch(webhook.url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(testPayload),
        signal: AbortSignal.timeout(5000),
      });

      return response.status >= 200 && response.status < 300;
    } catch (error) {
      console.error("Webhook test failed:", error);
      return false;
    }
  }

  /**
   * Trigger compliance alert webhook
   */
  static async triggerComplianceAlert(tenantId: string, alert: any): Promise<void> {
    await this.sendWebhookEvent(tenantId, "compliance_alert", {
      type: "alert",
      framework: alert.frameworkName,
      severity: alert.severity,
      message: alert.message,
      score: alert.currentScore,
    });
  }

  /**
   * Trigger remediation action webhook
   */
  static async triggerRemediationAction(tenantId: string, action: any): Promise<void> {
    await this.sendWebhookEvent(tenantId, "remediation_action", {
      type: "remediation",
      actionType: action.type,
      status: action.status,
      description: action.description,
      result: action.result,
    });
  }

  /**
   * Trigger audit log webhook
   */
  static async triggerAuditLog(tenantId: string, audit: any): Promise<void> {
    await this.sendWebhookEvent(tenantId, "audit_log", {
      type: "audit",
      action: audit.action,
      framework: audit.frameworkName,
      user: audit.userEmail,
    });
  }
}
