/**
 * DDoS Action Enforcement Service
 * Enforces throttling, CAPTCHA challenges, and blocking
 */

import { DDoSEvent } from '../models';
import { generateChallenge } from '../utils/captcha';

interface ActionResult {
  action: 'allow' | 'throttle' | 'challenge' | 'block';
  reason: string;
  challengeId?: string;
  delayMs?: number;
}

export class ActionEnforcementService {
  private throttledIPs: Map<string, { count: number; resetAt: number }> = new Map();
  private blockedIPs: Map<string, number> = new Map();
  private const THROTTLE_LIMIT = 10;
  private const THROTTLE_WINDOW = 60000; // 1 minute

  /**
   * Enforce action for DDoS response
   */
  async enforceAction(
    tenantId: string,
    clientIp: string,
    action: 'allow' | 'throttle' | 'challenge' | 'block',
    severity: 'low' | 'medium' | 'high' | 'critical',
    reason: string
  ): Promise<ActionResult> {
    try {
      // Log the event to database
      await DDoSEvent.create({
        tenantId,
        clientIp,
        severity,
        eventType: 'rate_limit',
        reason,
        action,
      } as any);

      // Enforce the action
      switch (action) {
        case 'allow':
          return { action: 'allow', reason };

        case 'throttle':
          return this.throttleRequest(clientIp, reason);

        case 'challenge':
          return this.generateChallenge(reason);

        case 'block':
          return this.blockIP(clientIp, reason);

        default:
          return { action: 'allow', reason };
      }
    } catch (error) {
      console.error('Error enforcing action:', error);
      return { action: 'allow', reason: 'Enforcement service error' };
    }
  }

  /**
   * Throttle request by adding delay
   */
  private throttleRequest(clientIp: string, reason: string): ActionResult {
    const now = Date.now();
    let ipData = this.throttledIPs.get(clientIp);

    if (!ipData) {
      ipData = { count: 1, resetAt: now + this.THROTTLE_WINDOW };
      this.throttledIPs.set(clientIp, ipData);
    } else if (now > ipData.resetAt) {
      // Reset counter if window expired
      ipData.count = 1;
      ipData.resetAt = now + this.THROTTLE_WINDOW;
    } else {
      ipData.count++;
    }

    // Calculate exponential backoff: 100ms, 200ms, 400ms, etc (max 5 seconds)
    const delayMs = Math.min(100 * Math.pow(2, Math.max(0, ipData.count - 1)), 5000);

    if (ipData.count > this.THROTTLE_LIMIT) {
      // Escalate to blocking
      this.blockedIPs.set(clientIp, now + 300000); // Block for 5 minutes
      return { action: 'block', reason: 'Throttle limit exceeded', delayMs: 0 };
    }

    return {
      action: 'throttle',
      reason,
      delayMs,
    };
  }

  /**
   * Generate CAPTCHA challenge
   */
  private generateChallenge(reason: string): ActionResult {
    const { id, question } = generateChallenge();
    return {
      action: 'challenge',
      reason,
      challengeId: id,
    };
  }

  /**
   * Block IP address for a period
   */
  private blockIP(clientIp: string, reason: string): ActionResult {
    const now = Date.now();
    const blockUntil = now + 300000; // Block for 5 minutes
    this.blockedIPs.set(clientIp, blockUntil);

    return {
      action: 'block',
      reason,
      delayMs: 0,
    };
  }

  /**
   * Check if IP is currently blocked
   */
  isIPBlocked(clientIp: string): boolean {
    const blockUntil = this.blockedIPs.get(clientIp);
    if (!blockUntil) return false;

    const now = Date.now();
    if (now > blockUntil) {
      this.blockedIPs.delete(clientIp);
      return false;
    }

    return true;
  }

  /**
   * Get throttle delay for IP
   */
  getThrottleDelay(clientIp: string): number {
    const ipData = this.throttledIPs.get(clientIp);
    if (!ipData) return 0;

    const now = Date.now();
    if (now > ipData.resetAt) {
      this.throttledIPs.delete(clientIp);
      return 0;
    }

    const delayMs = Math.min(100 * Math.pow(2, Math.max(0, ipData.count - 1)), 5000);
    return delayMs;
  }

  /**
   * Cleanup expired throttles and blocks
   */
  cleanup(): void {
    const now = Date.now();

    for (const [ip, data] of this.throttledIPs.entries()) {
      if (now > data.resetAt) {
        this.throttledIPs.delete(ip);
      }
    }

    for (const [ip, blockUntil] of this.blockedIPs.entries()) {
      if (now > blockUntil) {
        this.blockedIPs.delete(ip);
      }
    }
  }
}

export const actionEnforcement = new ActionEnforcementService();

// Cleanup every 30 seconds
setInterval(() => {
  actionEnforcement.cleanup();
}, 30000);
