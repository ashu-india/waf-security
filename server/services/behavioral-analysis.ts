/**
 * Behavioral Analysis Service
 * Detects credential stuffing, bot activity, and user anomalies
 */

import { v4 as uuidv4 } from "uuid";
import { storage } from "../storage";

export interface LoginAttempt {
  email: string;
  ip: string;
  userAgent: string;
  timestamp: Date;
  success: boolean;
  reason?: string;
}

export interface BotSignal {
  tlsFingerprint?: string;
  requestTiming: number[]; // Time between requests in ms
  userAgentConsistency: number; // 0-100
  headerAnomalies: number; // Count
  pathPatterns: string[];
  trustScore: number; // 0-100, higher = more trusted
}

export interface BehaviorProfile {
  email: string;
  totalAttempts: number;
  failedAttempts: number;
  successfulAttempts: number;
  lastAttempt: Date;
  ips: Map<string, IpBehavior>;
  isLocked: boolean;
  lockExpiresAt?: Date;
  botScore: number;
  anomalyScore: number;
  riskLevel: "low" | "medium" | "high" | "critical";
}

export interface IpBehavior {
  attempts: number;
  failures: number;
  lastSeen: Date;
  countries: Set<string>;
  userAgents: Set<string>;
  suspiciousPatterns: string[];
}

export class BehavioralAnalysisEngine {
  private loginHistory = new Map<string, LoginAttempt[]>();
  private behaviorProfiles = new Map<string, BehaviorProfile>();
  private failedLoginThreshold = 5;
  private lockoutDurationMs = 15 * 60 * 1000; // 15 minutes
  private historyWindow = 24 * 60 * 60 * 1000; // 24 hours
  private botThresholdScore = 75;

  /**
   * Track a login attempt
   */
  trackLoginAttempt(attempt: LoginAttempt): {
    allowed: boolean;
    reason?: string;
    profile: BehaviorProfile;
  } {
    // Get or create profile
    let profile = this.behaviorProfiles.get(attempt.email) || this.createProfile(attempt.email);

    // Check lockout
    if (profile.isLocked && profile.lockExpiresAt! > attempt.timestamp) {
      profile.totalAttempts++;
      return {
        allowed: false,
        reason: `Account locked due to too many failed attempts. Try again after ${Math.round((profile.lockExpiresAt!.getTime() - attempt.timestamp.getTime()) / 60000)} minutes`,
        profile,
      };
    } else if (profile.isLocked && profile.lockExpiresAt! <= attempt.timestamp) {
      profile.isLocked = false;
      profile.lockExpiresAt = undefined;
    }

    // Track attempt
    this.updateLoginHistory(attempt);
    profile.totalAttempts++;
    profile.lastAttempt = attempt.timestamp;

    // Update IP behavior
    this.updateIpBehavior(profile, attempt);

    // Track failure
    if (!attempt.success) {
      profile.failedAttempts++;

      // Check lockout threshold
      const recentFailures = this.getRecentFailures(attempt.email, this.historyWindow);
      if (recentFailures >= this.failedLoginThreshold) {
        profile.isLocked = true;
        profile.lockExpiresAt = new Date(attempt.timestamp.getTime() + this.lockoutDurationMs);
        return {
          allowed: false,
          reason: `Account locked after ${recentFailures} failed attempts. Try again in 15 minutes`,
          profile,
        };
      }

      // Calculate risk
      const riskScore = this.calculateFailureRisk(profile, attempt);
      if (riskScore > 70) {
        return {
          allowed: false,
          reason: `Suspicious login pattern detected (Risk: ${Math.round(riskScore)}/100)`,
          profile,
        };
      }
    } else {
      profile.successfulAttempts++;
      // Reset failures on successful login
      profile.failedAttempts = 0;
    }

    // Save profile
    this.behaviorProfiles.set(attempt.email, profile);

    return {
      allowed: true,
      profile,
    };
  }

  /**
   * Analyze bot signals
   */
  analyzeBotSignals(signals: BotSignal, email: string): {
    isBotLikely: boolean;
    botScore: number;
    factors: string[];
  } {
    let botScore = 0;
    const factors: string[] = [];

    // TLS Fingerprint analysis
    if (signals.tlsFingerprint) {
      // Known suspicious fingerprints or too generic
      if (this.isGenericTlsFingerprint(signals.tlsFingerprint)) {
        botScore += 15;
        factors.push("Generic TLS fingerprint");
      }
    }

    // Request timing analysis (bots are too regular or too fast)
    if (signals.requestTiming.length >= 2) {
      const avgTiming = signals.requestTiming.reduce((a, b) => a + b, 0) / signals.requestTiming.length;
      const variance = this.calculateVariance(signals.requestTiming);
      const stdDev = Math.sqrt(variance);

      if (stdDev < 50 && avgTiming < 200) {
        botScore += 25;
        factors.push("Suspiciously regular request timing");
      }

      if (avgTiming < 100) {
        botScore += 15;
        factors.push("Requests too fast (possible automation)");
      }
    }

    // User agent consistency
    if (signals.userAgentConsistency > 95) {
      botScore += 10;
      factors.push("Unusually consistent user agent");
    } else if (signals.userAgentConsistency < 10) {
      botScore += 20;
      factors.push("Rapidly changing user agents");
    }

    // Header anomalies
    if (signals.headerAnomalies > 3) {
      botScore += signals.headerAnomalies * 5;
      factors.push(`Multiple header anomalies detected (${signals.headerAnomalies})`);
    }

    // Path pattern analysis
    if (signals.pathPatterns.length > 0) {
      const suspiciousPatterns = signals.pathPatterns.filter(p =>
        /admin|api|config|backup|\.env|\.git|wp-admin|phpmyadmin/i.test(p)
      );
      if (suspiciousPatterns.length > 0) {
        botScore += suspiciousPatterns.length * 10;
        factors.push(`Suspicious path patterns: ${suspiciousPatterns.slice(0, 2).join(", ")}`);
      }
    }

    botScore = Math.min(100, botScore + (100 - signals.trustScore) * 0.3);

    // Update profile
    const profile = this.behaviorProfiles.get(email);
    if (profile) {
      profile.botScore = botScore;
    }

    return {
      isBotLikely: botScore >= this.botThresholdScore,
      botScore: Math.round(botScore),
      factors,
    };
  }

  /**
   * Calculate anomaly score combining multiple factors
   */
  calculateAnomalyScore(email: string): {
    anomalyScore: number;
    components: Record<string, number>;
    riskLevel: "low" | "medium" | "high" | "critical";
  } {
    const profile = this.behaviorProfiles.get(email);
    if (!profile) {
      return {
        anomalyScore: 0,
        components: {},
        riskLevel: "low",
      };
    }

    const components: Record<string, number> = {};

    // Failed login rate
    const failureRate = profile.failedAttempts / Math.max(1, profile.totalAttempts);
    components.failureRate = failureRate * 40;

    // Geographic anomaly
    const uniqueCountries = new Set<string>();
    for (const ipData of Array.from(profile.ips.values())) {
      ipData.countries.forEach((c: string) => uniqueCountries.add(c));
    }
    if (uniqueCountries.size > 2) {
      components.geoAnomaly = Math.min(30, uniqueCountries.size * 10);
    } else {
      components.geoAnomaly = 0;
    }

    // User agent consistency anomaly
    const totalUAs = new Set<string>();
    for (const ipData of Array.from(profile.ips.values())) {
      ipData.userAgents.forEach((ua: string) => totalUAs.add(ua));
    }
    if (totalUAs.size > 10) {
      components.userAgentAnomaly = 25;
    } else if (totalUAs.size > 5) {
      components.userAgentAnomaly = 15;
    } else {
      components.userAgentAnomaly = 0;
    }

    // Velocity anomaly
    const recentAttempts = this.getRecentAttempts(email, 60 * 60 * 1000); // Last hour
    if (recentAttempts > 20) {
      components.velocityAnomaly = 30;
    } else if (recentAttempts > 10) {
      components.velocityAnomaly = 15;
    } else {
      components.velocityAnomaly = 0;
    }

    // Combine scores
    const anomalyScore = Math.min(100, Object.values(components).reduce((a, b) => a + b, 0));

    // Determine risk level
    let riskLevel: "low" | "medium" | "high" | "critical" = "low";
    if (anomalyScore >= 75) riskLevel = "critical";
    else if (anomalyScore >= 60) riskLevel = "high";
    else if (anomalyScore >= 40) riskLevel = "medium";

    profile.anomalyScore = anomalyScore;
    profile.riskLevel = riskLevel;

    return {
      anomalyScore: Math.round(anomalyScore),
      components: Object.fromEntries(Object.entries(components).map(([k, v]) => [k, Math.round(v)])),
      riskLevel,
    };
  }

  /**
   * Detect credential stuffing patterns
   */
  detectCredentialStuffing(email: string): {
    isStuffing: boolean;
    confidence: number;
    indicators: string[];
  } {
    const profile = this.behaviorProfiles.get(email);
    if (!profile) {
      return { isStuffing: false, confidence: 0, indicators: [] };
    }

    const indicators: string[] = [];
    let confidence = 0;

    // Multiple failed attempts from different IPs
    const uniqueIps = profile.ips.size;
    if (uniqueIps > 5) {
      confidence += 20;
      indicators.push(`${uniqueIps} different IPs (credential sharing)`);
    }

    // High failure rate
    if (profile.failedAttempts > 10) {
      confidence += 25;
      indicators.push(`${profile.failedAttempts} failed attempts (brute force)`);
    }

    // Rapid succession attempts
    const recentAttempts = this.getRecentAttempts(email, 10 * 60 * 1000); // Last 10 mins
    if (recentAttempts > 15) {
      confidence += 30;
      indicators.push(`${recentAttempts} attempts in 10 minutes (rapid)`);
    }

    // Multiple user agents
    const uniqueUAs = new Set<string>();
    for (const ipData of Array.from(profile.ips.values())) {
      ipData.userAgents.forEach((ua: string) => uniqueUAs.add(ua));
    }
    if (uniqueUAs.size > 8) {
      confidence += 15;
      indicators.push(`${uniqueUAs.size} different user agents`);
    }

    // Suspicious IPs
    const suspiciousIps = Array.from(profile.ips.values()).filter((ip: IpBehavior) =>
      ip.suspiciousPatterns.length > 0
    ).length;
    if (suspiciousIps > 2) {
      confidence += 10;
      indicators.push(`${suspiciousIps} suspicious IPs`);
    }

    confidence = Math.min(100, confidence);

    return {
      isStuffing: confidence >= 60,
      confidence: Math.round(confidence),
      indicators,
    };
  }

  /**
   * Get profile for user
   */
  getProfile(email: string): BehaviorProfile | undefined {
    return this.behaviorProfiles.get(email);
  }

  /**
   * Clear old history (cleanup)
   */
  clearOldHistory(beforeDate: Date): number {
    let cleaned = 0;
    for (const [email, attempts] of Array.from(this.loginHistory.entries())) {
      const filtered = attempts.filter((a: LoginAttempt) => a.timestamp > beforeDate);
      if (filtered.length === 0) {
        this.loginHistory.delete(email);
        cleaned++;
      } else {
        this.loginHistory.set(email, filtered);
      }
    }
    return cleaned;
  }

  // Private helpers

  private createProfile(email: string): BehaviorProfile {
    return {
      email,
      totalAttempts: 0,
      failedAttempts: 0,
      successfulAttempts: 0,
      lastAttempt: new Date(),
      ips: new Map(),
      isLocked: false,
      botScore: 0,
      anomalyScore: 0,
      riskLevel: "low",
    };
  }

  private updateLoginHistory(attempt: LoginAttempt): void {
    const history = this.loginHistory.get(attempt.email) || [];
    history.push(attempt);
    // Keep only last 100 attempts per user
    if (history.length > 100) {
      history.shift();
    }
    this.loginHistory.set(attempt.email, history);
  }

  private updateIpBehavior(profile: BehaviorProfile, attempt: LoginAttempt): void {
    let ipBehavior = profile.ips.get(attempt.ip);
    if (!ipBehavior) {
      ipBehavior = {
        attempts: 0,
        failures: 0,
        lastSeen: attempt.timestamp,
        countries: new Set(),
        userAgents: new Set(),
        suspiciousPatterns: [],
      };
    }

    ipBehavior.attempts++;
    if (!attempt.success) ipBehavior.failures++;
    ipBehavior.lastSeen = attempt.timestamp;
    ipBehavior.userAgents.add(attempt.userAgent);

    // Detect suspicious patterns
    if (ipBehavior.attempts > 10 && ipBehavior.failures === ipBehavior.attempts) {
      if (!ipBehavior.suspiciousPatterns.includes("all_failed")) {
        ipBehavior.suspiciousPatterns.push("all_failed");
      }
    }

    profile.ips.set(attempt.ip, ipBehavior);
  }

  private getRecentFailures(email: string, windowMs: number): number {
    const history = this.loginHistory.get(email) || [];
    const cutoff = new Date(Date.now() - windowMs);
    return history.filter(h => h.timestamp > cutoff && !h.success).length;
  }

  private getRecentAttempts(email: string, windowMs: number): number {
    const history = this.loginHistory.get(email) || [];
    const cutoff = new Date(Date.now() - windowMs);
    return history.filter(h => h.timestamp > cutoff).length;
  }

  private calculateFailureRisk(profile: BehaviorProfile, attempt: LoginAttempt): number {
    let risk = 0;

    // Failed attempt
    risk += 10;

    // Multiple failures
    if (profile.failedAttempts > 3) {
      risk += 20;
    }

    // Same IP, different user agents
    const ipData = profile.ips.get(attempt.ip);
    if (ipData && ipData.userAgents.size > 5) {
      risk += 25;
    }

    // Many unique IPs
    if (profile.ips.size > 10) {
      risk += 20;
    }

    return Math.min(100, risk);
  }

  private isGenericTlsFingerprint(fingerprint: string): boolean {
    // Common generic fingerprints (simplified)
    const genericFingerprints = ["default", "chrome", "firefox", "bot"];
    return genericFingerprints.some(g => fingerprint.toLowerCase().includes(g));
  }

  private calculateVariance(numbers: number[]): number {
    if (numbers.length === 0) return 0;
    const mean = numbers.reduce((a, b) => a + b, 0) / numbers.length;
    return numbers.reduce((a, b) => a + Math.pow(b - mean, 2), 0) / numbers.length;
  }
}

export const behavioralEngine = new BehavioralAnalysisEngine();

/**
 * Wrapper for persistent storage
 */
export async function saveBehavioralProfile(email: string, profile: BehaviorProfile): Promise<void> {
  try {
    await storage.createOrUpdateBehavioralProfile(email, {
      email,
      totalAttempts: profile.totalAttempts,
      failedAttempts: profile.failedAttempts,
      successfulAttempts: profile.successfulAttempts,
      lastAttempt: profile.lastAttempt,
      isLocked: profile.isLocked,
      lockExpiresAt: profile.lockExpiresAt,
      botScore: profile.botScore,
      anomalyScore: profile.anomalyScore,
      riskLevel: profile.riskLevel,
      ipsJson: Array.from(profile.ips.entries()).map(([ip, data]) => ({
        ip,
        attempts: data.attempts,
        failures: data.failures,
        lastSeen: data.lastSeen,
        countries: Array.from(data.countries),
        userAgents: Array.from(data.userAgents),
        suspiciousPatterns: data.suspiciousPatterns,
      })),
    });
  } catch (error) {
    console.error("Error saving behavioral profile:", error);
  }
}

export async function recordLoginEvent(
  email: string,
  ip: string,
  userAgent: string,
  success: boolean,
  reason?: string
): Promise<void> {
  try {
    const profile = await storage.getBehavioralProfile(email);
    if (profile) {
      await storage.recordBehavioralEvent(profile.id, email, {
        eventType: success ? "login_success" : "login_failed",
        ipAddress: ip,
        userAgent,
        success,
        reason,
      });
    }
  } catch (error) {
    console.error("Error recording login event:", error);
  }
}
