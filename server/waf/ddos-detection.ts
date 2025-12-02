/**
 * DDoS Detection Service - TENANT-ONLY
 * Detects and mitigates distributed denial-of-service attacks per tenant
 * Features: Per-tenant detection, connection limiting, graduated response, traffic normalization
 */

import { EventEmitter } from 'events';

export interface DDoSMetrics {
  requestsPerSecond: number;
  uniqueIPs: number;
  topAttackerIPs: { ip: string; count: number }[];
  suspiciousPatterns: string[];
  volumetricScore: number; // 0-1 confidence score
  protocolAnomalies: number;
  detectionConfidence: number;
}

export interface DDoSConfig {
  // Connection limits
  maxConnections: number;
  maxConnectionsPerIP: number;
  maxRequestsPerSecond: number;
  maxRequestsPerIPPerSecond: number;

  // Detection thresholds
  volumetricThreshold: number; // requests/sec to trigger detection
  uniqueIPThreshold: number; // unique IPs to consider suspicious
  anomalyThreshold: number; // 0-1 confidence threshold

  // Response modes
  enableAutomaticMitigation: boolean;
  graduatedResponseEnabled: boolean;

  // Traffic normalization
  enableNormalization: boolean;
  requestTimeoutMs: number;
  maxHeaderSize: number;
  maxBodySize: number;
}

interface TenantDDoSState {
  requestHistory: Map<string, number[]>; // IP -> timestamps
  ipConnections: Map<string, number>; // IP -> connection count
  totalConnections: number;
  metrics: DDoSMetrics;
  config: DDoSConfig;
  lastMetricsUpdate: number;
}

export class DDoSDetectionService extends EventEmitter {
  private tenantStates: Map<string, TenantDDoSState> = new Map();
  private defaultConfig: DDoSConfig;

  constructor(config: Partial<DDoSConfig> = {}) {
    super();
    this.defaultConfig = {
      maxConnections: 10000,
      maxConnectionsPerIP: 100,
      maxRequestsPerSecond: 5000,
      maxRequestsPerIPPerSecond: 50,
      volumetricThreshold: 3000,
      uniqueIPThreshold: 500,
      anomalyThreshold: 0.7,
      enableAutomaticMitigation: true,
      graduatedResponseEnabled: true,
      enableNormalization: true,
      requestTimeoutMs: 30000,
      maxHeaderSize: 8192,
      maxBodySize: 10485760, // 10MB
      ...config,
    };

    // Cleanup old history every 60 seconds for all tenants
    setInterval(() => this.cleanupAllTenants(), 60000);
  }

  /**
   * Initialize tenant state
   */
  private initializeTenant(tenantId: string): TenantDDoSState {
    if (this.tenantStates.has(tenantId)) {
      return this.tenantStates.get(tenantId)!;
    }

    const state: TenantDDoSState = {
      requestHistory: new Map(),
      ipConnections: new Map(),
      totalConnections: 0,
      metrics: {
        requestsPerSecond: 0,
        uniqueIPs: 0,
        topAttackerIPs: [],
        suspiciousPatterns: [],
        volumetricScore: 0,
        protocolAnomalies: 0,
        detectionConfidence: 0,
      },
      config: { ...this.defaultConfig },
      lastMetricsUpdate: Date.now(),
    };

    this.tenantStates.set(tenantId, state);
    return state;
  }

  /**
   * Analyze request and detect DDoS patterns for specific tenant
   */
  analyzeRequest(
    tenantId: string,
    clientIp: string,
    method: string,
    path: string,
    headers: Record<string, string>,
    bodySize: number
  ): {
    isDDoSDetected: boolean;
    severity: 'low' | 'medium' | 'high' | 'critical';
    action: 'allow' | 'challenge' | 'throttle' | 'block';
    reason: string;
  } {
    const state = this.initializeTenant(tenantId);
    const now = Date.now();
    const severity = this.assessSeverity(state);

    // 1. Check traffic normalization violations
    const normalizationViolation = this.checkNormalizationViolations(
      method,
      path,
      headers,
      bodySize,
      state.config
    );
    if (normalizationViolation) {
      return {
        isDDoSDetected: true,
        severity: 'medium',
        action: 'throttle',
        reason: normalizationViolation,
      };
    }

    // 2. Check connection limits
    const connectionViolation = this.checkConnectionLimits(clientIp, state);
    if (connectionViolation) {
      return {
        isDDoSDetected: true,
        severity: connectionViolation.severity,
        action: connectionViolation.action,
        reason: connectionViolation.reason,
      };
    }

    // 3. Check rate limits
    const rateLimitViolation = this.checkRateLimits(clientIp, now, state);
    if (rateLimitViolation) {
      return {
        isDDoSDetected: true,
        severity: rateLimitViolation.severity,
        action: rateLimitViolation.action,
        reason: rateLimitViolation.reason,
      };
    }

    // 4. Detect volumetric attacks
    const volumetricDetection = this.detectVolumetricAttack(now, state);
    if (volumetricDetection.detected) {
      return {
        isDDoSDetected: true,
        severity: volumetricDetection.severity,
        action: this.getGraduatedResponse(volumetricDetection.severity, state.config),
        reason: volumetricDetection.reason,
      };
    }

    // 5. Detect protocol anomalies
    const protocolAnomaly = this.detectProtocolAnomalies(
      method,
      headers,
      bodySize,
      state
    );
    if (protocolAnomaly) {
      return {
        isDDoSDetected: true,
        severity: 'low',
        action: 'throttle',
        reason: protocolAnomaly,
      };
    }

    return {
      isDDoSDetected: false,
      severity: 'low',
      action: 'allow',
      reason: 'No DDoS pattern detected',
    };
  }

  /**
   * Track per-tenant request
   */
  trackRequest(tenantId: string, clientIp: string): void {
    const state = this.initializeTenant(tenantId);
    const now = Date.now();

    // Track request timestamps per IP
    if (!state.requestHistory.has(clientIp)) {
      state.requestHistory.set(clientIp, []);
    }

    const timestamps = state.requestHistory.get(clientIp)!;
    timestamps.push(now);

    // Keep only last 60 seconds
    const cutoff = now - 60000;
    while (timestamps.length > 0 && timestamps[0] < cutoff) {
      timestamps.shift();
    }

    // Track connections
    state.ipConnections.set(clientIp, (state.ipConnections.get(clientIp) || 0) + 1);
    state.totalConnections++;

    // Update metrics every 5 seconds
    if (now - state.lastMetricsUpdate > 5000) {
      this.updateMetrics(state);
    }
  }

  /**
   * Release connection
   */
  releaseConnection(tenantId: string, clientIp: string): void {
    const state = this.tenantStates.get(tenantId);
    if (!state) return;

    const current = state.ipConnections.get(clientIp) || 0;
    if (current > 0) {
      state.ipConnections.set(clientIp, current - 1);
      state.totalConnections--;
    }
  }

  /**
   * Normalize traffic by checking size and format violations
   */
  private checkNormalizationViolations(
    method: string,
    path: string,
    headers: Record<string, string>,
    bodySize: number,
    config: DDoSConfig
  ): string | null {
    if (!config.enableNormalization) return null;

    // Check suspicious methods
    const suspiciousMethods = ['TRACE', 'CONNECT'];
    if (suspiciousMethods.includes(method)) {
      return `Suspicious HTTP method: ${method}`;
    }

    // Check header size
    const headerSize = JSON.stringify(headers).length;
    if (headerSize > config.maxHeaderSize) {
      return `Header size exceeds limit: ${headerSize}`;
    }

    // Check body size
    if (bodySize > config.maxBodySize) {
      return `Body size exceeds limit: ${bodySize}`;
    }

    // Check for null bytes in path (protocol attack)
    if (path.includes('\x00')) {
      return 'Null byte detected in path';
    }

    // Check for malformed paths
    if (path.includes('..\\') || path.includes('..%')) {
      return 'Path traversal attempt detected';
    }

    return null;
  }

  /**
   * Check per-IP and global connection limits
   */
  private checkConnectionLimits(clientIp: string, state: TenantDDoSState): {
    severity: 'low' | 'medium' | 'high' | 'critical';
    action: 'allow' | 'challenge' | 'throttle' | 'block';
    reason: string;
  } | null {
    const ipConnections = state.ipConnections.get(clientIp) || 0;

    // Per-IP limit
    if (ipConnections > state.config.maxConnectionsPerIP) {
      return {
        severity: 'high',
        action: 'throttle',
        reason: `IP ${clientIp} exceeded connection limit: ${ipConnections}/${state.config.maxConnectionsPerIP}`,
      };
    }

    // Tenant connection limit
    if (state.totalConnections > state.config.maxConnections) {
      // Under severe load, challenge new connections
      return {
        severity: 'critical',
        action: 'challenge',
        reason: `Tenant connection limit exceeded: ${state.totalConnections}/${state.config.maxConnections}`,
      };
    }

    return null;
  }

  /**
   * Check rate limits per IP and global (tenant-scoped)
   */
  private checkRateLimits(
    clientIp: string,
    now: number,
    state: TenantDDoSState
  ): {
    severity: 'low' | 'medium' | 'high' | 'critical';
    action: 'allow' | 'challenge' | 'throttle' | 'block';
    reason: string;
  } | null {
    const timestamps = state.requestHistory.get(clientIp) || [];
    const lastSecond = timestamps.filter((t) => t > now - 1000).length;

    // Per-IP rate limit
    if (lastSecond > state.config.maxRequestsPerIPPerSecond) {
      return {
        severity: 'medium',
        action: 'throttle',
        reason: `IP rate limit exceeded: ${lastSecond} req/s`,
      };
    }

    // Tenant rate limit
    const totalLastSecond = Array.from(state.requestHistory.values()).reduce(
      (sum, ts) => sum + ts.filter((t) => t > now - 1000).length,
      0
    );

    if (totalLastSecond > state.config.maxRequestsPerSecond) {
      return {
        severity: 'high',
        action: 'challenge',
        reason: `Tenant rate limit exceeded: ${totalLastSecond} req/s`,
      };
    }

    return null;
  }

  /**
   * Detect volumetric DDoS attacks (tenant-scoped)
   */
  private detectVolumetricAttack(now: number, state: TenantDDoSState): {
    detected: boolean;
    severity: 'low' | 'medium' | 'high' | 'critical';
    reason: string;
  } {
    const lastSecond = Array.from(state.requestHistory.values()).reduce(
      (sum, ts) => sum + ts.filter((t) => t > now - 1000).length,
      0
    );

    const uniqueIPs = state.requestHistory.size;

    // Calculate volumetric score
    const volumeScore = Math.min(1, lastSecond / (state.config.volumetricThreshold * 2));
    const diversityScore = Math.min(1, uniqueIPs / state.config.uniqueIPThreshold);
    const volumetricScore = (volumeScore + diversityScore) / 2;

    state.metrics.volumetricScore = volumetricScore;

    if (volumetricScore > state.config.anomalyThreshold) {
      let severity: 'low' | 'medium' | 'high' | 'critical' = 'low';
      if (volumetricScore > 0.9) severity = 'critical';
      else if (volumetricScore > 0.8) severity = 'high';
      else if (volumetricScore > 0.7) severity = 'medium';

      return {
        detected: true,
        severity,
        reason: `Volumetric attack detected (score: ${(volumetricScore * 100).toFixed(1)}%, ${lastSecond} req/s)`,
      };
    }

    return {
      detected: false,
      severity: 'low',
      reason: 'No volumetric attack detected',
    };
  }

  /**
   * Detect protocol and HTTP anomalies
   */
  private detectProtocolAnomalies(
    method: string,
    headers: Record<string, string>,
    bodySize: number,
    state: TenantDDoSState
  ): string | null {
    // Anomalies to check
    const anomalies: string[] = [];

    // GET with large body
    if (method === 'GET' && bodySize > 100) {
      anomalies.push('GET request with unexpected body');
    }

    // Missing Host header
    if (!headers['host']) {
      anomalies.push('Missing Host header');
    }

    // Malformed User-Agent
    if (headers['user-agent']?.length === 0) {
      anomalies.push('Empty User-Agent header');
    }

    // Unusual Content-Length
    if (
      headers['content-length'] &&
      isNaN(parseInt(headers['content-length']))
    ) {
      anomalies.push('Invalid Content-Length header');
    }

    state.metrics.protocolAnomalies = anomalies.length;

    return anomalies.length > 0 ? anomalies[0] : null;
  }

  /**
   * Get graduated response based on severity
   */
  private getGraduatedResponse(
    severity: 'low' | 'medium' | 'high' | 'critical',
    config: DDoSConfig
  ): 'allow' | 'challenge' | 'throttle' | 'block' {
    if (!config.graduatedResponseEnabled) {
      return severity === 'critical' ? 'block' : 'throttle';
    }

    // Graduated response: escalate based on severity
    switch (severity) {
      case 'low':
        return 'allow'; // No action
      case 'medium':
        return 'throttle'; // Rate limit
      case 'high':
        return 'challenge'; // CAPTCHA/verification
      case 'critical':
        return 'block'; // Block completely
      default:
        return 'allow';
    }
  }

  /**
   * Assess overall attack severity for tenant
   */
  private assessSeverity(state: TenantDDoSState): 'low' | 'medium' | 'high' | 'critical' {
    if (state.metrics.volumetricScore > 0.9) return 'critical';
    if (state.metrics.volumetricScore > 0.8) return 'high';
    if (state.metrics.volumetricScore > 0.7) return 'medium';
    return 'low';
  }

  /**
   * Update metrics for tenant
   */
  private updateMetrics(state: TenantDDoSState): void {
    const now = Date.now();

    // Requests per second (last second)
    const lastSecond = Array.from(state.requestHistory.values()).reduce(
      (sum, ts) => sum + ts.filter((t) => t > now - 1000).length,
      0
    );
    state.metrics.requestsPerSecond = lastSecond;

    // Unique IPs
    state.metrics.uniqueIPs = state.requestHistory.size;

    // Top attacker IPs
    const ipCounts = Array.from(state.requestHistory.entries())
      .map(([ip, timestamps]) => ({
        ip,
        count: timestamps.filter((t) => t > now - 60000).length,
      }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 10);

    state.metrics.topAttackerIPs = ipCounts;

    // Detection confidence
    state.metrics.detectionConfidence = state.metrics.volumetricScore;

    state.lastMetricsUpdate = now;
    this.emit(`metrics-updated:${state}`, state.metrics);
  }

  /**
   * Cleanup old history for all tenants
   */
  private cleanupAllTenants(): void {
    for (const [, state] of this.tenantStates.entries()) {
      this.cleanupTenant(state);
    }
  }

  /**
   * Cleanup old history for specific tenant
   */
  private cleanupTenant(state: TenantDDoSState): void {
    const now = Date.now();
    const cutoff = now - 120000; // 2 minutes

    const toDelete: string[] = [];

    for (const [ip, timestamps] of state.requestHistory.entries()) {
      // Keep only recent timestamps
      while (timestamps.length > 0 && timestamps[0] < cutoff) {
        timestamps.shift();
      }

      // Remove empty entries
      if (timestamps.length === 0) {
        toDelete.push(ip);
      }
    }

    toDelete.forEach((ip) => {
      state.requestHistory.delete(ip);
      state.ipConnections.delete(ip);
    });
  }

  /**
   * Get tenant-specific metrics
   */
  getTenantMetrics(tenantId: string): DDoSMetrics {
    const state = this.initializeTenant(tenantId);
    const now = Date.now();

    // Requests per second (last second)
    const lastSecond = Array.from(state.requestHistory.values()).reduce(
      (sum, ts) => sum + ts.filter((t) => t > now - 1000).length,
      0
    );

    // Unique IPs
    const uniqueIPs = state.requestHistory.size;

    // Top attacker IPs
    const ipCounts = Array.from(state.requestHistory.entries())
      .map(([ip, timestamps]) => ({
        ip,
        count: timestamps.filter((t) => t > now - 60000).length,
      }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 10);

    // Calculate volumetric score
    const volumeScore = Math.min(1, lastSecond / (state.config.volumetricThreshold * 2));
    const diversityScore = Math.min(1, uniqueIPs / state.config.uniqueIPThreshold);
    const volumetricScore = (volumeScore + diversityScore) / 2;

    const metrics: DDoSMetrics = {
      requestsPerSecond: lastSecond,
      uniqueIPs,
      topAttackerIPs: ipCounts,
      suspiciousPatterns: [],
      volumetricScore,
      protocolAnomalies: 0,
      detectionConfidence: volumetricScore,
    };

    state.metrics = metrics;
    return metrics;
  }

  /**
   * Get all tenants' metrics (for dashboard)
   */
  getAllTenantMetrics(): Map<string, DDoSMetrics> {
    const allMetrics = new Map<string, DDoSMetrics>();
    for (const [tenantId] of this.tenantStates.entries()) {
      allMetrics.set(tenantId, this.getTenantMetrics(tenantId));
    }
    return allMetrics;
  }

  /**
   * Update tenant-specific config
   */
  updateTenantConfig(tenantId: string, config: Partial<DDoSConfig>): void {
    const state = this.initializeTenant(tenantId);
    state.config = { ...state.config, ...config };
  }

  /**
   * Get tenant-specific config
   */
  getTenantConfig(tenantId: string): DDoSConfig {
    const state = this.initializeTenant(tenantId);
    return state.config;
  }

  /**
   * Reset specific tenant's tracking
   */
  resetTenant(tenantId: string): void {
    const state = this.tenantStates.get(tenantId);
    if (state) {
      state.requestHistory.clear();
      state.ipConnections.clear();
      state.totalConnections = 0;
      state.metrics = {
        requestsPerSecond: 0,
        uniqueIPs: 0,
        topAttackerIPs: [],
        suspiciousPatterns: [],
        volumetricScore: 0,
        protocolAnomalies: 0,
        detectionConfidence: 0,
      };
    }
  }

  /**
   * Reset all tenants' tracking
   */
  resetAll(): void {
    this.tenantStates.clear();
  }
}

export const ddosDetection = new DDoSDetectionService();
