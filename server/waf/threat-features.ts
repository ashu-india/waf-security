/**
 * Advanced Feature Engineering for Threat Scoring
 * 
 * Extracts statistical and behavioral features for ML-based threat detection
 */

import type { RequestFeatures } from './ml-scoring';

/**
 * Extended threat features for advanced ML scoring
 */
export interface ThreatFeatures extends RequestFeatures {
  // Attack pattern signatures
  sqlInjectionSignature: number; // 0-1 likelihood
  xssSignature: number;
  rceSignature: number;
  xxeSignature: number;
  pathTraversalSignature: number;
  
  // Request behavior patterns
  requestVelocity: number; // requests per second
  payloadComplexity: number; // 0-1
  obfuscationLevel: number; // 0-1
  
  // Statistical anomalies
  zscore: number; // statistical deviation
  mahalanobisDistance: number; // multivariate anomaly
  
  // Time-series features
  timeSeriesAnomaly: boolean;
  burstActivity: boolean;
  
  // Cross-request patterns
  sequentialPatternScore: number; // 0-1
  sessionAnomalyScore: number; // 0-1
}

export class ThreatFeatureExtractor {
  private requestHistory = new Map<string, RequestFeatures[]>();
  private sessionProfiles = new Map<string, {
    requestCount: number;
    pathCount: Set<string>;
    lastRequestTime?: number;
    timeBetweenRequests?: number;
    ipChanged?: boolean;
    userAgentChanged?: boolean;
  }>();
  
  /**
   * Extract advanced threat features
   */
  extractThreatFeatures(
    features: RequestFeatures,
    clientIp: string,
    sessionId?: string
  ): ThreatFeatures {
    // Attack signatures
    const sqlSig = this.calculateSQLSignature(features);
    const xssSig = this.calculateXSSSignature(features);
    const rceSig = this.calculateRCESignature(features);
    const xxeSig = this.calculateXXESignature(features);
    const pathSig = this.calculatePathTraversalSignature(features);
    
    // Request behavior
    const velocity = this.calculateRequestVelocity(clientIp);
    const complexity = this.calculatePayloadComplexity(features);
    const obfuscation = this.calculateObfuscationLevel(features);
    
    // Statistical anomalies
    const zscore = this.calculateZScore(features, clientIp);
    const mahal = this.calculateMahalanobisDistance(features, clientIp);
    
    // Time-series
    const timeSeriesAnomaly = this.detectTimeSeriesAnomaly(clientIp);
    const burstActivity = this.detectBurstActivity(clientIp);
    
    // Sequential patterns
    const seqScore = this.calculateSequentialPatternScore(clientIp, sessionId);
    const sessionAnomaly = this.calculateSessionAnomalyScore(clientIp, sessionId);
    
    return {
      ...features,
      sqlInjectionSignature: sqlSig,
      xssSignature: xssSig,
      rceSignature: rceSig,
      xxeSignature: xxeSig,
      pathTraversalSignature: pathSig,
      requestVelocity: velocity,
      payloadComplexity: complexity,
      obfuscationLevel: obfuscation,
      zscore,
      mahalanobisDistance: mahal,
      timeSeriesAnomaly,
      burstActivity,
      sequentialPatternScore: seqScore,
      sessionAnomalyScore: sessionAnomaly,
    };
  }
  
  /**
   * Calculate SQL injection attack signature
   * Combines multiple indicators into a single score
   */
  private calculateSQLSignature(features: RequestFeatures): number {
    let score = 0;
    
    // Keyword indicators
    score += Math.min(0.3, features.sqlKeywordCount * 0.1);
    
    // Pattern indicators
    const commentRatio = features.specialCharDensity * 0.5;
    score += Math.min(0.2, commentRatio);
    
    // Encoding tricks
    score += Math.min(0.15, features.urlEncodingDensity * 0.3);
    
    // Entropy spike
    if (features.entropyScore > 4) {
      score += 0.15;
    }
    
    // Quote presence in query
    score += Math.min(0.2, (features.specialCharDensity * features.numberDensity) * 0.2);
    
    return Math.min(1, score);
  }
  
  /**
   * Calculate XSS attack signature
   */
  private calculateXSSSignature(features: RequestFeatures): number {
    let score = 0;
    
    // JavaScript keyword indicators
    score += Math.min(0.3, features.jsKeywordCount * 0.15);
    
    // Angle brackets and special chars (< > " ')
    const xssCharPattern = features.specialCharDensity * 0.4;
    score += Math.min(0.25, xssCharPattern);
    
    // Encoded payload detection
    score += Math.min(0.2, features.urlEncodingDensity * 0.2);
    
    // High entropy with special chars
    if (features.entropyScore > 3.5 && features.specialCharDensity > 0.2) {
      score += 0.15;
    }
    
    // Mixed case pattern (encoding bypass)
    score += Math.min(0.1, features.upperCaseDensity * features.specialCharDensity);
    
    return Math.min(1, score);
  }
  
  /**
   * Calculate RCE attack signature
   */
  private calculateRCESignature(features: RequestFeatures): number {
    let score = 0;
    
    // Shell command keywords
    score += Math.min(0.4, features.shellCommandCount * 0.2);
    
    // Pipe, redirection, semicolon patterns
    const cmdChars = (features.specialCharDensity * 0.3);
    score += Math.min(0.3, cmdChars);
    
    // Path indicators (/, \, ~)
    score += Math.min(0.15, (features.pathLength / Math.max(features.queryLength, 1)) * 0.1);
    
    // High entropy (encoding/obfuscation)
    if (features.entropyScore > 4.5) {
      score += 0.15;
    }
    
    return Math.min(1, score);
  }
  
  /**
   * Calculate XXE attack signature
   */
  private calculateXXESignature(features: RequestFeatures): number {
    // XXE typically in body/payload
    const xmlIndicators = /xml|dtd|entity|!DOCTYPE/i;
    let score = 0;
    
    // Body-based attack (not path/query)
    if (features.bodyLength > features.pathLength) {
      score += 0.2;
    }
    
    // Special char spike in body
    score += Math.min(0.3, features.specialCharDensity * 0.3);
    
    // Encoding patterns
    score += Math.min(0.2, features.urlEncodingDensity * 0.2);
    
    return Math.min(1, score);
  }
  
  /**
   * Calculate path traversal signature
   */
  private calculatePathTraversalSignature(features: RequestFeatures): number {
    let score = 0;
    
    // Direct path traversal count
    score += Math.min(0.4, features.pathTraversalCount * 0.2);
    
    // Parent directory references in path
    const pathRatio = features.pathLength > 0 
      ? (features.queryLength / features.pathLength) 
      : 0;
    score += Math.min(0.2, pathRatio * 0.1);
    
    // Null byte injection patterns
    score += Math.min(0.15, features.specialCharDensity * 0.15);
    
    return Math.min(1, score);
  }
  
  /**
   * Calculate request velocity (requests per minute from IP)
   */
  private calculateRequestVelocity(clientIp: string): number {
    const history = this.requestHistory.get(clientIp) || [];
    const now = Date.now();
    const oneMinuteAgo = now - 60000;
    
    const recentRequests = history.filter(
      (_, idx) => now - (idx * 1000) > oneMinuteAgo
    );
    
    return recentRequests.length / 60; // requests per second
  }
  
  /**
   * Calculate payload complexity score
   */
  private calculatePayloadComplexity(features: RequestFeatures): number {
    const totalLength = features.pathLength + 
                       features.queryLength + 
                       features.bodyLength;
    
    const charVariety = Math.min(1, (
      (features.specialCharDensity > 0 ? 1 : 0) +
      (features.numberDensity > 0 ? 1 : 0) +
      (features.upperCaseDensity > 0 ? 1 : 0)
    ) / 3);
    
    const lengthFactor = Math.min(1, totalLength / 10000);
    
    return (charVariety + lengthFactor) / 2;
  }
  
  /**
   * Calculate obfuscation level
   */
  private calculateObfuscationLevel(features: RequestFeatures): number {
    let score = 0;
    
    // URL encoding density
    score += features.urlEncodingDensity * 0.3;
    
    // High entropy
    const normalizedEntropy = Math.min(1, features.entropyScore / 8);
    score += normalizedEntropy * 0.3;
    
    // Mixed case with numbers
    const mixedCase = features.upperCaseDensity * features.numberDensity;
    score += Math.min(0.3, mixedCase);
    
    // Special character density
    score += Math.min(0.1, features.specialCharDensity * 0.5);
    
    return Math.min(1, score);
  }
  
  /**
   * Calculate Z-score for request
   */
  private calculateZScore(features: RequestFeatures, clientIp: string): number {
    const history = this.requestHistory.get(clientIp) || [];
    if (history.length < 10) return 0;
    
    // Calculate mean and stddev of key features
    const lengths = history.map(f => 
      (f.pathLength || 0) + (f.queryLength || 0) + (f.bodyLength || 0)
    );
    
    const mean = lengths.reduce((a, b) => (a as number) + (b as number), 0) / lengths.length;
    const variance = lengths.reduce(
      (sum, x) => (sum as number) + Math.pow((x as number) - mean, 2), 
      0
    ) / lengths.length;
    const stddev = Math.sqrt(variance);
    
    const currentLength = features.pathLength + 
                         features.queryLength + 
                         features.bodyLength;
    
    return stddev > 0 
      ? Math.abs((currentLength - mean) / stddev)
      : 0;
  }
  
  /**
   * Calculate Mahalanobis distance (multivariate anomaly)
   */
  private calculateMahalanobisDistance(features: RequestFeatures, clientIp: string): number {
    const history = this.requestHistory.get(clientIp) || [];
    if (history.length < 5) return 0;
    
    // Simplified Mahalanobis distance
    const features_arr = [
      features.specialCharDensity,
      features.entropyScore,
      features.sqlKeywordCount,
      features.jsKeywordCount,
    ];
    
    // Calculate deviation from mean
    let distance = 0;
    for (const feature of features_arr) {
      distance += Math.abs(feature - 0.5); // Simplified: compare to neutral value
    }
    
    return Math.min(1, distance / 4);
  }
  
  /**
   * Detect time-series anomaly
   */
  private detectTimeSeriesAnomaly(clientIp: string): boolean {
    const history = this.requestHistory.get(clientIp) || [];
    if (history.length < 3) return false;
    
    // Check for sudden spike in request patterns
    const recent = history.slice(-3);
    const scores = recent.map(f => 
      f.specialCharDensity + f.entropyScore
    );
    
    const avg = scores.reduce((a, b) => a + b, 0) / scores.length;
    const spike = scores[scores.length - 1] > avg * 1.5;
    
    return spike;
  }
  
  /**
   * Detect burst activity
   */
  private detectBurstActivity(clientIp: string): boolean {
    const history = this.requestHistory.get(clientIp) || [];
    return history.length > 20; // More than 20 requests recently = burst
  }
  
  /**
   * Calculate sequential pattern score
   */
  private calculateSequentialPatternScore(clientIp: string, sessionId?: string): number {
    // Check if requests follow suspicious pattern
    // E.g., scanning multiple endpoints
    if (!sessionId) return 0;
    
    const profile = this.sessionProfiles.get(sessionId);
    if (!profile) return 0;
    
    const pathVariety = profile.pathCount?.size || 1;
    const requestCount = profile.requestCount || 1;
    
    // High path variety relative to request count = scanning
    const ratio = pathVariety / requestCount;
    return Math.min(1, ratio);
  }
  
  /**
   * Calculate session anomaly score
   */
  private calculateSessionAnomalyScore(clientIp: string, sessionId?: string): number {
    if (!sessionId) return 0;
    
    const profile = this.sessionProfiles.get(sessionId);
    if (!profile) return 0;
    
    // Deviation from expected session behavior
    let score = 0;
    
    // Unusual request timing
    if ((profile.timeBetweenRequests ?? 0) < 100) {
      score += 0.2; // Too fast
    }
    
    // Unusual geographic pattern (if available)
    if (profile.ipChanged) {
      score += 0.3;
    }
    
    // Unusual user agent
    if (profile.userAgentChanged) {
      score += 0.2;
    }
    
    return Math.min(1, score);
  }
  
  /**
   * Record request for history tracking
   */
  recordRequest(clientIp: string, features: RequestFeatures, sessionId?: string): void {
    const history = this.requestHistory.get(clientIp) || [];
    history.push(features);
    
    // Keep only last 100 requests per IP
    if (history.length > 100) {
      history.shift();
    }
    
    this.requestHistory.set(clientIp, history);
    
    // Update session profile
    if (sessionId) {
      const profile = this.sessionProfiles.get(sessionId) || {
        requestCount: 0,
        pathCount: new Set<string>(),
        lastRequestTime: 0,
      };
      
      profile.requestCount += 1;
      profile.timeBetweenRequests = Date.now() - (profile.lastRequestTime ?? 0);
      profile.lastRequestTime = Date.now();
      
      this.sessionProfiles.set(sessionId, profile);
    }
  }
}

