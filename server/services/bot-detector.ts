/**
 * Bot Detection Service
 * Identifies automated attacks using behavioral signals
 */

export interface RequestSignals {
  method: string;
  path: string;
  userAgent: string;
  headers: Record<string, string | string[]>;
  ip: string;
  timestamp: number;
  bodySize?: number;
}

export interface BotDetectionResult {
  isBot: boolean;
  score: number;
  factors: string[];
  detectionMethod: string;
}

export class BotDetector {
  private suspiciousPathPatterns = [
    /\/admin/i,
    /\/api\/admin/i,
    /wp-admin/i,
    /phpmyadmin/i,
    /\.env/i,
    /\.git/i,
    /config\.php/i,
    /web\.config/i,
    /\.aws/i,
    /\.env\.local/i,
    /backup/i,
    /uploads/i,
    /downloads/i,
    /\.zip/i,
    /\.sql/i,
    /shell\.php/i,
    /test\.php/i,
  ];

  private suspiciousUserAgents = [
    /bot/i,
    /crawler/i,
    /spider/i,
    /scraper/i,
    /curl/i,
    /wget/i,
    /python/i,
    /java(?!script)/i,
    /perl/i,
    /ruby/i,
    /golang/i,
    /php/i,
    /sqlmap/i,
    /nikto/i,
    /nessus/i,
    /burp/i,
    /masscan/i,
    /nmap/i,
  ];

  private genericUserAgents = [
    "mozilla/5.0",
    "user-agent",
    "-",
    "none",
    "",
  ];

  /**
   * Analyze request for bot patterns
   */
  analyze(signals: RequestSignals): BotDetectionResult {
    let score = 0;
    const factors: string[] = [];
    let detectionMethod = "composite";

    // Check 1: Suspicious paths
    const pathScore = this.analyzePath(signals.path);
    if (pathScore > 0) {
      score += pathScore;
      factors.push("Suspicious path pattern");
    }

    // Check 2: User agent analysis
    const uaScore = this.analyzeUserAgent(signals.userAgent);
    if (uaScore > 0) {
      score += uaScore;
      factors.push("Bot-like user agent");
    }

    // Check 3: Missing/suspicious headers
    const headerScore = this.analyzeHeaders(signals.headers);
    if (headerScore > 0) {
      score += headerScore;
      factors.push("Suspicious header pattern");
    }

    // Check 4: HTTP method anomalies
    if (this.isMethodAnomaly(signals.method, signals.path)) {
      score += 15;
      factors.push(`Unusual ${signals.method} request to ${signals.path}`);
    }

    // Check 5: Payload size anomalies
    if (signals.bodySize !== undefined && signals.bodySize > 10 * 1024 * 1024) {
      score += 10;
      factors.push("Extremely large payload");
    }

    score = Math.min(100, score);

    return {
      isBot: score >= 60,
      score: Math.round(score),
      factors,
      detectionMethod,
    };
  }

  /**
   * Detect scraping patterns
   */
  detectScrapingPattern(
    requests: RequestSignals[],
    windowMs: number = 60000
  ): {
    isScraping: boolean;
    confidence: number;
    indicators: string[];
  } {
    if (requests.length < 2) {
      return { isScraping: false, confidence: 0, indicators: [] };
    }

    const indicators: string[] = [];
    let confidence = 0;

    // Group by IP
    const requestsByIp = this.groupByIp(requests);

    for (const [ip, ipRequests] of Array.from(requestsByIp.entries())) {
      if (ipRequests.length < 5) continue;

      // Check 1: Sequential path access pattern
      const paths = ipRequests.map((r: RequestSignals) => r.path);
      const sequentialScore = this.detectSequentialAccess(paths);
      if (sequentialScore > 50) {
        confidence += 25;
        indicators.push(`IP ${ip.substring(0, 10)}... accessing sequential paths`);
      }

      // Check 2: High request velocity
      const timeWindow = ipRequests[ipRequests.length - 1].timestamp - ipRequests[0].timestamp;
      const velocity = ipRequests.length / (timeWindow / 1000);
      if (velocity > 10) {
        // >10 req/sec
        confidence += 30;
        indicators.push(`High velocity: ${velocity.toFixed(1)} requests/second`);
      }

      // Check 3: Consistent headers
      const headerConsistency = this.calculateHeaderConsistency(ipRequests);
      if (headerConsistency > 90) {
        confidence += 15;
        indicators.push("Highly consistent headers (bot-like)");
      }

      // Check 4: Uniform user agents
      const userAgents = new Set(ipRequests.map((r: RequestSignals) => r.userAgent));
      if (userAgents.size === 1 && ipRequests.length > 20) {
        confidence += 20;
        indicators.push("Single user agent for many requests");
      }

      // Check 5: No referer pattern
      const noRefererCount = ipRequests.filter((r: RequestSignals) => !r.headers.referer).length;
      if (noRefererCount === ipRequests.length && ipRequests.length > 10) {
        confidence += 15;
        indicators.push("No referer headers (direct requests)");
      }
    }

    confidence = Math.min(100, confidence);

    return {
      isScraping: confidence >= 60,
      confidence: Math.round(confidence),
      indicators: indicators.slice(0, 3),
    };
  }

  /**
   * Detect credential stuffing bot patterns
   */
  detectCredentialStuffingBot(
    attempts: RequestSignals[]
  ): {
    isCredentialStuffing: boolean;
    confidence: number;
    indicators: string[];
  } {
    const indicators: string[] = [];
    let confidence = 0;

    if (attempts.length < 5) {
      return { isCredentialStuffing: false, confidence: 0, indicators: [] };
    }

    // Check 1: High failure velocity (inferred from rapid POST to login)
    const loginAttempts = attempts.filter(a => a.path.includes("login") && a.method === "POST");
    if (loginAttempts.length > 10) {
      const timeWindow = loginAttempts[loginAttempts.length - 1].timestamp - loginAttempts[0].timestamp;
      const velocity = loginAttempts.length / (timeWindow / 1000);
      if (velocity > 1) {
        // >1 attempt/sec
        confidence += 35;
        indicators.push(`Rapid login attempts: ${velocity.toFixed(1)}/second`);
      }
    }

    // Check 2: Consistent headers (bot signature)
    const headerConsistency = this.calculateHeaderConsistency(attempts);
    if (headerConsistency > 85) {
      confidence += 25;
      indicators.push("Bot-consistent headers");
    }

    // Check 3: Consistent user agent
    const userAgents = new Set(attempts.map(a => a.userAgent));
    if (userAgents.size <= 2 && attempts.length > 20) {
      confidence += 20;
      indicators.push("Consistent user agent across attempts");
    }

    // Check 4: Systematic path probing
    const paths = attempts.map(a => a.path).filter(p => p.includes("login") || p.includes("admin"));
    if (paths.length === attempts.length && paths.length > 15) {
      confidence += 15;
      indicators.push("Systematic credential attack pattern");
    }

    // Check 5: No human delays
    const timings: number[] = [];
    for (let i = 1; i < attempts.length; i++) {
      timings.push(attempts[i].timestamp - attempts[i - 1].timestamp);
    }
    if (timings.length > 0) {
      const avgTiming = timings.reduce((a, b) => a + b) / timings.length;
      const variance = this.calculateVariance(timings);
      if (avgTiming < 500 && variance < 100000) {
        confidence += 20;
        indicators.push("Mechanical request timing");
      }
    }

    confidence = Math.min(100, confidence);

    return {
      isCredentialStuffing: confidence >= 65,
      confidence: Math.round(confidence),
      indicators: indicators.slice(0, 3),
    };
  }

  // Private helpers

  private analyzePath(path: string): number {
    let score = 0;
    for (const pattern of this.suspiciousPathPatterns) {
      if (pattern.test(path)) {
        score += 20;
      }
    }
    return Math.min(40, score);
  }

  private analyzeUserAgent(ua: string): number {
    let score = 0;

    // Generic user agent
    if (this.genericUserAgents.some(g => ua.toLowerCase() === g.toLowerCase())) {
      score += 25;
    }

    // Suspicious keywords
    for (const pattern of this.suspiciousUserAgents) {
      if (pattern.test(ua)) {
        score += 20;
        break;
      }
    }

    // Too short
    if (ua.length < 10) {
      score += 15;
    }

    return Math.min(50, score);
  }

  private analyzeHeaders(headers: Record<string, string | string[]>): number {
    let score = 0;

    // Missing common headers
    const requiredHeaders = ["accept", "accept-language", "accept-encoding"];
    for (const header of requiredHeaders) {
      if (!headers[header] && !headers[header.replace("-", "_")]) {
        score += 10;
      }
    }

    // Suspicious header patterns
    if (headers["user-agent"]?.toString().includes("bot")) {
      score += 15;
    }

    // Missing referer for GET requests
    if (!headers.referer && !headers.host) {
      score += 10;
    }

    return Math.min(40, score);
  }

  private isMethodAnomaly(method: string, path: string): boolean {
    // DELETE/PATCH on login endpoints is suspicious
    if ((method === "DELETE" || method === "PATCH") && path.includes("login")) {
      return true;
    }

    // HEAD on mutation endpoints
    if (method === "HEAD" && (path.includes("api") && !path.includes("health"))) {
      return true;
    }

    return false;
  }

  private groupByIp(requests: RequestSignals[]): Map<string, RequestSignals[]> {
    const grouped = new Map<string, RequestSignals[]>();
    for (const req of requests) {
      if (!grouped.has(req.ip)) {
        grouped.set(req.ip, []);
      }
      grouped.get(req.ip)!.push(req);
    }
    return grouped;
  }

  private detectSequentialAccess(paths: string[]): number {
    if (paths.length < 5) return 0;

    let score = 0;
    let sequenceLen = 1;

    for (let i = 1; i < paths.length; i++) {
      if (this.arePathsSequential(paths[i - 1], paths[i])) {
        sequenceLen++;
      } else {
        sequenceLen = 1;
      }

      if (sequenceLen >= 5) {
        score += 30;
        break;
      }
    }

    return Math.min(60, score);
  }

  private arePathsSequential(path1: string, path2: string): boolean {
    // Check for numeric patterns that increment
    const nums1 = path1.match(/\d+/g) || [];
    const nums2 = path2.match(/\d+/g) || [];

    if (nums1.length > 0 && nums2.length > 0) {
      const n1 = parseInt(nums1[nums1.length - 1]);
      const n2 = parseInt(nums2[nums2.length - 1]);
      if (n2 - n1 === 1 && path1.replace(/\d+/g, "X") === path2.replace(/\d+/g, "X")) {
        return true;
      }
    }

    return false;
  }

  private calculateHeaderConsistency(requests: RequestSignals[]): number {
    if (requests.length < 2) return 0;

    let consistent = 0;
    const baseHeaders = requests[0].headers;

    for (let i = 1; i < requests.length; i++) {
      const headers = requests[i].headers;
      let match = 0;
      let total = 0;

      for (const key in baseHeaders) {
        total++;
        if (headers[key] === baseHeaders[key]) {
          match++;
        }
      }

      if (total > 0) {
        consistent += (match / total) * 100;
      }
    }

    return Math.round(consistent / (requests.length - 1));
  }

  private calculateVariance(numbers: number[]): number {
    if (numbers.length === 0) return 0;
    const mean = numbers.reduce((a, b) => a + b, 0) / numbers.length;
    return numbers.reduce((a, b) => a + Math.pow(b - mean, 2), 0) / numbers.length;
  }
}

export const botDetector = new BotDetector();
