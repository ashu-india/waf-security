interface WafRule {
  id: string;
  name?: string;
  pattern: string;
  targetField: string;
  severity: string;
  category: string;
  enabled: boolean;
  description?: string;
}

interface RequestData {
  method: string;
  path: string;
  headers: Record<string, any>;
  body?: any;
  query?: any;
  clientIp?: string;
  tenantId?: string;
  enforcementMode?: "monitor" | "block";
}

interface RuleMatch {
  ruleId: string;
  ruleName: string;
  field: string;
  value: string;
  severity: string;
  category: string;
  description?: string;
  matchedPattern?: string;
  recommendation?: string;
}

interface AnalysisResult {
  action: "allow" | "block" | "challenge" | "throttle";
  score: number;
  matches: RuleMatch[];
  reason: string;
  processingTimeMs: number;
  riskLevel: string;
  breakdown: {
    patternScore: number;
    anomalyScore: number;
    reputationScore: number;
    mlScore?: number;
    combinedScore?: number;
    ddosScore?: number;
  };
  mlAnalysis?: {
    threatProbability: number;
    anomalyScore: number;
    confidence: number;
    topFactors: { factor: string; importance: number }[];
    reasoning: string[];
  };
  ddosDetection?: {
    detected: boolean;
    severity: "low" | "medium" | "high" | "critical";
    reason: string;
    volumetricScore: number;
  };
  explainability: {
    summary: string;
    details: string[];
    recommendations: string[];
  };
}

interface Thresholds {
  blockThreshold: number;
  challengeThreshold: number;
  monitorThreshold: number;
}

interface RateLimitEntry {
  count: number;
  firstRequest: number;
  lastRequest: number;
  paths: Set<string>;
  methods: Set<string>;
}

// Import modularized rules
import { OWASP_PATTERNS } from './rules/index';
import { GeolocationService } from '../services/geolocation';
import { ddosDetection } from './ddos-detection';

export { OWASP_PATTERNS };

const HEADER_ANOMALIES = [
  { header: 'user-agent', pattern: /^$/, score: 30, description: 'Missing User-Agent header' },
  { header: 'user-agent', pattern: /^.{0,10}$/, score: 20, description: 'Suspiciously short User-Agent' },
  { header: 'user-agent', pattern: /^.{500,}$/, score: 40, description: 'Excessively long User-Agent' },
  { header: 'host', pattern: /^$/, score: 50, description: 'Missing Host header' },
  { header: 'content-type', pattern: /multipart.*boundary.*boundary/i, score: 60, description: 'Multiple boundary parameters' },
];

class WafEngine {
  private customRules: WafRule[] = [];
  private rateLimitStore = new Map<string, RateLimitEntry>();
  private ipReputationCache = new Map<string, { score: number; lastUpdated: number }>();
  
  setCustomRules(rules: WafRule[]) {
    this.customRules = rules.filter(r => r.enabled);
  }

  /**
   * Get DDoS detection service
   */
  getDDoSDetection() {
    return ddosDetection;
  }
  
  private checkRateAnomaly(clientIp: string, request: RequestData, policy?: any): number {
    const now = Date.now();
    const windowMs = 60000;
    let entry = this.rateLimitStore.get(clientIp);
    
    if (!entry || now - entry.firstRequest > windowMs) {
      entry = {
        count: 1,
        firstRequest: now,
        lastRequest: now,
        paths: new Set([request.path]),
        methods: new Set([request.method])
      };
      this.rateLimitStore.set(clientIp, entry);
      return 0;
    }
    
    entry.count++;
    entry.lastRequest = now;
    entry.paths.add(request.path);
    entry.methods.add(request.method);
    
    let anomalyScore = 0;
    
    // Get country-specific rate limit if policy defines it
    let countryLimit = 100; // default
    if (policy?.geoRateLimitByCountry && request.clientIp) {
      try {
        const geo = GeolocationService.lookup(request.clientIp);
        if (geo?.country && policy.geoRateLimitByCountry[geo.country]) {
          countryLimit = policy.geoRateLimitByCountry[geo.country];
        }
      } catch (e) {
        // Ignore errors, use default limit
      }
    }
    
    // Apply rate limits (country-aware if configured)
    if (entry.count > countryLimit * 1.5) anomalyScore += 50;
    else if (entry.count > countryLimit) anomalyScore += 30;
    else if (entry.count > countryLimit * 0.8) anomalyScore += 15;
    
    if (entry.paths.size > 50) anomalyScore += 15;
    
    const avgInterval = (entry.lastRequest - entry.firstRequest) / entry.count;
    if (avgInterval < 50 && entry.count > 10) anomalyScore += 25;
    
    if (Math.random() < 0.01) {
      const entries = Array.from(this.rateLimitStore.entries());
      for (const [ip, e] of entries) {
        if (now - e.lastRequest > windowMs * 2) {
          this.rateLimitStore.delete(ip);
        }
      }
    }
    
    return Math.min(anomalyScore, 50);
  }
  
  private checkHeaderAnomalies(headers: Record<string, any>): { score: number; issues: string[] } {
    let score = 0;
    const issues: string[] = [];
    
    for (const check of HEADER_ANOMALIES) {
      const headerValue = headers[check.header] || '';
      if (check.pattern.test(headerValue)) {
        score += check.score;
        issues.push(check.description);
      }
    }
    
    const headerCount = Object.keys(headers).length;
    if (headerCount < 3) {
      score += 20;
      issues.push('Minimal headers (potential automated request)');
    }
    
    return { score: Math.min(score, 40), issues };
  }
  
  private getIpReputation(clientIp: string): number {
    const cached = this.ipReputationCache.get(clientIp);
    if (cached && Date.now() - cached.lastUpdated < 300000) {
      return cached.score;
    }
    return 0;
  }
  
  updateIpReputation(clientIp: string, wasBlocked: boolean) {
    const cached = this.ipReputationCache.get(clientIp) || { score: 0, lastUpdated: 0 };
    cached.score = Math.min(100, cached.score + (wasBlocked ? 10 : -1));
    cached.lastUpdated = Date.now();
    this.ipReputationCache.set(clientIp, cached);
    
    if (this.ipReputationCache.size > 10000) {
      const entries = Array.from(this.ipReputationCache.entries())
        .sort((a, b) => a[1].lastUpdated - b[1].lastUpdated);
      entries.slice(0, 5000).forEach(([ip]) => this.ipReputationCache.delete(ip));
    }
  }
  
  private extractStrings(obj: unknown, maxDepth = 5, depth = 0): string[] {
    if (depth > maxDepth) return [];
    if (obj === null || obj === undefined) return [];
    
    if (typeof obj === 'string') return [obj];
    if (typeof obj === 'number' || typeof obj === 'boolean') return [String(obj)];
    
    if (Array.isArray(obj)) {
      const results: string[] = [];
      for (let i = 0; i < Math.min(obj.length, 100); i++) {
        results.push(...this.extractStrings(obj[i], maxDepth, depth + 1));
      }
      return results;
    }
    
    if (typeof obj === 'object') {
      const results: string[] = [];
      const keys = Object.keys(obj as Record<string, unknown>);
      for (let i = 0; i < Math.min(keys.length, 100); i++) {
        const key = keys[i];
        results.push(key);
        results.push(...this.extractStrings((obj as Record<string, unknown>)[key], maxDepth, depth + 1));
      }
      return results;
    }
    
    return [];
  }
  
  analyzeRequest(request: RequestData, thresholds: Thresholds, policy?: any, skipDDoS: boolean = false): AnalysisResult {
    const startTime = Date.now();
    const matches: RuleMatch[] = [];
    let patternScore = 0;
    const details: string[] = [];
    const recommendations: string[] = [];
    
    // ===== GEO-LOCATION CHECK (HIGHEST PRIORITY - BEFORE ALL OTHER CHECKS) =====
    if (request.clientIp && policy) {
      // Check blocked countries (ALWAYS highest priority)
      if (policy.blockedCountries?.length) {
        const geoCheck = GeolocationService.checkGeoRestriction(
          request.clientIp,
          undefined,
          policy.blockedCountries
        );
        if (!geoCheck.allowed) {
          return {
            action: 'block',
            score: 100,
            matches: [{
              ruleId: 'geo-blocked-country',
              ruleName: 'Geo-Location: Blocked Country',
              field: 'clientIp',
              value: request.clientIp,
              severity: 'critical',
              category: 'Geo-Location',
              description: geoCheck.reason || 'Request from blocked country',
              matchedPattern: geoCheck.country || 'unknown'
            }],
            reason: geoCheck.reason || `Country blocked by policy`,
            processingTimeMs: Date.now() - startTime,
            riskLevel: 'critical',
            breakdown: {
              patternScore: 0,
              anomalyScore: 0,
              reputationScore: 0,
              combinedScore: 100
            },
            explainability: {
              summary: `Request blocked: ${geoCheck.reason}`,
              details: [geoCheck.reason || 'Country not allowed'],
              recommendations: ['Request from blocked geography. Contact support if this is incorrect.']
            }
          };
        }
      }
      
      // Check allowed countries (whitelist mode if specified)
      if (policy.allowedCountries?.length) {
        const geoCheck = GeolocationService.checkGeoRestriction(
          request.clientIp,
          policy.allowedCountries,
          undefined
        );
        if (!geoCheck.allowed) {
          return {
            action: 'block',
            score: 100,
            matches: [{
              ruleId: 'geo-not-allowed-country',
              ruleName: 'Geo-Location: Not in Allowed List',
              field: 'clientIp',
              value: request.clientIp,
              severity: 'critical',
              category: 'Geo-Location',
              description: geoCheck.reason || 'Request from country not in allowed list',
              matchedPattern: geoCheck.country || 'unknown'
            }],
            reason: geoCheck.reason || `Country not in allowed list`,
            processingTimeMs: Date.now() - startTime,
            riskLevel: 'critical',
            breakdown: {
              patternScore: 0,
              anomalyScore: 0,
              reputationScore: 0,
              combinedScore: 100
            },
            explainability: {
              summary: `Request blocked: ${geoCheck.reason}`,
              details: [geoCheck.reason || 'Country not allowed'],
              recommendations: ['Request from non-whitelisted country. Contact support if this is incorrect.']
            }
          };
        }
      }
      
      // Check VPN detection
      if (policy.vpnDetectionEnabled) {
        const isVPN = GeolocationService.checkVPN(request.clientIp);
        if (isVPN) {
          const vpnAction = policy.vpnBlockAction || 'monitor';
          
          if (vpnAction === 'block') {
            return {
              action: 'block',
              score: 100,
              matches: [{
                ruleId: 'geo-vpn-blocked',
                ruleName: 'Geo-Location: VPN Detected & Blocked',
                field: 'clientIp',
                value: request.clientIp,
                severity: 'high',
                category: 'Geo-Location',
                description: 'VPN/Proxy detected and blocked by policy',
                matchedPattern: 'VPN'
              }],
              reason: 'Request from VPN/proxy blocked by policy',
              processingTimeMs: Date.now() - startTime,
              riskLevel: 'high',
              breakdown: {
                patternScore: 0,
                anomalyScore: 0,
                reputationScore: 0,
                combinedScore: 100
              },
              explainability: {
                summary: 'VPN/Proxy detected and blocked',
                details: ['Request originates from cloud provider/VPN network'],
                recommendations: ['Disable VPN/Proxy to access this service']
              }
            };
          } else if (vpnAction === 'challenge') {
            return {
              action: 'challenge',
              score: 70,
              matches: [{
                ruleId: 'geo-vpn-challenged',
                ruleName: 'Geo-Location: VPN Detected & Challenged',
                field: 'clientIp',
                value: request.clientIp,
                severity: 'medium',
                category: 'Geo-Location',
                description: 'VPN/Proxy detected - challenge required',
                matchedPattern: 'VPN'
              }],
              reason: 'VPN detected - verification required',
              processingTimeMs: Date.now() - startTime,
              riskLevel: 'medium',
              breakdown: {
                patternScore: 0,
                anomalyScore: 0,
                reputationScore: 0,
                combinedScore: 70
              },
              explainability: {
                summary: 'VPN/Proxy detected - please verify',
                details: ['Request originates from cloud provider/VPN network'],
                recommendations: ['Complete CAPTCHA verification to proceed']
              }
            };
          }
          // monitor: continue with normal analysis, but log it
          details.push('VPN/Proxy detected (monitoring only)');
        }
      }
    }
    
    const pathContent = request.path || '';
    const queryStrings = this.extractStrings(request.query);
    const bodyStrings = typeof request.body === 'string' 
      ? [request.body] 
      : this.extractStrings(request.body);
    const headerStrings = this.extractStrings(request.headers);
    
    const searchableContent = {
      path: pathContent,
      query: queryStrings.join(' '),
      body: bodyStrings.join(' '),
      headers: headerStrings.join(' '),
      request: [pathContent, ...queryStrings, ...bodyStrings].join(' ')
    };
    
    const maxContentLength = 50000;
    for (const key of Object.keys(searchableContent) as (keyof typeof searchableContent)[]) {
      if (searchableContent[key].length > maxContentLength) {
        searchableContent[key] = searchableContent[key].substring(0, maxContentLength);
      }
    }
    
    // Load patterns: only enabled OWASP patterns + custom rules
    const allPatterns = OWASP_PATTERNS.filter(p => {
      // Check if built-in rule is enabled in customRules
      const customRule = this.customRules.find(r => r.id === p.id);
      if (customRule) return customRule.enabled;
      return true; // Default: include if no override
    });
    
    for (const custom of this.customRules) {
      allPatterns.push({
        id: custom.id,
        name: custom.name || custom.id,
        pattern: new RegExp(custom.pattern, 'i'),
        field: custom.targetField,
        severity: custom.severity,
        score: custom.severity === 'critical' ? 90 : custom.severity === 'high' ? 75 : custom.severity === 'medium' ? 50 : 25,
        category: custom.category,
        description: custom.description || `Custom rule: ${custom.name || custom.id}`,
        recommendation: 'Review custom rule configuration'
      } as any);
    }
    
    for (const rule of allPatterns) {
      const targetContent = searchableContent[rule.field as keyof typeof searchableContent] || searchableContent.request;
      const regex = rule.pattern instanceof RegExp ? rule.pattern : new RegExp(rule.pattern, 'i');
      
      const match = regex.exec(targetContent);
      if (match) {
        patternScore += rule.score;
        
        const matchContext = targetContent.substring(
          Math.max(0, match.index - 20),
          Math.min(targetContent.length, match.index + match[0].length + 20)
        );
        
        matches.push({
          ruleId: rule.id,
          ruleName: rule.name,
          field: rule.field,
          value: matchContext.substring(0, 100),
          severity: rule.severity,
          category: rule.category,
          description: rule.description,
          matchedPattern: match[0].substring(0, 50),
          recommendation: rule.recommendation
        });
        
        details.push(`${rule.name}: ${rule.description}`);
        if (rule.recommendation && !recommendations.includes(rule.recommendation)) {
          recommendations.push(rule.recommendation);
        }
      }
    }
    
    patternScore = Math.min(100, patternScore);
    
    // Check DDoS detection first (tenant-scoped)
    let ddosResult: any = null;
    if (!skipDDoS && request.clientIp && request.tenantId) {
      ddosResult = ddosDetection.analyzeRequest(
        request.tenantId,
        request.clientIp,
        request.method,
        request.path,
        request.headers || {},
        JSON.stringify(request.body || '').length
      );
      ddosDetection.trackRequest(request.tenantId, request.clientIp);
    }

    // If DDoS detected with high/critical severity, escalate action
    if (ddosResult?.isDDoSDetected && (ddosResult.severity === 'high' || ddosResult.severity === 'critical')) {
      const ddosAction = ddosResult.action === 'block' ? 'block' : ddosResult.action === 'challenge' ? 'challenge' : 'throttle';
      
      return {
        action: ddosAction as any,
        score: ddosResult.severity === 'critical' ? 100 : 85,
        matches: [],
        reason: ddosResult.reason,
        processingTimeMs: Date.now() - startTime,
        riskLevel: 'critical',
        breakdown: {
          patternScore: 0,
          anomalyScore: 0,
          reputationScore: 0,
          ddosScore: ddosResult.severity === 'critical' ? 100 : 85,
        },
        ddosDetection: {
          detected: true,
          severity: ddosResult.severity,
          reason: ddosResult.reason,
          volumetricScore: request.tenantId ? ddosDetection.getTenantMetrics(request.tenantId).volumetricScore : 0,
        },
        explainability: {
          summary: `DDoS Attack Detected - ${ddosResult.severity.toUpperCase()} SEVERITY`,
          details: [ddosResult.reason],
          recommendations: [
            'Traffic from this IP has been rate-limited',
            'Multiple sources detected attacking the service',
            'Complete CAPTCHA verification to proceed',
          ],
        },
      };
    }

    const rateAnomaly = request.clientIp ? this.checkRateAnomaly(request.clientIp, request, policy) : 0;
    const headerCheck = this.checkHeaderAnomalies(request.headers || {});
    const reputationScore = request.clientIp ? this.getIpReputation(request.clientIp) : 0;
    
    if (rateAnomaly > 0) {
      details.push(`Rate anomaly detected (score: ${rateAnomaly})`);
    }
    headerCheck.issues.forEach(issue => details.push(`Header: ${issue}`));
    if (reputationScore > 0) {
      details.push(`IP has negative reputation history (score: ${reputationScore})`);
    }
    
    const anomalyScore = Math.min(30, (rateAnomaly + headerCheck.score) / 2);
    
    // ===== ML SCORING INTEGRATION =====
    let mlScore = 0;
    let mlAnalysis: AnalysisResult['mlAnalysis'] | undefined;
    let totalScore = Math.min(100, patternScore * 0.7 + anomalyScore * 0.2 + reputationScore * 0.1);
    
    try {
      // Import ML engine dynamically to avoid circular dependencies
      const { mlEngine } = require('./ml-integration');
      
      // Extract base features for ML
      const baseFeatures = mlEngine.extractFeatures({
        method: request.method,
        path: request.path,
        headers: request.headers || {},
        body: request.body,
        query: request.query,
        clientIp: request.clientIp,
      });
      
      // Calculate ML score
      const mlPrediction = mlEngine.calculateMLScore(baseFeatures);
      mlScore = mlPrediction.anomalyScore;
      
      // Combine pattern score with ML score (60% pattern + 40% ML)
      totalScore = mlEngine.combinedScore(patternScore, mlPrediction);
      
      // Include ML analysis in output
      mlAnalysis = {
        threatProbability: mlPrediction.threatProbability,
        anomalyScore: mlPrediction.anomalyScore,
        confidence: mlPrediction.confidence,
        topFactors: mlPrediction.topFactors,
        reasoning: mlPrediction.reasoning,
      };
      
      // Record decision for ML training
      const action = totalScore >= 70 ? 'block' : totalScore >= 50 ? 'challenge' : 'allow';
      mlEngine.recordDecision(
        baseFeatures,
        patternScore,
        mlScore,
        totalScore,
        action,
        request.clientIp || 'unknown'
      );
      
      details.push(`ML Score: ${Math.round(mlScore)} | Threat Probability: ${(mlPrediction.threatProbability * 100).toFixed(1)}%`);
    } catch (mlError) {
      console.warn('ML scoring failed, using pattern-only scoring:', mlError);
      // Fall back to pattern-only scoring - totalScore already calculated above
    }
    
    let action: AnalysisResult['action'] = 'allow';
    let reason = 'Request passed all security checks';
    let riskLevel = 'low';
    
    // ENFORCEMENT MODE CHECK: Respect monitor/log-only modes (always allow, just log)
    if (request.enforcementMode === 'monitor') {
      // Monitor mode: ALWAYS allow, just log threats
      if (totalScore >= thresholds.monitorThreshold) {
        reason = `Threat score ${Math.round(totalScore)} flagged for monitoring`;
        if (totalScore >= thresholds.blockThreshold) {
          riskLevel = 'critical';
        } else if (totalScore >= thresholds.challengeThreshold) {
          riskLevel = 'high';
        } else {
          riskLevel = 'medium';
        }
      } else {
        reason = 'Request passed all security checks';
        riskLevel = 'low';
      }
      action = 'allow'; // Monitor mode: never block, only allow
    } else {
      // ENFORCE mode: Use standard thresholds (block, challenge, monitor)
      if (totalScore >= thresholds.blockThreshold) {
        action = 'block';
        reason = `Threat score ${Math.round(totalScore)} exceeded block threshold`;
        riskLevel = 'critical';
        if (request.clientIp) {
          this.updateIpReputation(request.clientIp, true);
        }
      } else if (totalScore >= thresholds.challengeThreshold) {
        action = 'challenge';
        reason = `Threat score ${Math.round(totalScore)} requires verification`;
        riskLevel = 'high';
      } else if (totalScore >= thresholds.monitorThreshold) {
        reason = `Threat score ${Math.round(totalScore)} flagged for monitoring`;
        riskLevel = 'medium';
      } else if (request.clientIp) {
        this.updateIpReputation(request.clientIp, false);
      }
    }
    
    let summary = '';
    if (matches.length === 0) {
      summary = 'No security threats detected in this request.';
    } else if (matches.length === 1) {
      summary = `Detected 1 potential security issue: ${matches[0].ruleName}`;
    } else {
      const categories = Array.from(new Set(matches.map(m => m.category)));
      summary = `Detected ${matches.length} security issues across ${categories.length} categories: ${categories.join(', ')}`;
    }
    
    return {
      action,
      score: Math.round(totalScore),
      matches,
      reason,
      processingTimeMs: Date.now() - startTime,
      riskLevel,
      breakdown: {
        patternScore: Math.round(patternScore),
        anomalyScore: Math.round(anomalyScore),
        reputationScore: Math.round(reputationScore),
        mlScore: Math.round(mlScore),
        combinedScore: Math.round(totalScore)
      },
      mlAnalysis,
      explainability: {
        summary,
        details,
        recommendations: recommendations.length > 0 ? recommendations : ['Continue monitoring for suspicious activity']
      }
    };
  }
  
  getStats() {
    return {
      activeIps: this.rateLimitStore.size,
      reputationEntries: this.ipReputationCache.size,
      customRulesLoaded: this.customRules.length,
      totalPatterns: OWASP_PATTERNS.length + this.customRules.length
    };
  }
}

export const wafEngine = new WafEngine();
