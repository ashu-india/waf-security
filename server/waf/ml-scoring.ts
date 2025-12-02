/**
 * Machine Learning-Ready Scoring System for WAF
 * 
 * This module provides:
 * - Feature extraction from HTTP requests
 * - ML model integration interface
 * - Advanced threat scoring with ML predictions
 * - Feature engineering for anomaly detection
 * - Historical data collection for training
 * - Ensemble scoring combining pattern + ML
 */

interface RequestFeatures {
  // Structural features
  pathLength: number;
  queryLength: number;
  bodyLength: number;
  headerCount: number;
  
  // Behavioral features
  httpMethod: string;
  hasQueryString: boolean;
  hasBody: boolean;
  hasAuthHeader: boolean;
  hasUserAgent: boolean;
  
  // Content features
  specialCharDensity: number; // 0-1
  numberDensity: number; // 0-1
  upperCaseDensity: number; // 0-1
  urlEncodingDensity: number; // 0-1
  sqlKeywordCount: number;
  jsKeywordCount: number;
  shellCommandCount: number;
  pathTraversalCount: number;
  
  // Request pattern features
  ratioPathToQuery: number;
  ratioBodyToPath: number;
  entropyScore: number; // Shannon entropy
  
  // Network features
  clientIpReputation: number; // 0-100
  isPrivateIp: boolean;
  isKnownGoodIp: boolean;
  
  // Temporal features (if available)
  timeOfDay?: number; // 0-23
  dayOfWeek?: number; // 0-6
  requestFrequency?: number; // requests per minute
}

interface MLPrediction {
  threatProbability: number; // 0-1 (likelihood of attack)
  anomalyScore: number; // 0-100 (deviation from normal)
  confidence: number; // 0-1 (model confidence in prediction)
  reasoning: string[];
  topFactors: { factor: string; importance: number }[];
}

interface ScoringRecord {
  timestamp: number;
  features: RequestFeatures;
  patternScore: number;
  mlScore?: number;
  finalScore: number;
  action: 'allow' | 'block' | 'challenge';
  wasCorrect?: boolean; // For training feedback
  clientIp: string;
  threatType?: string; // Inferred threat category
}

export class MLScoringEngine {
  private featureCache = new Map<string, RequestFeatures>();
  private scoringHistory: ScoringRecord[] = [];
  private modelWeights = {
    patternWeight: 0.6,
    mlWeight: 0.4,
  };
  private mlModel: MLModel | null = null;
  
  constructor() {
    this.initializeDefaults();
  }
  
  private initializeDefaults() {
    // Default weights can be updated via ML training
    this.modelWeights = {
      patternWeight: 0.6,
      mlWeight: 0.4,
    };
  }
  
  /**
   * Extract ML-ready features from HTTP request
   */
  extractFeatures(requestData: {
    method: string;
    path: string;
    headers: Record<string, any>;
    body?: any;
    query?: any;
    clientIp?: string;
  }): RequestFeatures {
    const cacheKey = `${requestData.method}:${requestData.path}:${requestData.clientIp || 'unknown'}`;
    const cached = this.featureCache.get(cacheKey);
    if (cached && this.featureCache.size < 1000) {
      return cached;
    }

    const pathStr = requestData.path || '';
    const queryStr = JSON.stringify(requestData.query || {});
    const bodyStr = typeof requestData.body === 'string' 
      ? requestData.body 
      : JSON.stringify(requestData.body || {});
    const headerStr = JSON.stringify(requestData.headers || {});
    
    const combinedContent = pathStr + queryStr + bodyStr + headerStr;
    
    // Structural features
    const features: RequestFeatures = {
      pathLength: pathStr.length,
      queryLength: queryStr.length,
      bodyLength: bodyStr.length,
      headerCount: Object.keys(requestData.headers || {}).length,
      
      // Behavioral
      httpMethod: requestData.method.toUpperCase(),
      hasQueryString: queryStr.length > 2,
      hasBody: bodyStr.length > 2,
      hasAuthHeader: !!requestData.headers?.authorization || !!requestData.headers?.Authorization,
      hasUserAgent: !!requestData.headers?.['user-agent'] || !!requestData.headers?.['User-Agent'],
      
      // Content features
      specialCharDensity: this.calculateDensity(combinedContent, /[!@#$%^&*()_+=\[\]{};:'",.<>?\/\\|-]/g),
      numberDensity: this.calculateDensity(combinedContent, /[0-9]/g),
      upperCaseDensity: this.calculateDensity(combinedContent, /[A-Z]/g),
      urlEncodingDensity: this.calculateDensity(combinedContent, /%[0-9A-Fa-f]{2}/g),
      
      // Keyword counts
      sqlKeywordCount: this.countKeywords(combinedContent, ['UNION', 'SELECT', 'INSERT', 'DROP', 'DELETE', 'OR', 'AND', 'EXEC']),
      jsKeywordCount: this.countKeywords(combinedContent, ['<script', 'eval', 'setTimeout', 'setInterval', 'onerror', 'onload']),
      shellCommandCount: this.countKeywords(combinedContent, ['bash', 'sh', 'cmd', 'powershell', '&>', '|', ';']),
      pathTraversalCount: this.countKeywords(combinedContent, ['../../../', '..\\..\\', '%2e%2e', 'null byte']),
      
      // Ratios
      ratioPathToQuery: queryStr.length > 0 ? pathStr.length / queryStr.length : 0,
      ratioBodyToPath: pathStr.length > 0 ? bodyStr.length / pathStr.length : 0,
      entropyScore: this.calculateEntropy(combinedContent),
      
      // Network
      clientIpReputation: this.getIpReputation(requestData.clientIp),
      isPrivateIp: this.isPrivateAddress(requestData.clientIp),
      isKnownGoodIp: this.isKnownGood(requestData.clientIp),
    };
    
    this.featureCache.set(cacheKey, features);
    if (this.featureCache.size > 5000) {
      const firstKey = this.featureCache.keys().next().value as string;
      if (firstKey) this.featureCache.delete(firstKey);
    }
    
    return features;
  }
  
  /**
   * Calculate ML-based threat score
   */
  calculateMLScore(features: RequestFeatures): MLPrediction {
    // This will be replaced with actual ML model when available
    if (this.mlModel) {
      return this.mlModel.predict(features);
    }
    
    // Heuristic scoring (baseline, before ML model)
    return this.heuristicScore(features);
  }
  
  /**
   * Heuristic scoring as fallback/baseline
   */
  private heuristicScore(features: RequestFeatures): MLPrediction {
    let threatScore = 0;
    const factors: { factor: string; importance: number }[] = [];
    
    // SQL Injection indicators
    if (features.sqlKeywordCount > 2) {
      threatScore += 25;
      factors.push({ factor: 'SQL Keywords Detected', importance: features.sqlKeywordCount });
    }
    
    // XSS indicators
    if (features.jsKeywordCount > 1) {
      threatScore += 20;
      factors.push({ factor: 'JavaScript/XSS Keywords', importance: features.jsKeywordCount });
    }
    
    // Command Injection indicators
    if (features.shellCommandCount > 1) {
      threatScore += 30;
      factors.push({ factor: 'Shell Commands Detected', importance: features.shellCommandCount });
    }
    
    // Path Traversal indicators
    if (features.pathTraversalCount > 0) {
      threatScore += 25;
      factors.push({ factor: 'Path Traversal Attempts', importance: features.pathTraversalCount });
    }
    
    // Content anomalies
    if (features.specialCharDensity > 0.3) {
      threatScore += 10;
      factors.push({ factor: 'High Special Character Density', importance: features.specialCharDensity });
    }
    
    if (features.urlEncodingDensity > 0.15) {
      threatScore += 15;
      factors.push({ factor: 'High URL Encoding Density', importance: features.urlEncodingDensity });
    }
    
    // Entropy-based anomaly
    if (features.entropyScore > 4.5) {
      threatScore += 12;
      factors.push({ factor: 'High Content Entropy', importance: features.entropyScore / 10 });
    }
    
    // IP Reputation
    if (features.clientIpReputation > 50) {
      threatScore += features.clientIpReputation * 0.2;
      factors.push({ factor: 'IP Reputation Score', importance: features.clientIpReputation / 100 });
    }
    
    // Request structure anomalies
    if (features.ratioBodyToPath > 10) {
      threatScore += 8;
      factors.push({ factor: 'Unusual Body-to-Path Ratio', importance: Math.min(1, features.ratioBodyToPath / 50) });
    }
    
    // Normalize to 0-100
    threatScore = Math.min(100, threatScore);
    
    return {
      threatProbability: threatScore / 100,
      anomalyScore: threatScore,
      confidence: this.calculateConfidence(factors.length),
      reasoning: [
        `Detected ${features.sqlKeywordCount} SQL keywords`,
        `Detected ${features.jsKeywordCount} JavaScript keywords`,
        `Detected ${features.shellCommandCount} shell commands`,
        `Special char density: ${(features.specialCharDensity * 100).toFixed(1)}%`,
        `Entropy score: ${features.entropyScore.toFixed(2)}`,
        `Content length: ${features.pathLength + features.queryLength + features.bodyLength} bytes`,
      ].filter(r => r),
      topFactors: factors.sort((a, b) => b.importance - a.importance).slice(0, 5),
    };
  }
  
  /**
   * Combine pattern-based and ML scores
   */
  combinedScore(patternScore: number, mlPrediction: MLPrediction): number {
    const normalizedPattern = patternScore / 100;
    const weights = this.modelWeights;
    
    return Math.min(100, 
      (normalizedPattern * weights.patternWeight + 
       mlPrediction.anomalyScore * weights.mlWeight / 100) * 100
    );
  }
  
  /**
   * Record scoring decision for ML training
   */
  recordDecision(
    features: RequestFeatures,
    patternScore: number,
    mlScore: number,
    finalScore: number,
    action: 'allow' | 'block' | 'challenge',
    clientIp: string
  ): void {
    this.scoringHistory.push({
      timestamp: Date.now(),
      features,
      patternScore,
      mlScore,
      finalScore,
      action,
      clientIp,
    });
    
    // Keep only recent history (last 10,000 decisions)
    if (this.scoringHistory.length > 10000) {
      this.scoringHistory = this.scoringHistory.slice(-10000);
    }
  }
  
  /**
   * Get training data for ML model
   */
  getTrainingData() {
    return this.scoringHistory.map(record => ({
      features: record.features,
      label: record.action === 'block' ? 1 : 0, // Binary: attack or not
      score: record.finalScore,
      timestamp: record.timestamp,
    }));
  }
  
  /**
   * Update model weights based on feedback
   */
  updateWeights(newWeights: { patternWeight: number; mlWeight: number }): void {
    const total = newWeights.patternWeight + newWeights.mlWeight;
    this.modelWeights = {
      patternWeight: newWeights.patternWeight / total,
      mlWeight: newWeights.mlWeight / total,
    };
  }
  
  /**
   * Register ML model
   */
  registerModel(model: MLModel): void {
    this.mlModel = model;
  }
  
  // Helper methods
  private calculateDensity(text: string, pattern: RegExp): number {
    if (!text) return 0;
    const matches = text.match(pattern) || [];
    return matches.length / Math.max(text.length, 1);
  }
  
  private countKeywords(text: string, keywords: string[]): number {
    const upperText = text.toUpperCase();
    return keywords.filter(kw => upperText.includes(kw.toUpperCase())).length;
  }
  
  private calculateEntropy(text: string): number {
    if (!text) return 0;
    const freq: Record<string, number> = {};
    for (const char of text) {
      freq[char] = (freq[char] || 0) + 1;
    }
    
    let entropy = 0;
    const len = text.length;
    for (const count of Object.values(freq)) {
      const p = count / len;
      entropy -= p * Math.log2(p);
    }
    return entropy;
  }
  
  private getIpReputation(ip?: string): number {
    if (!ip) return 0;
    // This would connect to reputation DB in production
    // For now, return mock data
    return 0;
  }
  
  private isPrivateAddress(ip?: string): boolean {
    if (!ip) return false;
    return /^(10\.|172\.1[6-9]\.|172\.2[0-9]\.|172\.3[01]\.|192\.168\.)/.test(ip);
  }
  
  private isKnownGood(ip?: string): boolean {
    // Whitelist of trusted IPs
    const whitelist = ['127.0.0.1', 'localhost'];
    return whitelist.includes(ip || '');
  }
  
  private calculateConfidence(factorCount: number): number {
    return Math.min(1, 0.5 + (factorCount * 0.1));
  }
}

/**
 * ML Model Interface
 * Implement this interface to provide custom ML models
 */
export interface MLModel {
  name: string;
  version: string;
  predict(features: RequestFeatures): MLPrediction;
  train?(data: { features: RequestFeatures; label: number }[]): void;
  evaluate?(testData: { features: RequestFeatures; label: number }[]): { accuracy: number; precision: number; recall: number };
}

/**
 * Example implementation: Simple Linear Model
 */
export class SimpleLinearModel implements MLModel {
  name = 'SimpleLinear';
  version = '1.0';
  private weights: Record<string, number> = {};
  
  predict(features: RequestFeatures): MLPrediction {
    let score = 0;
    const factors: { factor: string; importance: number }[] = [];
    
    // Feature weights (would be learned during training)
    const featureWeights = {
      sqlKeywordCount: 15,
      jsKeywordCount: 12,
      shellCommandCount: 18,
      pathTraversalCount: 20,
      specialCharDensity: 8,
      urlEncodingDensity: 10,
      entropyScore: 5,
      clientIpReputation: 3,
    };
    
    for (const [featureName, weight] of Object.entries(featureWeights)) {
      const value = (features as any)[featureName] || 0;
      const contribution = value * weight;
      score += contribution;
      if (contribution > 0) {
        factors.push({ factor: featureName, importance: contribution / 100 });
      }
    }
    
    score = Math.min(100, score);
    
    return {
      threatProbability: score / 100,
      anomalyScore: score,
      confidence: Math.min(1, 0.7 + (factors.length * 0.05)),
      reasoning: [`Linear model score: ${score.toFixed(2)}`],
      topFactors: factors.sort((a, b) => b.importance - a.importance).slice(0, 5),
    };
  }
}

export { RequestFeatures, MLPrediction, ScoringRecord };
