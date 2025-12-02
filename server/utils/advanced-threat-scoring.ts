/**
 * Advanced Threat Scoring
 * Combines ML, behavioral analysis, and bot detection
 */

export interface ThreatScoringInput {
  patternScore: number; // 0-100
  anomalyScore: number; // 0-100
  reputationScore: number; // 0-100
  botScore: number; // 0-100
  behavioralScore: number; // 0-100
  geoAnomaly: number; // 0-100
  velocityAnomaly: number; // 0-100
  credentialStuffingIndicators: number; // 0-100
}

export interface EnhancedThreatAnalysis {
  finalScore: number;
  riskLevel: "low" | "medium" | "high" | "critical";
  recommendation: "allow" | "challenge" | "block";
  factors: string[];
  weightBreakdown: Record<string, { weight: number; value: number; contribution: number }>;
  mlConfidence: number;
  suggestedAction: string;
}

export class AdvancedThreatScorer {
  /**
   * Calculate enhanced threat score using multiple signals
   */
  calculateThreat(input: ThreatScoringInput): EnhancedThreatAnalysis {
    // Adaptive weights based on signal reliability
    const weights = {
      pattern: 0.30, // OWASP patterns
      anomaly: 0.15, // Request anomalies
      reputation: 0.10, // IP reputation
      bot: 0.20, // Bot detection
      behavioral: 0.15, // Login/behavioral
      geo: 0.05, // Geolocation
      velocity: 0.03, // Request velocity
      stuffing: 0.02, // Credential stuffing indicators
    };

    // Normalize scores
    const normalized = {
      pattern: Math.min(100, input.patternScore),
      anomaly: Math.min(100, input.anomalyScore),
      reputation: Math.min(100, input.reputationScore),
      bot: Math.min(100, input.botScore),
      behavioral: Math.min(100, input.behavioralScore),
      geo: Math.min(100, input.geoAnomaly),
      velocity: Math.min(100, input.velocityAnomaly),
      stuffing: Math.min(100, input.credentialStuffingIndicators),
    };

    // Calculate contributions
    const contributions = {
      pattern: normalized.pattern * weights.pattern,
      anomaly: normalized.anomaly * weights.anomaly,
      reputation: normalized.reputation * weights.reputation,
      bot: normalized.bot * weights.bot,
      behavioral: normalized.behavioral * weights.behavioral,
      geo: normalized.geo * weights.geo,
      velocity: normalized.velocity * weights.velocity,
      stuffing: normalized.stuffing * weights.stuffing,
    };

    // Final score with bias toward detected threats
    const baseScore = Object.values(contributions).reduce((a, b) => a + b, 0);

    // Apply threat amplification for critical signals
    let finalScore = baseScore;

    // If bot detected + credential stuffing indicators, increase significantly
    if (input.botScore > 60 && input.credentialStuffingIndicators > 50) {
      finalScore = Math.min(100, finalScore * 1.3);
    }

    // If pattern + anomaly both high, increase
    if (input.patternScore > 50 && input.anomalyScore > 40) {
      finalScore = Math.min(100, finalScore * 1.15);
    }

    // Determine risk level and recommendation
    const riskLevel = this.determineRiskLevel(finalScore, input);
    const recommendation = this.getRecommendation(riskLevel, input);
    const factors = this.identifyFactors(input);
    const mlConfidence = this.calculateConfidence(input);
    const suggestedAction = this.suggestAction(riskLevel, factors);

    return {
      finalScore: Math.round(finalScore),
      riskLevel,
      recommendation,
      factors,
      weightBreakdown: {
        pattern: { weight: weights.pattern, value: normalized.pattern, contribution: contributions.pattern },
        anomaly: { weight: weights.anomaly, value: normalized.anomaly, contribution: contributions.anomaly },
        reputation: { weight: weights.reputation, value: normalized.reputation, contribution: contributions.reputation },
        bot: { weight: weights.bot, value: normalized.bot, contribution: contributions.bot },
        behavioral: { weight: weights.behavioral, value: normalized.behavioral, contribution: contributions.behavioral },
        geo: { weight: weights.geo, value: normalized.geo, contribution: contributions.geo },
        velocity: { weight: weights.velocity, value: normalized.velocity, contribution: contributions.velocity },
        stuffing: { weight: weights.stuffing, value: normalized.stuffing, contribution: contributions.stuffing },
      },
      mlConfidence: Math.round(mlConfidence),
      suggestedAction,
    };
  }

  /**
   * Determine risk level with contextual analysis
   */
  private determineRiskLevel(
    score: number,
    input: ThreatScoringInput
  ): "low" | "medium" | "high" | "critical" {
    // Context-aware thresholds
    if (score >= 80) {
      return "critical";
    } else if (score >= 65) {
      // Check for specific high-confidence threats
      if (input.botScore > 80 && input.credentialStuffingIndicators > 70) {
        return "critical";
      }
      return "high";
    } else if (score >= 45) {
      return "medium";
    } else {
      return "low";
    }
  }

  /**
   * Get recommendation based on risk level
   */
  private getRecommendation(
    riskLevel: string,
    input: ThreatScoringInput
  ): "allow" | "challenge" | "block" {
    switch (riskLevel) {
      case "critical":
        return "block";
      case "high":
        // Block if high confidence bot or credential stuffing
        if ((input.botScore > 75 && input.credentialStuffingIndicators > 60) ||
            input.credentialStuffingIndicators > 85) {
          return "block";
        }
        return "challenge";
      case "medium":
        return "challenge";
      default:
        return "allow";
    }
  }

  /**
   * Identify key threat factors
   */
  private identifyFactors(input: ThreatScoringInput): string[] {
    const factors: string[] = [];

    if (input.patternScore > 60) {
      factors.push(`OWASP patterns detected (${Math.round(input.patternScore)}/100)`);
    }

    if (input.botScore > 65) {
      factors.push(`Bot-like behavior detected (${Math.round(input.botScore)}/100)`);
    }

    if (input.credentialStuffingIndicators > 60) {
      factors.push(`Credential stuffing patterns (${Math.round(input.credentialStuffingIndicators)}/100)`);
    }

    if (input.behavioralScore > 60) {
      factors.push(`Behavioral anomalies (${Math.round(input.behavioralScore)}/100)`);
    }

    if (input.anomalyScore > 50) {
      factors.push(`Request anomalies (${Math.round(input.anomalyScore)}/100)`);
    }

    if (input.geoAnomaly > 50) {
      factors.push(`Geographic anomalies (${Math.round(input.geoAnomaly)}/100)`);
    }

    if (input.velocityAnomaly > 60) {
      factors.push(`High request velocity (${Math.round(input.velocityAnomaly)}/100)`);
    }

    if (input.reputationScore > 50) {
      factors.push(`Bad IP reputation (${Math.round(input.reputationScore)}/100)`);
    }

    return factors.slice(0, 5);
  }

  /**
   * Calculate ML confidence score
   */
  private calculateConfidence(input: ThreatScoringInput): number {
    // Confidence increases when multiple signals agree
    let confidence = 50; // Base confidence

    const signals = [
      input.patternScore > 50,
      input.botScore > 60,
      input.credentialStuffingIndicators > 60,
      input.behavioralScore > 60,
      input.anomalyScore > 50,
    ];

    const agreementCount = signals.filter(s => s).length;
    confidence += agreementCount * 10;

    // High confidence if consistent signal
    if (input.patternScore > 70 && input.anomalyScore > 60) {
      confidence = Math.min(95, confidence + 10);
    }

    return Math.min(100, confidence);
  }

  /**
   * Suggest specific action
   */
  private suggestAction(riskLevel: string, factors: string[]): string {
    if (riskLevel === "critical") {
      if (factors.some(f => f.includes("Credential stuffing"))) {
        return "Block and notify security team - potential credential stuffing attack";
      }
      return "Block request - high confidence threat";
    } else if (riskLevel === "high") {
      if (factors.some(f => f.includes("Bot-like"))) {
        return "Challenge with CAPTCHA - bot detection confirmed";
      }
      return "Challenge with CAPTCHA or require verification";
    } else if (riskLevel === "medium") {
      return "Challenge with CAPTCHA - behavioral anomalies detected";
    } else {
      return "Allow request - low risk";
    }
  }
}

export const advancedThreatScorer = new AdvancedThreatScorer();
