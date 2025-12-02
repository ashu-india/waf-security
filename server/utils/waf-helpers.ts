/**
 * WAF Helper Functions
 * Extracted common patterns from WAF endpoints to reduce code duplication
 */

import type { WafRule } from "../models";

/**
 * Extract security thresholds from policy
 * Default thresholds if not specified: block=70, challenge=50, monitor=30
 */
export function extractThresholds(policy: any) {
  return {
    blockThreshold: policy?.blockThreshold ?? 70,
    challengeThreshold: policy?.challengeThreshold ?? 50,
    monitorThreshold: policy?.monitorThreshold ?? 30,
  };
}

/**
 * Merge and prepare WAF rules for analysis
 * Combines global and tenant-specific rules with default severity
 */
export function mergeAndPrepareRules(
  globalRules: any[],
  customRules: any[]
) {
  return [...globalRules, ...customRules].map((r) => ({
    ...r,
    severity: r.severity || "medium",
  }));
}
