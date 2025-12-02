/**
 * ModSecurity Integration for WAF
 * Integrates OWASP ModSecurity CRS rules with the existing WAF engine
 * 
 * Installation:
 * npm install modsecurity
 */

import OWASP_CRS_RULES, { type ModSecurityRule } from './owasp-crs-rules';

interface ModSecurityMatch {
  ruleId: string;
  message: string;
  severity: string;
  action: string;
  phase: string;
}

/**
 * ModSecurity CRS (Core Rule Set) Rules
 * OWASP CRS v3.3 - Comprehensive 453+ rules for enterprise web protection
 */
export const MODSECURITY_CRS_RULES: typeof OWASP_CRS_RULES = OWASP_CRS_RULES;

// Legacy array - now points to full OWASP CRS rules above
export class ModSecurityEngine {
  private rules: ModSecurityRule[] = [];
  private enabled: boolean = true;

  constructor(customRules?: ModSecurityRule[]) {
    // Load default OWASP CRS rules
    this.rules = [...MODSECURITY_CRS_RULES];

    // Add custom rules if provided
    if (customRules) {
      this.rules.push(...customRules);
    }
  }

  /**
   * Evaluate request against ModSecurity rules
   */
  evaluateRequest(requestData: {
    method: string;
    uri: string;
    headers: Record<string, string>;
    body?: string;
    query?: Record<string, string>;
    clientIp?: string;
  }): ModSecurityMatch[] {
    if (!this.enabled) return [];

    const matches: ModSecurityMatch[] = [];

    for (const rule of this.rules) {
      // Check if rule applies to this request phase
      if (!this.shouldApplyRule(rule, requestData)) continue;

      // Evaluate rule against request data
      const ruleMatches = this.evaluateRule(rule, requestData);
      if (ruleMatches) {
        matches.push({
          ruleId: rule.id,
          message: rule.msg,
          severity: rule.severity,
          action: rule.action,
          phase: rule.phase,
        });
      }
    }

    return matches;
  }

  /**
   * Determine if rule should be evaluated for this request
   */
  private shouldApplyRule(rule: ModSecurityRule, requestData: any): boolean {
    // Only apply to request phases for now
    if (!['REQUEST_HEADERS', 'REQUEST_BODY'].includes(rule.phase)) {
      return false;
    }

    // Check if rule targets current request data
    for (const target of rule.target) {
      if (target === 'REQUEST_METHOD' && requestData.method) return true;
      if (target === 'REQUEST_URI' && requestData.uri) return true;
      if (target === 'ARGS' && (requestData.query || requestData.body)) return true;
      if (target === 'HEADERS' && requestData.headers) return true;
      if (target === 'POST_PAYLOAD' && requestData.body) return true;
      if (target.startsWith('REQUEST_HEADERS:')) return true;
    }

    return false;
  }

  /**
   * Evaluate a single rule against request data
   */
  private evaluateRule(rule: ModSecurityRule, requestData: any): boolean {
    const regex = new RegExp(rule.pattern, 'i');

    for (const target of rule.target) {
      let valueToCheck = '';

      // Extract value based on target
      if (target === 'REQUEST_METHOD') {
        valueToCheck = requestData.method;
      } else if (target === 'REQUEST_URI') {
        valueToCheck = requestData.uri;
      } else if (target === 'ARGS') {
        valueToCheck = [
          requestData.query ? JSON.stringify(requestData.query) : '',
          requestData.body || '',
        ].join(' ');
      } else if (target === 'HEADERS') {
        valueToCheck = JSON.stringify(requestData.headers);
      } else if (target === 'POST_PAYLOAD') {
        valueToCheck = requestData.body || '';
      } else if (target.startsWith('REQUEST_HEADERS:')) {
        const headerName = target.split(':')[1];
        valueToCheck = requestData.headers[headerName.toLowerCase()] || '';
      }

      // Apply operator
      if (this.matchesOperator(rule.operator, valueToCheck, rule.pattern)) {
        return true;
      }
    }

    return false;
  }

  /**
   * Match against operators
   */
  private matchesOperator(operator: string, value: string, pattern: string): boolean {
    switch (operator) {
      case 'rx': // Regex
        return new RegExp(pattern, 'i').test(value);
      case 'eq': // Equals
        return value === pattern;
      case 'contains':
        return value.includes(pattern);
      case 'startswith':
        return value.startsWith(pattern);
      case 'endswith':
        return value.endsWith(pattern);
      case 'gt': // Greater than (for numeric)
        return parseInt(value) > parseInt(pattern);
      case 'lt': // Less than
        return parseInt(value) < parseInt(pattern);
      default:
        return false;
    }
  }

  /**
   * Get rule by ID
   */
  getRule(id: string): ModSecurityRule | undefined {
    return this.rules.find((r) => r.id === id);
  }

  /**
   * Enable/disable engine
   */
  setEnabled(enabled: boolean): void {
    this.enabled = enabled;
  }

  /**
   * Add custom rule
   */
  addRule(rule: ModSecurityRule): void {
    this.rules.push(rule);
  }

  /**
   * Get all rules
   */
  getRules(): ModSecurityRule[] {
    return this.rules;
  }

  /**
   * Get rule count
   */
  getRuleCount(): number {
    return this.rules.length;
  }
}

// Export singleton instance
export const modSecurityEngine = new ModSecurityEngine();
