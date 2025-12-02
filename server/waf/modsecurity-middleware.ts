/**
 * ModSecurity Middleware for Express
 * Integrates ModSecurity engine into the request processing pipeline
 */

import { Request, Response, NextFunction } from 'express';
import { modSecurityEngine, ModSecurityMatch } from './modsecurity-integration';

interface ModSecurityConfig {
  enabled: boolean;
  blockOn: string[]; // Rule severities that trigger blocking
  logAll: boolean;
  customRules?: any[];
}

const defaultConfig: ModSecurityConfig = {
  enabled: true,
  blockOn: ['CRITICAL', 'EMERGENCY', 'ALERT'],
  logAll: false,
};

let config = { ...defaultConfig };

/**
 * Configure ModSecurity middleware
 */
export function configureModSecurity(customConfig: Partial<ModSecurityConfig>): void {
  config = { ...config, ...customConfig };
  modSecurityEngine.setEnabled(config.enabled);
}

/**
 * ModSecurity middleware for Express
 */
export function modSecurityMiddleware(
  req: Request,
  res: Response,
  next: NextFunction
): void {
  if (!config.enabled) {
    return next();
  }

  try {
    // Collect request data
    const requestData = {
      method: req.method,
      uri: req.path,
      headers: req.headers as Record<string, string>,
      query: req.query as Record<string, string>,
      body: req.body ? JSON.stringify(req.body) : '',
      clientIp: req.ip,
    };

    // Evaluate against ModSecurity rules
    const matches = modSecurityEngine.evaluateRequest(requestData);

    // Store matches in request for later access
    (req as any).modSecurityMatches = matches;

    // Log all matches if configured
    if (config.logAll && matches.length > 0) {
      console.log(`[ModSecurity] ${matches.length} rule(s) triggered:`, matches);
    }

    // Check if any critical rules were triggered
    const criticalMatches = matches.filter((m: ModSecurityMatch) =>
      config.blockOn.includes(m.severity)
    );

    if (criticalMatches.length > 0) {
      // Log the attack
      console.warn(
        `[ModSecurity] BLOCKED: ${criticalMatches.length} critical rule(s) triggered`,
        {
          ip: req.ip,
          method: req.method,
          path: req.path,
          rules: criticalMatches.map((m: ModSecurityMatch) => ({
            id: m.ruleId,
            message: m.message,
            severity: m.severity,
          })),
        }
      );

      // Return 403 Forbidden
      return res.status(403).json({
        error: 'Access Denied',
        message: 'Your request was blocked by the security filter',
        details: 'ModSecurity protection rule triggered',
      });
    }

    // Continue to next middleware
    next();
  } catch (error) {
    console.error('[ModSecurity] Middleware error:', error);
    // Don't block on middleware errors, just log
    next();
  }
}

/**
 * Get ModSecurity matches from request
 */
export function getModSecurityMatches(req: Request): ModSecurityMatch[] {
  return (req as any).modSecurityMatches || [];
}

/**
 * Get human-readable rule list
 */
export function getModSecurityRulesList(): string {
  const rules = modSecurityEngine.getRules();
  return rules
    .map(
      (r) =>
        `[${r.id}] ${r.name} (${r.severity}) - ${r.msg}`
    )
    .join('\n');
}

/**
 * Get ModSecurity stats
 */
export function getModSecurityStats(): {
  enabled: boolean;
  totalRules: number;
  config: ModSecurityConfig;
} {
  return {
    enabled: config.enabled,
    totalRules: modSecurityEngine.getRuleCount(),
    config,
  };
}
