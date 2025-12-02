/**
 * WAF vs ModSecurity Comparison API Endpoints
 * Test traffic through both engines and return comparison results
 */

import type { Express } from 'express';
import { wafEngine } from '../waf/engine';
import { modSecurityEngine } from '../waf/modsecurity-integration';
import { DDoSConfigSchema } from '../schemas/ddos-validation';

interface ComparisonResult {
  engine: 'waf' | 'modsecurity';
  blocked: boolean;
  severity: string;
  matches: any[];
  score: number;
  action: string;
  processingTimeMs: number;
  details: string;
}

export function registerComparisonEndpoints(app: Express, requireAuth: any, requireRole?: any) {
  /**
   * POST /api/tenants/:tenantId/waf/test
   * Test payload through WAF Engine
   */
  app.post('/api/tenants/:tenantId/waf/test', requireAuth, (req, res) => {
    try {
      const { tenantId } = req.params;
      const { method = 'POST', uri = '/test', headers = {}, body = '' } = req.body;

      const startTime = Date.now();

      // Test through WAF Engine
      const result = wafEngine.analyzeRequest({
        method,
        path: uri,
        headers,
        body: body ? JSON.stringify(body) : '',
        query: {},
        clientIp: req.ip,
        tenantId,
        enforcementMode: 'block',
      });

      const processingTimeMs = Date.now() - startTime;

      const response: ComparisonResult = {
        engine: 'waf',
        blocked: result.action === 'block' || result.action === 'deny',
        severity: result.riskLevel,
        matches: result.matches,
        score: result.score,
        action: result.action,
        processingTimeMs,
        details: result.reason,
      };

      res.json({
        success: true,
        result: response,
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: error instanceof Error ? error.message : 'WAF test failed',
      });
    }
  });

  /**
   * POST /api/tenants/:tenantId/modsecurity/test
   * Test payload through ModSecurity
   */
  app.post('/api/tenants/:tenantId/modsecurity/test', requireAuth, (req, res) => {
    try {
      const { tenantId } = req.params;
      const { method = 'POST', uri = '/test', headers = {}, body = '' } = req.body;

      const startTime = Date.now();

      // Test through ModSecurity
      const matches = modSecurityEngine.evaluateRequest({
        method,
        uri,
        headers: headers as Record<string, string>,
        body,
        query: {},
        clientIp: req.ip,
      });

      const processingTimeMs = Date.now() - startTime;

      // Determine if blocked
      const criticalMatches = matches.filter((m: any) => 
        ['CRITICAL', 'EMERGENCY', 'ALERT'].includes(m.severity)
      );
      const blocked = criticalMatches.length > 0;

      // Calculate severity
      const maxSeverity = matches.length > 0
        ? matches.reduce((max: string, m: any) => {
            const severityOrder = {
              'EMERGENCY': 8,
              'ALERT': 7,
              'CRITICAL': 6,
              'ERROR': 5,
              'WARNING': 4,
              'NOTICE': 3,
              'INFO': 2,
              'DEBUG': 1,
            };
            return (severityOrder[m.severity as keyof typeof severityOrder] || 0) >
              (severityOrder[max as keyof typeof severityOrder] || 0)
              ? m.severity
              : max;
          }, 'INFO')
        : 'LOW';

      const response: ComparisonResult = {
        engine: 'modsecurity',
        blocked,
        severity: maxSeverity,
        matches: matches.map((m: any) => ({
          id: m.ruleId,
          name: m.message,
          category: m.action,
        })),
        score: matches.length > 0 ? Math.min(1, matches.length * 0.2) : 0,
        action: blocked ? 'deny' : 'allow',
        processingTimeMs,
        details: matches.length > 0 
          ? `${matches.length} rule(s) triggered`
          : 'No threats detected',
      };

      res.json({
        success: true,
        result: response,
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: error instanceof Error ? error.message : 'ModSecurity test failed',
      });
    }
  });

  /**
   * POST /api/tenants/:tenantId/comparison
   * Test payload through both engines and return comparison
   */
  app.post('/api/tenants/:tenantId/comparison', requireAuth, async (req, res) => {
    try {
      const { tenantId } = req.params;
      const { method = 'POST', uri = '/test', headers = {}, body = '' } = req.body;

      // Test WAF Engine
      const wafStartTime = Date.now();
      const wafResult = wafEngine.analyzeRequest({
        method,
        path: uri,
        headers,
        body: body ? JSON.stringify(body) : '',
        query: {},
        clientIp: req.ip,
        tenantId,
        enforcementMode: 'block',
      });
      const wafProcessingTime = Date.now() - wafStartTime;

      // Test ModSecurity
      const modSecStartTime = Date.now();
      const modSecMatches = modSecurityEngine.evaluateRequest({
        method,
        uri,
        headers: headers as Record<string, string>,
        body,
        query: {},
        clientIp: req.ip,
      });
      const modSecProcessingTime = Date.now() - modSecStartTime;

      // Prepare comparison results
      const wafResponse: ComparisonResult = {
        engine: 'waf',
        blocked: wafResult.action === 'block' || wafResult.action === 'deny',
        severity: wafResult.riskLevel,
        matches: wafResult.matches,
        score: wafResult.score,
        action: wafResult.action,
        processingTimeMs: wafProcessingTime,
        details: wafResult.reason,
      };

      const criticalModSecMatches = modSecMatches.filter((m: any) =>
        ['CRITICAL', 'EMERGENCY', 'ALERT'].includes(m.severity)
      );
      const modSecMaxSeverity = modSecMatches.length > 0
        ? modSecMatches.reduce((max: string, m: any) => {
            const severityOrder = {
              'EMERGENCY': 8,
              'ALERT': 7,
              'CRITICAL': 6,
              'ERROR': 5,
              'WARNING': 4,
              'NOTICE': 3,
              'INFO': 2,
              'DEBUG': 1,
            };
            return (severityOrder[m.severity as keyof typeof severityOrder] || 0) >
              (severityOrder[max as keyof typeof severityOrder] || 0)
              ? m.severity
              : max;
          }, 'INFO')
        : 'LOW';

      const modSecResponse: ComparisonResult = {
        engine: 'modsecurity',
        blocked: criticalModSecMatches.length > 0,
        severity: modSecMaxSeverity,
        matches: modSecMatches.map((m: any) => ({
          id: m.ruleId,
          name: m.message,
          category: m.action,
        })),
        score: modSecMatches.length > 0 ? Math.min(1, modSecMatches.length * 0.2) : 0,
        action: criticalModSecMatches.length > 0 ? 'deny' : 'allow',
        processingTimeMs: modSecProcessingTime,
        details: modSecMatches.length > 0
          ? `${modSecMatches.length} rule(s) triggered`
          : 'No threats detected',
      };

      // Analysis
      const agreement = wafResponse.blocked === modSecResponse.blocked;
      const recommendation = 
        (wafResponse.blocked && modSecResponse.blocked)
          ? 'BLOCK'
          : (wafResponse.blocked || modSecResponse.blocked)
            ? 'CHALLENGE'
            : 'ALLOW';

      res.json({
        success: true,
        waf: wafResponse,
        modsecurity: modSecResponse,
        analysis: {
          agreement,
          speedDifference: Math.abs(wafProcessingTime - modSecProcessingTime),
          fasterEngine: wafProcessingTime < modSecProcessingTime ? 'waf' : 'modsecurity',
          rulesTriggered: {
            waf: wafResponse.matches.length,
            modsecurity: modSecResponse.matches.length,
          },
          recommendation,
        },
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: error instanceof Error ? error.message : 'Comparison failed',
      });
    }
  });

  /**
   * GET /api/tenants/:tenantId/engines/status
   * Get current engine status and configuration
   */
  app.get('/api/tenants/:tenantId/engines/status', requireAuth, (req, res) => {
    try {
      const { tenantId } = req.params;

      res.json({
        success: true,
        engines: {
          waf: {
            name: 'WAF Engine',
            status: 'active',
            rulesLoaded: 453, // OWASP rules count
            enabled: true,
            priority: 'secondary',
          },
          modsecurity: {
            name: 'ModSecurity CRS v3.3',
            status: 'active',
            rulesLoaded: modSecurityEngine.getRuleCount(),
            enabled: true,
            priority: 'primary',
          },
        },
        tenantId,
        timestamp: new Date().toISOString(),
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: error instanceof Error ? error.message : 'Failed to get status',
      });
    }
  });
}
