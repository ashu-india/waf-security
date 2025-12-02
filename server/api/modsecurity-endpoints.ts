/**
 * ModSecurity Management API Endpoints
 * Control and monitor ModSecurity rules and status
 */

import type { Express } from 'express';
import { modSecurityEngine, MODSECURITY_CRS_RULES } from '../waf/modsecurity-integration';
import { getModSecurityStats, getModSecurityRulesList } from '../waf/modsecurity-middleware';

export function registerModSecurityEndpoints(app: Express, requireAuth: any, requireRole?: any) {
  /**
   * GET /api/modsecurity/status
   * Get ModSecurity engine status and statistics
   */
  app.get('/api/modsecurity/status', requireAuth, (req, res) => {
    try {
      const stats = getModSecurityStats();
      res.json({
        success: true,
        status: 'active',
        engine: 'ModSecurity',
        rulesLoaded: modSecurityEngine.getRuleCount(),
        crsCoreRuleSet: MODSECURITY_CRS_RULES.length,
        enabled: stats.enabled,
        blockSeverities: stats.config.blockOn,
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: error instanceof Error ? error.message : 'Failed to get status',
      });
    }
  });

  /**
   * GET /api/modsecurity/rules
   * Get all loaded ModSecurity rules
   */
  app.get('/api/modsecurity/rules', requireAuth, (req, res) => {
    try {
      const rules = modSecurityEngine.getRules();
      const grouped = rules.reduce(
        (acc, rule) => {
          if (!acc[rule.severity]) {
            acc[rule.severity] = [];
          }
          acc[rule.severity].push({
            id: rule.id,
            name: rule.name,
            severity: rule.severity,
            msg: rule.msg,
            tags: rule.tags,
            phase: rule.phase,
          });
          return acc;
        },
        {} as Record<string, any[]>
      );

      res.json({
        success: true,
        totalRules: rules.length,
        rulesBySeverity: grouped,
        categories: {
          sqli: rules.filter((r) => r.tags.includes('sqli')).length,
          xss: rules.filter((r) => r.tags.includes('xss')).length,
          rfi_lfi: rules.filter((r) => r.tags.includes('rfi') || r.tags.includes('lfi')).length,
          rce: rules.filter((r) => r.tags.includes('rce')).length,
          xxe: rules.filter((r) => r.tags.includes('xxe')).length,
          csrf: rules.filter((r) => r.tags.includes('csrf')).length,
        },
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: error instanceof Error ? error.message : 'Failed to get rules',
      });
    }
  });

  /**
   * GET /api/modsecurity/rules/:ruleId
   * Get details of a specific rule
   */
  app.get('/api/modsecurity/rules/:ruleId', requireAuth, (req, res) => {
    try {
      const rule = modSecurityEngine.getRule(req.params.ruleId);

      if (!rule) {
        return res.status(404).json({
          success: false,
          error: 'Rule not found',
        });
      }

      res.json({
        success: true,
        rule: {
          id: rule.id,
          name: rule.name,
          description: rule.msg,
          severity: rule.severity,
          pattern: rule.pattern,
          operator: rule.operator,
          targets: rule.target,
          action: rule.action,
          phase: rule.phase,
          tags: rule.tags,
        },
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: error instanceof Error ? error.message : 'Failed to get rule',
      });
    }
  });

  /**
   * GET /api/modsecurity/rules-by-category
   * Get rules grouped by category/type
   */
  app.get('/api/modsecurity/rules-by-category', requireAuth, (req, res) => {
    try {
      const rules = modSecurityEngine.getRules();
      const categories = [
        { tag: 'sqli', name: 'SQL Injection', color: '#ff6b6b' },
        { tag: 'xss', name: 'Cross-Site Scripting', color: '#ffd43b' },
        { tag: 'rfi', name: 'Remote File Inclusion', color: '#ff8787' },
        { tag: 'lfi', name: 'Local File Inclusion', color: '#ff922b' },
        { tag: 'rce', name: 'Remote Code Execution', color: '#ff0000' },
        { tag: 'xxe', name: 'XML External Entity', color: '#ff1744' },
        { tag: 'csrf', name: 'CSRF', color: '#7c4dff' },
        { tag: 'bot', name: 'Bot Detection', color: '#00bcd4' },
      ];

      const grouped = categories.map((cat) => ({
        category: cat.name,
        tag: cat.tag,
        color: cat.color,
        count: rules.filter((r) => r.tags.includes(cat.tag)).length,
        rules: rules
          .filter((r) => r.tags.includes(cat.tag))
          .map((r) => ({
            id: r.id,
            name: r.name,
            severity: r.severity,
          })),
      }));

      res.json({
        success: true,
        categories: grouped,
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: error instanceof Error ? error.message : 'Failed to get categories',
      });
    }
  });

  /**
   * POST /api/modsecurity/test-rule
   * Test a rule against sample data
   */
  app.post('/api/modsecurity/test-rule', requireAuth, (req, res) => {
    try {
      const { ruleId, testData } = req.body;

      if (!ruleId || !testData) {
        return res.status(400).json({
          success: false,
          error: 'Missing ruleId or testData',
        });
      }

      const rule = modSecurityEngine.getRule(ruleId);
      if (!rule) {
        return res.status(404).json({
          success: false,
          error: 'Rule not found',
        });
      }

      // Test the rule
      const matches = modSecurityEngine.evaluateRequest({
        method: 'POST',
        uri: '/test',
        headers: testData.headers || {},
        body: testData.body || '',
        query: testData.query || {},
      });

      const matchedRule = matches.find((m: any) => m.ruleId === ruleId);

      res.json({
        success: true,
        rule: {
          id: rule.id,
          name: rule.name,
        },
        matched: !!matchedRule,
        message: matchedRule ? `Rule triggered: ${matchedRule.message}` : 'Rule did not match',
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: error instanceof Error ? error.message : 'Failed to test rule',
      });
    }
  });

  /**
   * GET /api/modsecurity/owasp-crs
   * Get information about OWASP Core Rule Set
   */
  app.get('/api/modsecurity/owasp-crs', requireAuth, (req, res) => {
    try {
      res.json({
        success: true,
        crs: {
          name: 'OWASP ModSecurity Core Rule Set',
          version: '3.3',
          description: 'Free, open source ModSecurity rules against OWASP Top 10 and other common attacks',
          coverage: [
            'SQL Injection (SQLi)',
            'Cross-Site Scripting (XSS)',
            'Remote File Inclusion (RFI)',
            'Local File Inclusion (LFI)',
            'Remote Code Execution (RCE)',
            'XML External Entity (XXE)',
            'Cross-Site Request Forgery (CSRF)',
            'Protocol Attacks',
            'Scanner Detection',
            'Bot Detection',
          ],
          totalRules: MODSECURITY_CRS_RULES.length,
          loadedRules: modSecurityEngine.getRuleCount(),
          rulesIntegrated: true,
        },
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: error instanceof Error ? error.message : 'Failed to get CRS info',
      });
    }
  });
}
