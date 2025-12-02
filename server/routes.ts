import type { Express } from "express";
import { createServer, type Server } from "http";
import { storage } from "./storage";
import { 
  insertTenantSchema, insertPolicySchema, insertWafRuleSchema,
  insertAlertSchema, insertOverrideSchema
} from "./schemas";
import { z } from "zod";
import { wafEngine } from "./waf/engine";
import { sseServer } from "./waf/sse";
import { startWafProxy } from "./waf/proxy";
import passport from "passport";
import { 
  rateLimit, requireRole, sanitizeInput, 
  securityHeaders, requestSanitizer, validateContentType, requestLogger,
  createTenantRateLimiter, startRateLimitCleanup
} from "./middleware";
import { startDataRetentionJob, triggerWebhooks } from "./jobs";
import { registerMLEndpoints } from "./api/ml-endpoints";
import { registerDDoSEndpoints } from "./api/ddos-endpoints";
import { registerComparisonEndpoints } from "./api/comparison-endpoints";
import complianceRouter from "./api/compliance-endpoints";
import tenantComplianceRouter from "./api/tenant-compliance-endpoints";
import complianceDashboardRouter from "./api/compliance-dashboard-endpoints";
import complianceMonitoringRouter from "./api/compliance-monitoring-endpoints";
import complianceRemediationRouter from "./api/compliance-remediation-endpoints";
import complianceWebhooksRouter from "./api/compliance-webhooks-endpoints";
import { modSecurityEngine } from "./waf/modsecurity-integration";
import { GeolocationService } from "./services/geolocation";
import { extractClientIpFromRequest, sanitizeIp } from "./utils/ip-extraction";
import { extractThresholds, mergeAndPrepareRules } from "./utils/waf-helpers";
import challengeRouter from "./api/challenge-endpoints";
import { behavioralEngine, type LoginAttempt } from "./services/behavioral-analysis";
import { botDetector } from "./services/bot-detector";
import { advancedThreatScorer } from "./utils/advanced-threat-scoring";
import mlFeedbackRouter from "./routes/ml-feedback.js";

// Helper function to scrub sensitive headers
function scrubHeaders(headers: Record<string, any>, scrubCookies: boolean, scrubAuthHeaders: boolean): Record<string, any> {
  const scrubbed = { ...headers };
  
  if (scrubCookies) {
    delete scrubbed['cookie'];
    delete scrubbed['set-cookie'];
  }
  
  if (scrubAuthHeaders) {
    delete scrubbed['authorization'];
    delete scrubbed['x-api-key'];
    delete scrubbed['x-auth-token'];
    delete scrubbed['x-access-token'];
  }
  
  return scrubbed;
}

function requireAuth(req: any, res: any, next: any) {
  if (!req.isAuthenticated || !req.isAuthenticated()) {
    return res.status(401).json({ message: "Unauthorized" });
  }
  // Disable HTTP caching for API responses - React Query handles caching
  if (req.method === "GET") {
    res.set("Cache-Control", "no-cache, no-store, must-revalidate, private");
    res.set("Pragma", "no-cache");
    res.set("Expires", "0");
  }
  next();
}

export async function registerRoutes(app: Express): Promise<Server> {
  // Start rate limit cleanup job (runs every 60 seconds)
  startRateLimitCleanup(60000);
  
  // Apply security middlewares
  app.use(securityHeaders());
  app.use(requestSanitizer());
  app.use(validateContentType());
  
  // Auth routes
  // Apply rate limiting to login
  app.post("/api/login", rateLimit(60000, 5), (req, res, next) => {
    // Extract client IP and user agent
    const clientIp = extractClientIpFromRequest(req);
    const userAgent = req.get("user-agent") || "unknown";
    const email = req.body.email || "unknown";

    // Track login attempt for behavioral analysis
    const attempt: LoginAttempt = {
      email,
      ip: clientIp,
      userAgent,
      timestamp: new Date(),
      success: false,
    };

    // Check behavioral analysis
    const behaviorCheck = behavioralEngine.trackLoginAttempt(attempt);
    if (!behaviorCheck.allowed) {
      return res.status(429).json({
        message: behaviorCheck.reason,
        type: "behavioral_block",
        profile: behaviorCheck.profile,
      });
    }

    // Bot detection
    const botCheck = botDetector.analyze({
      method: req.method,
      path: req.path,
      userAgent,
      headers: req.headers as Record<string, string | string[]>,
      ip: clientIp,
      timestamp: Date.now(),
      bodySize: req.get("content-length") ? parseInt(req.get("content-length")!) : undefined,
    });

    if (botCheck.isBot && botCheck.score > 75) {
      return res.status(429).json({
        message: "Bot detection triggered. Please solve the CAPTCHA.",
        type: "bot_detected",
        botScore: botCheck.score,
        factors: botCheck.factors,
      });
    }

    passport.authenticate("local", (err: any, user: any, info: any) => {
      if (err) {
        return res.status(500).json({ message: "Authentication error" });
      }
      if (!user) {
        // Update attempt as failed
        attempt.success = false;
        behavioralEngine.trackLoginAttempt(attempt);

        // Check for credential stuffing
        const stuffingCheck = behavioralEngine.detectCredentialStuffing(email);
        if (stuffingCheck.isStuffing) {
          return res.status(429).json({
            message: "Credential stuffing detected. Account temporarily locked.",
            type: "credential_stuffing",
            confidence: stuffingCheck.confidence,
            indicators: stuffingCheck.indicators,
          });
        }

        return res.status(401).json({ message: info?.message || "Invalid credentials" });
      }

      // Mark as successful
      attempt.success = true;
      behavioralEngine.trackLoginAttempt(attempt);

      req.login(user, (err: any) => {
        if (err) {
          return res.status(500).json({ message: "Login failed" });
        }
        res.json(user);
      });
    })(req, res, next);
  });

  app.get("/api/auth/logout", (req, res) => {
    req.logout((err) => {
      if (err) {
        return res.status(500).json({ message: "Logout failed" });
      }
      // Destroy session and send JSON response
      req.session?.destroy((destroyErr) => {
        if (destroyErr) {
          console.error("Session destroy error:", destroyErr);
        }
        res.clearCookie("connect.sid");
        res.json({ message: "Logged out successfully" });
      });
    });
  });

  // Legacy logout endpoint
  app.get("/api/logout", (req, res) => {
    req.logout((err) => {
      if (err) {
        return res.status(500).json({ message: "Logout failed" });
      }
      req.session?.destroy((destroyErr) => {
        if (destroyErr) {
          console.error("Session destroy error:", destroyErr);
        }
        res.clearCookie("connect.sid");
        res.redirect("/");
      });
    });
  });

  app.get("/api/auth/user", async (req, res) => {
    if (!req.isAuthenticated || !req.isAuthenticated()) {
      return res.status(401).json({ message: "Unauthorized" });
    }
    res.json(req.user);
  });

  // Dashboard
  app.get("/api/dashboard/stats", requireAuth, async (req, res) => {
    try {
      const stats = await storage.getDashboardStats();
      res.json(stats);
    } catch (error) {
      console.error("Error fetching dashboard stats:", error);
      res.status(500).json({ message: "Failed to fetch dashboard stats" });
    }
  });

  // Tenants
  app.get("/api/tenants", requireAuth, async (req, res) => {
    try {
      const tenants = await storage.getTenants();
      res.json(tenants);
    } catch (error) {
      console.error("Error fetching tenants:", error);
      res.status(500).json({ message: "Failed to fetch tenants" });
    }
  });

  app.get("/api/tenants/:id", requireAuth, async (req, res) => {
    try {
      const tenant = await storage.getTenant(req.params.id);
      if (!tenant) {
        return res.status(404).json({ message: "Tenant not found" });
      }
      res.json(tenant);
    } catch (error) {
      console.error("Error fetching tenant:", error);
      res.status(500).json({ message: "Failed to fetch tenant" });
    }
  });

  app.post("/api/tenants", requireRole("admin"), async (req, res) => {
    try {
      const data = insertTenantSchema.parse(req.body);
      const tenant = await storage.createTenant(data);
      
      // Create default policy for the tenant
      await storage.createPolicy({
        tenantId: tenant.id,
        name: "Default Policy",
        enforcementMode: req.body.enforcementMode || "monitor",
        blockThreshold: req.body.blockThreshold || 70,
        challengeThreshold: 50,
        monitorThreshold: 30,
        rateLimit: 100,
        rateLimitWindow: 60,
        isDefault: true,
      });
      
      res.status(201).json(tenant);
    } catch (error) {
      console.error("Error creating tenant:", error);
      if (error instanceof z.ZodError) {
        return res.status(400).json({ message: "Invalid data", errors: error.errors });
      }
      res.status(500).json({ message: "Failed to create tenant" });
    }
  });

  app.patch("/api/tenants/:id", requireRole("admin"), async (req, res) => {
    try {
      const tenant = await storage.updateTenant(req.params.id, req.body);
      if (!tenant) {
        return res.status(404).json({ message: "Tenant not found" });
      }
      
      // If policy-related settings are included, update the tenant's default policy
      if (req.body.enforcementMode || req.body.blockThreshold !== undefined || req.body.challengeThreshold !== undefined || req.body.monitorThreshold !== undefined) {
        const policy = await storage.getPolicyByTenant(req.params.id);
        if (policy) {
          await storage.updatePolicy(policy.id, {
            enforcementMode: req.body.enforcementMode || policy.enforcementMode,
            blockThreshold: req.body.blockThreshold !== undefined ? req.body.blockThreshold : policy.blockThreshold,
            challengeThreshold: req.body.challengeThreshold !== undefined ? req.body.challengeThreshold : policy.challengeThreshold,
            monitorThreshold: req.body.monitorThreshold !== undefined ? req.body.monitorThreshold : policy.monitorThreshold,
          });
        }
      }
      
      res.json(tenant);
    } catch (error) {
      console.error("Error updating tenant:", error);
      res.status(500).json({ message: "Failed to update tenant" });
    }
  });

  app.delete("/api/tenants/:id", requireRole("admin"), async (req, res) => {
    try {
      await storage.deleteTenant(req.params.id);
      res.status(204).send();
    } catch (error) {
      console.error("Error deleting tenant:", error);
      res.status(500).json({ message: "Failed to delete tenant" });
    }
  });

  // Tenant Policy
  app.get("/api/tenants/:id/policy", requireAuth, async (req, res) => {
    try {
      const policy = await storage.getPolicyByTenant(req.params.id);
      if (!policy) {
        return res.status(404).json({ message: "Policy not found" });
      }
      res.json(policy);
    } catch (error) {
      console.error("Error fetching tenant policy:", error);
      res.status(500).json({ message: "Failed to fetch policy" });
    }
  });

  // Tenant Requests
  app.get("/api/tenants/:id/requests", requireAuth, async (req, res) => {
    try {
      const requests = await storage.getRequests(req.params.id);
      res.json(requests);
    } catch (error) {
      console.error("Error fetching tenant requests:", error);
      res.status(500).json({ message: "Failed to fetch requests" });
    }
  });

  // Policies
  app.get("/api/policies", requireAuth, async (req, res) => {
    try {
      const policies = await storage.getPolicies();
      res.json(policies);
    } catch (error) {
      console.error("Error fetching policies:", error);
      res.status(500).json({ message: "Failed to fetch policies" });
    }
  });

  app.get("/api/policies/:id", requireAuth, async (req, res) => {
    try {
      const policy = await storage.getPolicy(req.params.id);
      if (!policy) {
        return res.status(404).json({ message: "Policy not found" });
      }
      res.json(policy);
    } catch (error) {
      console.error("Error fetching policy:", error);
      res.status(500).json({ message: "Failed to fetch policy" });
    }
  });

  app.post("/api/policies", requireRole("admin", "operator"), async (req, res) => {
    try {
      const data = insertPolicySchema.parse(req.body);
      const policy = await storage.createPolicy(data);
      res.status(201).json(policy);
    } catch (error) {
      console.error("Error creating policy:", error);
      if (error instanceof z.ZodError) {
        return res.status(400).json({ message: "Invalid data", errors: error.errors });
      }
      res.status(500).json({ message: "Failed to create policy" });
    }
  });

  app.patch("/api/policies/:id", requireRole("admin", "operator"), async (req, res) => {
    try {
      const policy = await storage.getPolicy(req.params.id);
      if (!policy) {
        return res.status(404).json({ message: "Policy not found" });
      }
      
      // If setting as default, unset other policies for same tenant
      if (req.body.isDefault === true && !policy.isDefault) {
        const allPolicies = await storage.getPolicies();
        const sameTenantPolicies = allPolicies.filter(p => p.tenantId === policy.tenantId && p.id !== req.params.id);
        for (const p of sameTenantPolicies) {
          await storage.updatePolicy(p.id, { isDefault: false });
        }
      }
      
      const updated = await storage.updatePolicy(req.params.id, req.body);
      res.json(updated);
    } catch (error) {
      console.error("Error updating policy:", error);
      res.status(500).json({ message: "Failed to update policy" });
    }
  });

  app.post("/api/policies/:id/duplicate", requireRole("admin", "operator"), async (req, res) => {
    try {
      const policy = await storage.getPolicy(req.params.id);
      if (!policy) {
        return res.status(404).json({ message: "Policy not found" });
      }
      const duplicated = await storage.createPolicy({
        tenantId: policy.tenantId,
        name: `${policy.name} (Copy)`,
        enforcementMode: policy.enforcementMode,
        blockThreshold: policy.blockThreshold,
        challengeThreshold: policy.challengeThreshold,
        monitorThreshold: policy.monitorThreshold,
        rateLimit: policy.rateLimit,
        rateLimitWindow: policy.rateLimitWindow,
      });
      res.status(201).json(duplicated);
    } catch (error) {
      console.error("Error duplicating policy:", error);
      res.status(500).json({ message: "Failed to duplicate policy" });
    }
  });

  app.delete("/api/policies/:id", requireRole("admin", "operator"), async (req, res) => {
    try {
      const policy = await storage.getPolicy(req.params.id);
      if (!policy) {
        return res.status(404).json({ message: "Policy not found" });
      }
      await storage.deletePolicy(req.params.id);
      res.status(204).send();
    } catch (error) {
      console.error("Error deleting policy:", error);
      res.status(500).json({ message: "Failed to delete policy" });
    }
  });

  // WAF Rules
  app.get("/api/rules", requireAuth, async (req, res) => {
    try {
      const rules = await storage.getRules();
      res.json(rules);
    } catch (error) {
      console.error("Error fetching rules:", error);
      res.status(500).json({ message: "Failed to fetch rules" });
    }
  });

  // Get all rules (built-in + custom) with full details
  app.get("/api/rules/all-with-stats", requireAuth, async (req, res) => {
    try {
      const rules = await storage.getRules();
      const stats = {
        total: rules.length,
        enabled: rules.filter(r => r.enabled).length,
        disabled: rules.filter(r => !r.enabled).length,
        builtIn: rules.filter(r => r.isBuiltIn).length,
        custom: rules.filter(r => !r.isBuiltIn).length,
        rules: rules.map(r => ({
          ...r,
          type: r.isBuiltIn ? 'built-in' : 'custom',
          status: r.enabled ? 'enabled' : 'disabled'
        }))
      };
      res.json(stats);
    } catch (error) {
      console.error("Error fetching rules with stats:", error);
      res.status(500).json({ message: "Failed to fetch rules" });
    }
  });

  app.get("/api/rules/:id", requireAuth, async (req, res) => {
    try {
      const rule = await storage.getRule(req.params.id);
      if (!rule) {
        return res.status(404).json({ message: "Rule not found" });
      }
      res.json(rule);
    } catch (error) {
      console.error("Error fetching rule:", error);
      res.status(500).json({ message: "Failed to fetch rule" });
    }
  });

  app.post("/api/rules", requireRole("admin"), async (req, res) => {
    try {
      const data = insertWafRuleSchema.parse(req.body);
      const rule = await storage.createRule(data);
      res.status(201).json(rule);
    } catch (error) {
      console.error("Error creating rule:", error);
      if (error instanceof z.ZodError) {
        return res.status(400).json({ message: "Invalid data", errors: error.errors });
      }
      res.status(500).json({ message: "Failed to create rule" });
    }
  });

  app.patch("/api/rules/:id", requireRole("admin"), async (req, res) => {
    try {
      const rule = await storage.updateRule(req.params.id, req.body);
      if (!rule) {
        return res.status(404).json({ message: "Rule not found" });
      }
      res.json(rule);
    } catch (error) {
      console.error("Error updating rule:", error);
      res.status(500).json({ message: "Failed to update rule" });
    }
  });

  app.delete("/api/rules/:id", requireRole("admin"), async (req, res) => {
    try {
      await storage.deleteRule(req.params.id);
      res.status(204).send();
    } catch (error) {
      console.error("Error deleting rule:", error);
      res.status(500).json({ message: "Failed to delete rule" });
    }
  });

  // Requests
  app.get("/api/requests", requireAuth, async (req, res) => {
    try {
      const { tenantId, ip, path, method, scoreMin, scoreMax } = req.query;
      let requests = await storage.getRequestsWithAnalysis(tenantId as string);
      
      // Apply filters
      if (ip) requests = requests.filter(r => r.clientIp?.includes(ip as string));
      if (path) requests = requests.filter(r => r.path.includes(path as string));
      if (method) requests = requests.filter(r => r.method === method);
      
      res.json(requests);
    } catch (error) {
      console.error("Error fetching requests:", error);
      res.status(500).json({ message: "Failed to fetch requests" });
    }
  });

  app.get("/api/requests/:id", requireAuth, async (req, res) => {
    try {
      const request = await storage.getRequestWithAnalysis(req.params.id);
      if (!request) {
        return res.status(404).json({ message: "Request not found" });
      }
      res.json(request);
    } catch (error) {
      console.error("Error fetching request:", error);
      res.status(500).json({ message: "Failed to fetch request" });
    }
  });

  app.post("/api/requests/:id/override", requireRole("admin", "operator"), async (req, res) => {
    try {
      const request = await storage.getRequest(req.params.id);
      if (!request) {
        return res.status(404).json({ message: "Request not found" });
      }
      
      const override = await storage.createOverride({
        overrideType: "request",
        targetId: req.params.id,
        tenantId: request.tenantId,
        action: req.body.action,
        operatorId: (req.user as any).id,
        reason: req.body.reason,
      });
      
      res.status(201).json(override);
    } catch (error) {
      console.error("Error creating override:", error);
      res.status(500).json({ message: "Failed to create override" });
    }
  });

  // Whitelist IP - add to allow list
  app.post("/api/requests/:id/whitelist-ip", requireRole("admin", "operator"), async (req, res) => {
    try {
      const request = await storage.getRequest(req.params.id);
      if (!request || !request.clientIp) {
        return res.status(404).json({ message: "Request not found or has no IP" });
      }
      
      await storage.createIpList({
        tenantId: request.tenantId,
        listType: "whitelist",
        ipAddress: request.clientIp,
        reason: req.body.reason || "Whitelisted from request detail",
      });
      
      res.status(201).json({ message: "IP whitelisted successfully" });
    } catch (error) {
      console.error("Error whitelisting IP:", error);
      res.status(500).json({ message: "Failed to whitelist IP" });
    }
  });

  // Blacklist IP - add to deny list
  app.post("/api/requests/:id/blacklist-ip", requireRole("admin", "operator"), async (req, res) => {
    try {
      const request = await storage.getRequest(req.params.id);
      if (!request || !request.clientIp) {
        return res.status(404).json({ message: "Request not found or has no IP" });
      }
      
      await storage.createIpList({
        tenantId: request.tenantId,
        listType: "blacklist",
        ipAddress: request.clientIp,
        reason: req.body.reason || "Blacklisted from request detail",
      });
      
      res.status(201).json({ message: "IP blacklisted successfully" });
    } catch (error) {
      console.error("Error blacklisting IP:", error);
      res.status(500).json({ message: "Failed to blacklist IP" });
    }
  });

  // Create rule from request
  app.post("/api/requests/:id/create-rule", requireRole("admin", "operator"), async (req, res) => {
    try {
      const request = await storage.getRequest(req.params.id);
      if (!request) {
        return res.status(404).json({ message: "Request not found" });
      }
      
      const rule = await storage.createRule({
        tenantId: request.tenantId,
        name: req.body.name,
        category: req.body.category || "custom",
        pattern: req.body.pattern || request.path,
        targetField: req.body.targetField || "request",
        description: req.body.description || `Custom rule created from request`,
        severity: req.body.severity || "medium",
        enabled: true,
      });
      
      res.status(201).json(rule);
    } catch (error) {
      console.error("Error creating rule:", error);
      if (error instanceof z.ZodError) {
        return res.status(400).json({ message: "Invalid data", errors: error.errors });
      }
      res.status(500).json({ message: "Failed to create rule" });
    }
  });

  // Alerts
  app.get("/api/alerts", requireAuth, async (req, res) => {
    try {
      const alerts = await storage.getAlerts();
      res.json(alerts);
    } catch (error) {
      console.error("Error fetching alerts:", error);
      res.status(500).json({ message: "Failed to fetch alerts" });
    }
  });

  app.get("/api/alerts/recent", requireAuth, async (req, res) => {
    try {
      const alerts = await storage.getAlerts();
      res.json(alerts.slice(0, 5));
    } catch (error) {
      console.error("Error fetching recent alerts:", error);
      res.status(500).json({ message: "Failed to fetch alerts" });
    }
  });

  app.patch("/api/alerts/:id", requireAuth, async (req, res) => {
    try {
      const alert = await storage.updateAlert(req.params.id, req.body);
      if (!alert) {
        return res.status(404).json({ message: "Alert not found" });
      }
      res.json(alert);
    } catch (error) {
      console.error("Error updating alert:", error);
      res.status(500).json({ message: "Failed to update alert" });
    }
  });

  app.post("/api/alerts/mark-all-read", requireAuth, async (req, res) => {
    try {
      await storage.markAllAlertsRead();
      res.status(204).send();
    } catch (error) {
      console.error("Error marking alerts as read:", error);
      res.status(500).json({ message: "Failed to mark alerts as read" });
    }
  });

  app.post("/api/alerts/:id/dismiss", requireAuth, async (req, res) => {
    try {
      const alert = await storage.updateAlert(req.params.id, { isDismissed: true });
      if (!alert) {
        return res.status(404).json({ message: "Alert not found" });
      }
      res.json(alert);
    } catch (error) {
      console.error("Error dismissing alert:", error);
      res.status(500).json({ message: "Failed to dismiss alert" });
    }
  });

  // Webhooks
  app.get("/api/webhooks", requireRole("admin"), async (req, res) => {
    try {
      const webhooks = await storage.getWebhooks();
      res.json(webhooks);
    } catch (error) {
      console.error("Error fetching webhooks:", error);
      res.status(500).json({ message: "Failed to fetch webhooks" });
    }
  });

  app.post("/api/webhooks", requireRole("admin"), async (req, res) => {
    try {
      const webhook = await storage.createWebhook(req.body);
      res.status(201).json(webhook);
    } catch (error) {
      console.error("Error creating webhook:", error);
      res.status(500).json({ message: "Failed to create webhook" });
    }
  });

  app.patch("/api/webhooks/:id", requireRole("admin"), async (req, res) => {
    try {
      const webhook = await storage.updateWebhook(req.params.id, req.body);
      if (!webhook) {
        return res.status(404).json({ message: "Webhook not found" });
      }
      res.json(webhook);
    } catch (error) {
      console.error("Error updating webhook:", error);
      res.status(500).json({ message: "Failed to update webhook" });
    }
  });

  app.delete("/api/webhooks/:id", requireRole("admin"), async (req, res) => {
    try {
      await storage.deleteWebhook(req.params.id);
      res.status(204).send();
    } catch (error) {
      console.error("Error deleting webhook:", error);
      res.status(500).json({ message: "Failed to delete webhook" });
    }
  });

  // Export endpoints
  app.get("/api/export/csv", requireAuth, async (req, res) => {
    try {
      const { tenantId, startDate, endDate } = req.query;
      const reqs = await storage.getRequestsForExport(
        tenantId as string,
        startDate ? new Date(startDate as string) : undefined,
        endDate ? new Date(endDate as string) : undefined
      );

      let csv = "ID,Timestamp,ClientIP,Method,Path,StatusCode,ActionTaken,Score\n";
      for (const req of reqs) {
        csv += `"${req.id}","${req.timestamp}","${req.clientIp || 'N/A'}","${req.method}","${req.path}",${req.responseCode || 'N/A'},"${req.actionTaken}",0\n`;
      }

      res.setHeader("Content-Type", "text/csv");
      res.setHeader("Content-Disposition", "attachment; filename=requests_export.csv");
      res.send(csv);
    } catch (error) {
      console.error("Error exporting CSV:", error);
      res.status(500).json({ message: "Failed to export CSV" });
    }
  });

  app.get("/api/export/json", requireAuth, async (req, res) => {
    try {
      const { tenantId, startDate, endDate } = req.query;
      const reqs = await storage.getRequestsForExport(
        tenantId as string,
        startDate ? new Date(startDate as string) : undefined,
        endDate ? new Date(endDate as string) : undefined
      );

      res.setHeader("Content-Type", "application/json");
      res.setHeader("Content-Disposition", "attachment; filename=requests_export.json");
      res.json({ exports: reqs, totalRecords: reqs.length });
    } catch (error) {
      console.error("Error exporting JSON:", error);
      res.status(500).json({ message: "Failed to export JSON" });
    }
  });

  // Users
  app.get("/api/users", requireRole("admin"), async (req, res) => {
    try {
      const users = await storage.getUsers();
      res.json(users);
    } catch (error) {
      console.error("Error fetching users:", error);
      res.status(500).json({ message: "Failed to fetch users" });
    }
  });

  app.post("/api/users", requireRole("admin"), async (req, res) => {
    try {
      const { email, firstName, lastName, role } = req.body;
      
      if (!email || !role) {
        return res.status(400).json({ message: "Email and role are required" });
      }

      const existingUser = await storage.getUserByEmail(email);
      if (existingUser) {
        return res.status(409).json({ message: "User already exists" });
      }

      const user = await storage.createUser({
        email,
        firstName: firstName || "",
        lastName: lastName || "",
        role,
        tenantIds: [],
      });
      res.status(201).json(user);
    } catch (error) {
      console.error("Error creating user:", error);
      res.status(500).json({ message: "Failed to create user" });
    }
  });

  app.patch("/api/users/:id", requireRole("admin"), async (req, res) => {
    try {
      const user = await storage.updateUser(req.params.id, req.body);
      if (!user) {
        return res.status(404).json({ message: "User not found" });
      }
      res.json(user);
    } catch (error) {
      console.error("Error updating user:", error);
      res.status(500).json({ message: "Failed to update user" });
    }
  });

  app.delete("/api/users/:id", requireRole("admin"), async (req, res) => {
    try {
      const user = await storage.getUser(req.params.id);
      if (!user) {
        return res.status(404).json({ message: "User not found" });
      }
      await storage.deleteUser(req.params.id);
      res.json({ message: "User deleted successfully" });
    } catch (error) {
      console.error("Error deleting user:", error);
      res.status(500).json({ message: "Failed to delete user" });
    }
  });

  // Settings
  app.get("/api/settings", requireAuth, async (req, res) => {
    try {
      const settings = await storage.getSettings();
      res.json(settings);
    } catch (error) {
      console.error("Error fetching settings:", error);
      res.status(500).json({ message: "Failed to fetch settings" });
    }
  });

  app.put("/api/settings", requireRole("admin"), async (req, res) => {
    try {
      const settings = await storage.updateSettings(req.body);
      res.json(settings);
    } catch (error) {
      console.error("Error updating settings:", error);
      res.status(500).json({ message: "Failed to update settings" });
    }
  });

  // WAF Ingress endpoint - analyze, store, and broadcast incoming requests
  // This endpoint receives proxied requests from upstream (e.g., nginx, load balancer)
  app.post("/api/waf/ingress", async (req, res) => {
    try {
      const { tenantId, request: incomingRequest } = req.body;
      
      if (!tenantId || !incomingRequest) {
        return res.status(400).json({ message: "tenantId and request are required" });
      }
      
      // Ensure clientIp is properly extracted and validated
      if (!incomingRequest.clientIp || incomingRequest.clientIp === 'unknown') {
        incomingRequest.clientIp = extractClientIpFromRequest(req, incomingRequest);
      } else {
        incomingRequest.clientIp = sanitizeIp(incomingRequest.clientIp);
      }
      
      const tenant = await storage.getTenant(tenantId);
      if (!tenant || !tenant.isActive) {
        return res.status(404).json({ message: "Tenant not found or inactive" });
      }
      
      // Apply tenant-specific rate limiting (1000 requests per minute per tenant)
      const tenantRateLimiter = createTenantRateLimiter(String(tenantId), 60000, 1000);
      const rateLimitRes = await new Promise<{ limited: boolean }>((resolve) => {
        tenantRateLimiter(req, res, () => resolve({ limited: false }));
        if (res.headersSent) resolve({ limited: true });
      });
      if (rateLimitRes.limited) return;
      
      // Get policy thresholds
      const policy = await storage.getPolicyByTenant(tenantId);
      const thresholds = extractThresholds(policy);
      
      // Load WAF rules
      const customRules = await storage.getRulesByTenant(tenantId);
      const globalRules = await storage.getRulesByTenant(null);
      const allRules = mergeAndPrepareRules(globalRules, customRules);
      wafEngine.setCustomRules(allRules as any);
      
      // Get selected security engine(s) from policy
      const selectedEngine = policy?.securityEngine || 'both';
      
      // Initialize results
      let modSecMatches: any[] = [];
      let modSecBlocked = false;
      let analysis: any = null;
      let combinedMatches: any[] = [];
      
      // LAYER 1: Check ModSecurity (if enabled)
      if (selectedEngine === 'modsecurity' || selectedEngine === 'both') {
        modSecMatches = modSecurityEngine.evaluateRequest({
          method: incomingRequest.method,
          uri: incomingRequest.path,
          headers: incomingRequest.headers || {},
          body: incomingRequest.body || '',
          query: incomingRequest.query || {},
          clientIp: incomingRequest.clientIp,
        });
        
        // Check if ModSecurity blocked (critical rules triggered)
        const criticalModSecMatches = modSecMatches.filter((m: any) =>
          ['CRITICAL', 'EMERGENCY', 'ALERT'].includes(m.severity)
        );
        modSecBlocked = criticalModSecMatches.length > 0;
      }
      
      // LAYER 2: Analyze with WAF Engine (if enabled)
      if (selectedEngine === 'waf-engine' || selectedEngine === 'both') {
        analysis = wafEngine.analyzeRequest({
          ...incomingRequest,
          tenantId,
          enforcementMode: policy?.enforcementMode || 'block'
        }, thresholds, policy);
      } else {
        // If WAF Engine disabled, create dummy analysis
        analysis = {
          action: 'allow',
          score: 0,
          riskLevel: 'LOW',
          matches: [],
          processingTimeMs: 0,
          reason: 'WAF Engine disabled',
        };
      }
      
      // Combine results based on selected engine(s)
      const finalAction = selectedEngine === 'modsecurity' 
        ? (modSecBlocked ? "block" : "allow")
        : selectedEngine === 'waf-engine'
          ? analysis.action === "block" ? "block" : analysis.action === "challenge" ? "challenge" : "allow"
          : // both engines
            (modSecBlocked || analysis.action === "block" ? "block"
              : analysis.action === "challenge" ? "challenge"
              : "allow");
      
      // Combine matches from enabled engines
      combinedMatches = [];
      if (selectedEngine === 'waf-engine' || selectedEngine === 'both') {
        combinedMatches.push(...analysis.matches);
      }
      if (selectedEngine === 'modsecurity' || selectedEngine === 'both') {
        combinedMatches.push(...modSecMatches.map((m: any) => ({
          id: m.ruleId,
          ruleName: m.message,
          category: 'modsecurity',
          severity: m.severity,
          description: m.message,
        })));
      }
      
      // Determine response code based on final action
      const responseCode = finalAction === "block" ? 403 
        : finalAction === "challenge" ? 429 
        : 200;
      
      // Apply privacy settings: scrub sensitive headers
      let headersToStore = incomingRequest.headers || {};
      if ((tenant.scrubCookies ?? false) || (tenant.scrubAuthHeaders ?? false)) {
        headersToStore = scrubHeaders(headersToStore, tenant.scrubCookies ?? false, tenant.scrubAuthHeaders ?? false);
      }
      
      // Store the request
      const storedRequest = await storage.createRequest({
        tenantId,
        timestamp: new Date(),
        method: incomingRequest.method,
        path: incomingRequest.path,
        clientIp: incomingRequest.clientIp,
        userAgent: incomingRequest.headers?.["user-agent"],
        responseCode,
        actionTaken: finalAction === "block" ? "deny" : finalAction as any,
        headersJson: headersToStore,
        bodyPreview: incomingRequest.body?.substring(0, 500) || null,
        queryString: Object.entries(incomingRequest.query || {})
          .map(([k, v]) => `${k}=${v}`).join("&") || null,
        wafHitsJson: combinedMatches,
      });
      
      // Store analysis record (both engines combined)
      await storage.createAnalysis({
        requestId: storedRequest.id,
        matchedRulesJson: combinedMatches,
        totalScore: analysis.score,
        suggestedAction: finalAction === "block" ? "deny" : finalAction as any,
        finalAction: finalAction === "block" ? "deny" : finalAction as any,
        processingTimeMs: analysis.processingTimeMs,
        breakdownJson: { 
          riskLevel: analysis.riskLevel, 
          matchCount: combinedMatches.length,
          wafMatches: analysis.matches.length,
          modSecMatches: modSecMatches.length,
          engines: ['WAF Engine', 'ModSecurity CRS v3.3']
        },
      });
      
      // Broadcast to SSE clients
      sseServer.broadcastRequest(storedRequest);
      
      // Create alert for high-risk requests or blocked requests
      if (analysis.score >= 70 || modSecBlocked) {
        const alert = await storage.createAlert({
          tenantId,
          severity: modSecBlocked ? 'CRITICAL' : analysis.riskLevel,
          type: combinedMatches[0]?.category || "unknown",
          title: modSecBlocked 
            ? `BLOCKED: Critical threat detected by ModSecurity (${criticalModSecMatches.length} rules)`
            : `High-risk request detected (Score: ${analysis.score})`,
          message: `Engines: WAF Engine (${analysis.matches.length} matches) + ModSecurity (${modSecMatches.length} rules). ${combinedMatches.slice(0, 3).map((m: any) => m.ruleName).join(", ")}${combinedMatches.length > 3 ? '...' : ''}`,
        });
        
        sseServer.broadcastAlert({
          id: alert.id,
          severity: alert.severity,
          message: alert.title,
          tenantId,
        });
      }
      
      // Return analysis result (BOTH ENGINES) for upstream to act upon
      res.json({
        requestId: storedRequest.id,
        action: finalAction,
        score: analysis.score,
        riskLevel: analysis.riskLevel,
        totalMatches: combinedMatches.length,
        wafMatches: analysis.matches.length,
        modSecMatches: modSecMatches.length,
        modSecBlocked,
        processingTimeMs: analysis.processingTimeMs,
        engines: ['WAF Engine', 'ModSecurity CRS v3.3 (513+ rules)'],
      });
    } catch (error) {
      console.error("Error processing WAF ingress:", error);
      res.status(500).json({ message: "WAF processing error" });
    }
  });

  // WAF Analysis endpoint - analyze a request without storing it
  app.post("/api/waf/analyze", requireAuth, async (req, res) => {
    try {
      const { tenantId, request: wafRequest } = req.body;
      
      const tenant = await storage.getTenant(tenantId);
      if (!tenant) {
        return res.status(404).json({ message: "Tenant not found" });
      }
      
      const policy = await storage.getPolicyByTenant(tenantId);
      const thresholds = extractThresholds(policy);
      
      const customRules = await storage.getRulesByTenant(tenantId);
      const globalRules = await storage.getRulesByTenant(null);
      const allAnalysisRules = mergeAndPrepareRules(globalRules, customRules);
      wafEngine.setCustomRules(allAnalysisRules as any);
      
      const result = wafEngine.analyzeRequest({
        ...wafRequest,
        tenantId,
        enforcementMode: policy?.enforcementMode || 'block'
      }, thresholds, policy);
      
      res.json(result);
    } catch (error) {
      console.error("Error analyzing request:", error);
      res.status(500).json({ message: "Failed to analyze request" });
    }
  });

  // Test attack endpoint - execute attack payloads against target
  app.post("/api/waf/test-attack", requireAuth, async (req, res) => {
    try {
      const { targetUrl, payload, tenantId } = req.body;
      
      if (!targetUrl || !payload || !tenantId) {
        return res.status(400).json({ message: "targetUrl, payload, and tenantId are required" });
      }
      
      const tenant = await storage.getTenant(tenantId);
      if (!tenant) {
        return res.status(404).json({ message: "Tenant not found" });
      }
      
      // Build WAF request from attack payload
      const wafRequest = {
        method: "GET",
        path: `/?q=${encodeURIComponent(payload)}`,
        query: { q: payload },
        headers: { "user-agent": "WAF-Test-Attack" },
        body: payload,
        clientIp: "127.0.0.1",
        timestamp: new Date().toISOString(),
      };
      
      // Get policy for tenant
      const policy = await storage.getPolicyByTenant(tenantId);
      const thresholds = extractThresholds(policy);
      
      // Load WAF rules
      const customRules = await storage.getRulesByTenant(tenantId);
      const globalRules = await storage.getRulesByTenant(null);
      const allRules = mergeAndPrepareRules(globalRules, customRules);
      wafEngine.setCustomRules(allRules as any);
      
      // Analyze the attack (with enforcement mode from policy)
      const analysis = wafEngine.analyzeRequest({
        ...wafRequest,
        tenantId,
        enforcementMode: policy?.enforcementMode || 'block'
      }, thresholds, policy);
      
      res.json({
        attackType: payload.substring(0, 40),
        payload,
        statusCode: analysis.action === "block" ? 403 : analysis.action === "challenge" ? 429 : 200,
        message: analysis.reason,
        timestamp: new Date().toISOString(),
        action: analysis.action,
        score: analysis.score,
      });
    } catch (error) {
      console.error("Error testing attack:", error);
      res.status(500).json({ message: "Failed to test attack" });
    }
  });

  // WAF Engine Test - test with WAF engine only
  app.post("/api/tenants/:tenantId/waf/test", requireAuth, async (req, res) => {
    try {
      const { tenantId } = req.params;
      const { method = "POST", uri = "/api/test", headers = {}, body = "", query = {} } = req.body;
      
      const tenant = await storage.getTenant(tenantId);
      if (!tenant) {
        return res.status(404).json({ message: "Tenant not found" });
      }

      const wafRequest = {
        method,
        path: uri,
        headers,
        body,
        query,
        clientIp: "127.0.0.1",
      };

      const policy = await storage.getPolicyByTenant(tenantId);
      const thresholds = extractThresholds(policy);
      const customRules = await storage.getRulesByTenant(tenantId);
      const globalRules = await storage.getRulesByTenant(null);
      const allRules = mergeAndPrepareRules(globalRules, customRules);
      wafEngine.setCustomRules(allRules as any);

      const startTime = Date.now();
      const analysis = wafEngine.analyzeRequest({
        ...wafRequest,
        tenantId,
        enforcementMode: policy?.enforcementMode || 'block'
      }, thresholds, policy);
      const processingTimeMs = Date.now() - startTime;

      res.json({
        engine: 'waf',
        blocked: analysis.action === 'block' || analysis.action === 'challenge',
        severity: analysis.riskLevel,
        matches: analysis.matches,
        score: analysis.score,
        action: analysis.action,
        processingTimeMs,
        details: analysis.reason,
      });
    } catch (error) {
      console.error("Error testing WAF:", error);
      res.status(500).json({ message: "Failed to test WAF" });
    }
  });

  // ModSecurity Test - test with ModSecurity engine only
  app.post("/api/tenants/:tenantId/modsecurity/test", requireAuth, async (req, res) => {
    try {
      const { tenantId } = req.params;
      const { method = "POST", uri = "/api/test", headers = {}, body = "", query = {} } = req.body;
      
      const tenant = await storage.getTenant(tenantId);
      if (!tenant) {
        return res.status(404).json({ message: "Tenant not found" });
      }

      const requestData = {
        method,
        uri,
        headers,
        body,
        query,
        clientIp: "127.0.0.1",
      };

      const startTime = Date.now();
      const matches = modSecurityEngine.evaluateRequest(requestData);
      const processingTimeMs = Date.now() - startTime;

      const blocked = matches.length > 0;
      const maxSeverity = matches.length > 0 ? matches.reduce((max, m) => m.severity > max ? m.severity : max, "low") : "low";

      res.json({
        engine: 'modsecurity',
        blocked,
        severity: maxSeverity,
        matches: matches.map(m => ({ id: m.ruleId, name: m.message, category: m.phase })),
        score: blocked ? 85 : 0,
        action: blocked ? 'block' : 'allow',
        processingTimeMs,
        details: blocked ? `ModSecurity detected ${matches.length} rule(s)` : 'No threats detected',
      });
    } catch (error) {
      console.error("Error testing ModSecurity:", error);
      res.status(500).json({ message: "Failed to test ModSecurity" });
    }
  });

  // Start background jobs
  startDataRetentionJob();

  // Register challenge endpoints (no auth needed - public for CAPTCHA)
  app.use('/api/waf', challengeRouter);
  app.use(mlFeedbackRouter);

  // Behavioral analytics endpoints
  app.get("/api/security/behavior/:email", requireAuth, async (req, res) => {
    try {
      const profile = behavioralEngine.getProfile(req.params.email);
      const anomalies = behavioralEngine.calculateAnomalyScore(req.params.email);

      res.json({
        profile,
        anomalies,
      });
    } catch (error) {
      console.error("Error fetching behavior profile:", error);
      res.status(500).json({ message: "Failed to fetch behavior profile" });
    }
  });

  // Advanced threat scoring endpoint (for demo/testing)
  app.post("/api/security/threat-score", requireAuth, async (req, res) => {
    try {
      const input = req.body;
      const analysis = advancedThreatScorer.calculateThreat(input);
      res.json(analysis);
    } catch (error) {
      console.error("Error calculating threat score:", error);
      res.status(500).json({ message: "Failed to calculate threat score" });
    }
  });

  // Register ML prediction endpoints (including training, metrics, models)
  registerMLEndpoints(app, requireAuth, requireRole);
  registerDDoSEndpoints(app, requireAuth, requireRole);
  registerComparisonEndpoints(app, requireAuth, requireRole);
  
  // Register compliance verification endpoints
  app.use("/api/compliance", complianceRouter);
  
  // Register tenant compliance management endpoints
  app.use("/api/tenant-compliance", tenantComplianceRouter);
  
  // Register compliance dashboard endpoints
  app.use("/api/compliance-dashboard", complianceDashboardRouter);
  
  // Register compliance monitoring endpoints
  app.use("/api/compliance-monitoring", complianceMonitoringRouter);
  
  // Register compliance remediation endpoints
  app.use("/api/compliance-remediation", complianceRemediationRouter);
  
  // Register compliance webhooks endpoints
  app.use("/api/compliance-webhooks", complianceWebhooksRouter);

  // CORS preflight for SSE endpoint
  app.options("/api/traffic/stream", (req, res) => {
    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader("Access-Control-Allow-Methods", "GET, OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
    res.setHeader("Access-Control-Allow-Credentials", "true");
    res.sendStatus(204);
  });

  // SSE stream endpoint for live traffic updates
  app.get("/api/traffic/stream", requireAuth, (req, res) => {
    // Disable timeouts for long-lived SSE connections
    req.socket?.setTimeout(0);
    res.socket?.setTimeout(0);
    
    const clientId = sseServer.registerClient(res);
    console.log(`[SSE] Stream endpoint: ${clientId} connected`);
  });

  // SSE status endpoint
  app.get("/api/sse/status", requireAuth, async (req, res) => {
    res.json({
      clients: sseServer.getClientCount(),
      status: "active",
    });
  });

  app.get("/api/analytics/dashboard", requireAuth, async (req, res) => {
    try { const stats = await storage.getDashboardStats(); res.json({ ...stats, behavioral: { totalProfiles: 0, lockedAccounts: 0, riskProfiles: [], credentialStuffingDetected: 0, botAttacksBlocked: 0, anomaliesDetected: 0 }, geo: { totalCountries: 0, topCountries: [], vpnDetectionsBlocked: 0, geoblockedRequests: 0, regionalRateLimitEnforced: 0 } }); } catch (error) { res.status(500).json({ message: "Failed" }); }
  });
  app.get("/api/analytics/tenant/:tenantId", requireAuth, async (req, res) => {
    try { const requests = await storage.getRequests(req.params.tenantId); res.json({ totalRequests: requests.length, blockedRequests: requests.filter((r: any) => r.actionTaken === "deny").length, monitoredRequests: requests.filter((r: any) => r.actionTaken === "monitor").length, allowedRequests: requests.filter((r: any) => r.actionTaken === "allow").length, behavioral: { totalProfiles: 0, lockedAccounts: 0, riskProfiles: [], credentialStuffingDetected: 0, botAttacksBlocked: 0, anomaliesDetected: 0 }, geo: { totalCountries: 0, topCountries: [], vpnDetectionsBlocked: 0, geoblockedRequests: 0, regionalRateLimitEnforced: 0 } }); } catch (error) { res.status(500).json({ message: "Failed" }); }
  });

  app.patch("/api/policies/:id/behavior", requireRole("admin", "operator"), async (req, res) => {
    try {
      const policy = await storage.updatePolicy(req.params.id, req.body);
      res.json(policy);
    } catch (error) {
      res.status(500).json({ message: "Failed to update policy" });
    }
  });

  // Update policy security engine selection
  app.patch("/api/policies/:id/engine", requireAuth, async (req, res) => {
    try {
      const { securityEngine } = req.body;
      if (!['waf-engine', 'modsecurity', 'both'].includes(securityEngine)) {
        return res.status(400).json({ error: 'Invalid engine selection' });
      }
      const policy = await storage.updatePolicy(req.params.id, { securityEngine });
      res.json(policy);
    } catch (error) {
      res.status(500).json({ message: "Failed to update engine" });
    }
  });

  const httpServer = createServer(app);

  // Start WAF reverse proxy (if configured via environment variables)
  // The reverse proxy runs on a separate port and sends requests to /api/waf/ingress
  await startWafProxy();

  return httpServer;
}
