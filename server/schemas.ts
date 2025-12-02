import { z } from "zod";

// Zod schemas for validation (replacing Drizzle-zod)

export const insertUserSchema = z.object({
  email: z.string().email(),
  firstName: z.string().optional(),
  lastName: z.string().optional(),
  profileImageUrl: z.string().optional(),
  avatarType: z.enum(["astronaut", "avatar", "bear", "bot", "cat", "dog", "robot", "user"]).optional(),
  role: z.enum(["admin", "operator", "viewer"]).default("viewer"),
  tenantIds: z.array(z.string()).optional(),
});

export const insertTenantSchema = z.object({
  name: z.string(),
  domain: z.string(),
  upstreamUrl: z.string(),
  sslEnabled: z.boolean().default(false),
  sslCertPath: z.string().optional(),
  sslKeyPath: z.string().optional(),
  isActive: z.boolean().default(true),
  retentionDays: z.number().default(30),
  anonymizeIpAfterDays: z.number().default(7),
  scrubCookies: z.boolean().default(true),
  scrubAuthHeaders: z.boolean().default(true),
});

export const insertPolicySchema = z.object({
  tenantId: z.string(),
  name: z.string(),
  enforcementMode: z.enum(["monitor", "block"]).default("monitor"),
  securityEngine: z.enum(["waf-engine", "modsecurity", "both"]).default("both"),
  blockThreshold: z.number().optional(),
  challengeThreshold: z.number().optional(),
  monitorThreshold: z.number().optional(),
  rateLimit: z.number().optional(),
  rateLimitWindow: z.number().optional(),
  isDefault: z.boolean().optional(),
  allowedCountries: z.array(z.string()).optional(),
  blockedCountries: z.array(z.string()).optional(),
  geoRateLimitByCountry: z.record(z.number()).optional(),
  vpnDetectionEnabled: z.boolean().optional(),
  vpnBlockAction: z.enum(["block", "challenge", "monitor"]).optional(),
});

export const insertWafRuleSchema = z.object({
  tenantId: z.string().optional(),
  name: z.string(),
  description: z.string().optional(),
  category: z.string(),
  severity: z.string().optional(),
  pattern: z.string(),
  patternType: z.string().optional(),
  targetField: z.string(),
  action: z.enum(["allow", "monitor", "challenge", "deny"]).optional(),
  score: z.number().optional(),
  enabled: z.boolean().optional(),
  isBuiltIn: z.boolean().optional(),
});

export const insertRequestSchema = z.object({
  tenantId: z.string(),
  timestamp: z.date().optional(),
  clientIp: z.string().optional(),
  clientIpAnonymized: z.boolean().default(false),
  method: z.string(),
  path: z.string(),
  queryString: z.string().optional(),
  headersJson: z.record(z.any()).optional(),
  bodyRef: z.string().optional(),
  bodyPreview: z.string().optional(),
  userAgent: z.string().optional(),
  referer: z.string().optional(),
  contentType: z.string().optional(),
  contentLength: z.number().optional(),
  responseCode: z.number().optional(),
  responseHeadersJson: z.record(z.any()).optional(),
  responseBodyRef: z.string().optional(),
  responseTime: z.number().optional(),
  analysisId: z.string().optional(),
  actionTaken: z.enum(["allow", "monitor", "challenge", "deny"]).default("allow"),
  wafHitsJson: z.record(z.any()).optional(),
  country: z.string().optional(),
  city: z.string().optional(),
});

export const insertAnalysisSchema = z.object({
  requestId: z.string(),
  totalScore: z.number().optional(),
  suggestedAction: z.enum(["allow", "monitor", "challenge", "deny"]).optional(),
  finalAction: z.enum(["allow", "monitor", "challenge", "deny"]).optional(),
  breakdownJson: z.record(z.any()).optional(),
  matchedRulesJson: z.array(z.any()).optional(),
  ipReputationScore: z.number().optional(),
  rateAnomalyScore: z.number().optional(),
  headerAnomalyScore: z.number().optional(),
  pathAnomalyScore: z.number().optional(),
  bodyAnomalyScore: z.number().optional(),
  processingTimeMs: z.number().optional(),
  explanationText: z.string().optional(),
});

export const insertOverrideSchema = z.object({
  overrideType: z.enum(["request", "rule", "ip"]),
  targetId: z.string(),
  tenantId: z.string().optional(),
  action: z.enum(["allow", "monitor", "challenge", "deny"]),
  operatorId: z.string(),
  reason: z.string().optional(),
  expiresAt: z.date().optional(),
  isActive: z.boolean().default(true),
});

export const insertAlertSchema = z.object({
  tenantId: z.string().optional(),
  severity: z.string(),
  type: z.string(),
  title: z.string(),
  message: z.string(),
  metadata: z.record(z.any()).optional(),
  isRead: z.boolean().optional(),
  isDismissed: z.boolean().optional(),
});

export const insertWebhookSchema = z.object({
  tenantId: z.string().optional(),
  name: z.string(),
  url: z.string().url(),
  secret: z.string().optional(),
  events: z.array(z.string()).optional(),
  isActive: z.boolean().default(true),
});

export const insertIpListSchema = z.object({
  tenantId: z.string().optional(),
  ipAddress: z.string().ip(),
  listType: z.string(),
  reason: z.string().optional(),
  expiresAt: z.date().optional(),
  createdBy: z.string().optional(),
});

// Type exports (matching Drizzle types)
export type InsertUser = z.infer<typeof insertUserSchema>;
export type InsertTenant = z.infer<typeof insertTenantSchema>;
export type InsertPolicy = z.infer<typeof insertPolicySchema>;
export type InsertWafRule = z.infer<typeof insertWafRuleSchema>;
export type InsertRequest = z.infer<typeof insertRequestSchema>;
export type InsertAnalysis = z.infer<typeof insertAnalysisSchema>;
export type InsertOverride = z.infer<typeof insertOverrideSchema>;
export type InsertAlert = z.infer<typeof insertAlertSchema>;
export type InsertWebhook = z.infer<typeof insertWebhookSchema>;
export type InsertIpList = z.infer<typeof insertIpListSchema>;
