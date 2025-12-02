import { DataTypes, Model, Optional } from "sequelize";
import { sequelize } from "./db";
import { v4 as uuidv4 } from "uuid";

// Types
export interface UserAttributes {
  id: string;
  email: string;
  firstName?: string;
  lastName?: string;
  profileImageUrl?: string;
  avatarType?: "astronaut" | "avatar" | "bear" | "bot" | "cat" | "dog" | "robot" | "user";
  role: "admin" | "operator" | "viewer";
  tenantIds?: string[];
  createdAt: Date;
  updatedAt: Date;
}
export interface UserCreationAttributes extends Optional<UserAttributes, "id" | "createdAt" | "updatedAt"> {}
export class User extends Model<UserAttributes, UserCreationAttributes> implements UserAttributes {
  declare id: string;
  declare email: string;
  declare firstName?: string;
  declare lastName?: string;
  declare profileImageUrl?: string;
  declare avatarType?: "astronaut" | "avatar" | "bear" | "bot" | "cat" | "dog" | "robot" | "user";
  declare role: "admin" | "operator" | "viewer";
  declare tenantIds?: string[];
  declare readonly createdAt: Date;
  declare readonly updatedAt: Date;
}

export interface TenantAttributes {
  id: string;
  name: string;
  domain: string;
  upstreamUrl: string;
  sslEnabled: boolean;
  sslCertPath?: string;
  sslKeyPath?: string;
  isActive: boolean;
  retentionDays: number;
  anonymizeIpAfterDays: number;
  scrubCookies: boolean;
  scrubAuthHeaders: boolean;
  createdAt: Date;
  updatedAt: Date;
}
export interface TenantCreationAttributes extends Optional<TenantAttributes, "id" | "createdAt" | "updatedAt"> {}
export class Tenant extends Model<TenantAttributes, TenantCreationAttributes> implements TenantAttributes {
  declare id: string;
  declare name: string;
  declare domain: string;
  declare upstreamUrl: string;
  declare sslEnabled: boolean;
  declare sslCertPath?: string;
  declare sslKeyPath?: string;
  declare isActive: boolean;
  declare retentionDays: number;
  declare anonymizeIpAfterDays: number;
  declare scrubCookies: boolean;
  declare scrubAuthHeaders: boolean;
  declare readonly createdAt: Date;
  declare readonly updatedAt: Date;
}

export interface PolicyAttributes {
  id: string;
  tenantId: string;
  name: string;
  enforcementMode: "monitor" | "block";
  securityEngine: "waf-engine" | "modsecurity" | "both";
  blockThreshold: number;
  challengeThreshold: number;
  monitorThreshold: number;
  rateLimit: number;
  rateLimitWindow: number;
  isDefault: boolean;
  allowedCountries?: string[];
  blockedCountries?: string[];
  geoRateLimitByCountry?: any;
  vpnDetectionEnabled?: boolean;
  vpnBlockAction?: "block" | "challenge" | "monitor";
  rules?: any;
  enabled?: boolean;
  createdAt: Date;
  updatedAt: Date;
}
export interface PolicyCreationAttributes extends Optional<PolicyAttributes, "id" | "createdAt" | "updatedAt"> {}
export class Policy extends Model<PolicyAttributes, PolicyCreationAttributes> implements PolicyAttributes {
  declare id: string;
  declare tenantId: string;
  declare name: string;
  declare enforcementMode: "monitor" | "block";
  declare securityEngine: "waf-engine" | "modsecurity" | "both";
  declare blockThreshold: number;
  declare challengeThreshold: number;
  declare monitorThreshold: number;
  declare rateLimit: number;
  declare rateLimitWindow: number;
  declare isDefault: boolean;
  declare allowedCountries?: string[];
  declare blockedCountries?: string[];
  declare geoRateLimitByCountry?: any;
  declare vpnDetectionEnabled?: boolean;
  declare vpnBlockAction?: "block" | "challenge" | "monitor";
  declare rules?: any;
  declare enabled?: boolean;
  declare readonly createdAt: Date;
  declare readonly updatedAt: Date;
}

export interface WafRuleAttributes {
  id: string;
  tenantId?: string;
  name: string;
  description?: string;
  category: string;
  severity: string;
  pattern: string;
  patternType: string;
  targetField: string;
  action: "allow" | "monitor" | "challenge" | "deny";
  score: number;
  enabled: boolean;
  isBuiltIn: boolean;
  hitCount: number;
  createdAt: Date;
  updatedAt: Date;
}
export interface WafRuleCreationAttributes extends Optional<WafRuleAttributes, "id" | "createdAt" | "updatedAt"> {}
export class WafRule extends Model<WafRuleAttributes, WafRuleCreationAttributes> implements WafRuleAttributes {
  declare id: string;
  declare tenantId?: string;
  declare name: string;
  declare description?: string;
  declare category: string;
  declare severity: string;
  declare pattern: string;
  declare patternType: string;
  declare targetField: string;
  declare action: "allow" | "monitor" | "challenge" | "deny";
  declare score: number;
  declare enabled: boolean;
  declare isBuiltIn: boolean;
  declare hitCount: number;
  declare readonly createdAt: Date;
  declare readonly updatedAt: Date;
}

export interface RequestAttributes {
  id: string;
  tenantId: string;
  timestamp: Date;
  clientIp?: string;
  clientIpAnonymized: boolean;
  method: string;
  path: string;
  queryString?: string;
  headersJson?: any;
  bodyRef?: string;
  bodyPreview?: string;
  userAgent?: string;
  referer?: string;
  contentType?: string;
  contentLength?: number;
  responseCode?: number;
  responseHeadersJson?: any;
  responseBodyRef?: string;
  responseTime?: number;
  analysisId?: string;
  actionTaken: "allow" | "monitor" | "challenge" | "deny";
  wafHitsJson?: any;
  country?: string;
  city?: string;
  createdAt: Date;
}
export interface RequestCreationAttributes extends Optional<RequestAttributes, "id" | "createdAt"> {}
export class Request extends Model<RequestAttributes, RequestCreationAttributes> implements RequestAttributes {
  declare id: string;
  declare tenantId: string;
  declare timestamp: Date;
  declare clientIp?: string;
  declare clientIpAnonymized: boolean;
  declare method: string;
  declare path: string;
  declare queryString?: string;
  declare headersJson?: any;
  declare bodyRef?: string;
  declare bodyPreview?: string;
  declare userAgent?: string;
  declare referer?: string;
  declare contentType?: string;
  declare contentLength?: number;
  declare responseCode?: number;
  declare responseHeadersJson?: any;
  declare responseBodyRef?: string;
  declare responseTime?: number;
  declare analysisId?: string;
  declare actionTaken: "allow" | "monitor" | "challenge" | "deny";
  declare wafHitsJson?: any;
  declare country?: string;
  declare city?: string;
  declare readonly createdAt: Date;
}

export interface AnalysisAttributes {
  id: string;
  requestId: string;
  totalScore: number;
  suggestedAction: "allow" | "monitor" | "challenge" | "deny";
  finalAction: "allow" | "monitor" | "challenge" | "deny";
  breakdownJson?: any;
  matchedRulesJson?: any;
  ipReputationScore: number;
  rateAnomalyScore: number;
  headerAnomalyScore: number;
  pathAnomalyScore: number;
  bodyAnomalyScore: number;
  processingTimeMs?: number;
  explanationText?: string;
  createdAt: Date;
}
export interface AnalysisCreationAttributes extends Optional<AnalysisAttributes, "id" | "createdAt"> {}
export class Analysis extends Model<AnalysisAttributes, AnalysisCreationAttributes> implements AnalysisAttributes {
  declare id: string;
  declare requestId: string;
  declare totalScore: number;
  declare suggestedAction: "allow" | "monitor" | "challenge" | "deny";
  declare finalAction: "allow" | "monitor" | "challenge" | "deny";
  declare breakdownJson?: any;
  declare matchedRulesJson?: any;
  declare ipReputationScore: number;
  declare rateAnomalyScore: number;
  declare headerAnomalyScore: number;
  declare pathAnomalyScore: number;
  declare bodyAnomalyScore: number;
  declare processingTimeMs?: number;
  declare explanationText?: string;
  declare readonly createdAt: Date;
}

export interface OverrideAttributes {
  id: string;
  overrideType: "request" | "rule" | "ip";
  targetId: string;
  tenantId?: string;
  action: "allow" | "monitor" | "challenge" | "deny";
  operatorId: string;
  reason?: string;
  expiresAt?: Date;
  isActive: boolean;
  createdAt: Date;
}
export interface OverrideCreationAttributes extends Optional<OverrideAttributes, "id" | "createdAt"> {}
export class Override extends Model<OverrideAttributes, OverrideCreationAttributes> implements OverrideAttributes {
  declare id: string;
  declare overrideType: "request" | "rule" | "ip";
  declare targetId: string;
  declare tenantId?: string;
  declare action: "allow" | "monitor" | "challenge" | "deny";
  declare operatorId: string;
  declare reason?: string;
  declare expiresAt?: Date;
  declare isActive: boolean;
  declare readonly createdAt: Date;
}

export interface AlertAttributes {
  id: string;
  tenantId?: string;
  severity: string;
  type: string;
  title: string;
  message: string;
  metadata?: any;
  isRead: boolean;
  isDismissed: boolean;
  createdAt: Date;
}
export interface AlertCreationAttributes extends Optional<AlertAttributes, "id" | "createdAt"> {}
export class Alert extends Model<AlertAttributes, AlertCreationAttributes> implements AlertAttributes {
  declare id: string;
  declare tenantId?: string;
  declare severity: string;
  declare type: string;
  declare title: string;
  declare message: string;
  declare metadata?: any;
  declare isRead: boolean;
  declare isDismissed: boolean;
  declare readonly createdAt: Date;
}

export interface WebhookAttributes {
  id: string;
  tenantId?: string;
  name: string;
  url: string;
  secret?: string;
  events?: string[];
  isActive: boolean;
  lastTriggeredAt?: Date;
  failureCount: number;
  createdAt: Date;
}
export interface WebhookCreationAttributes extends Optional<WebhookAttributes, "id" | "createdAt"> {}
export class Webhook extends Model<WebhookAttributes, WebhookCreationAttributes> implements WebhookAttributes {
  declare id: string;
  declare tenantId?: string;
  declare name: string;
  declare url: string;
  declare secret?: string;
  declare events?: string[];
  declare isActive: boolean;
  declare lastTriggeredAt?: Date;
  declare failureCount: number;
  declare readonly createdAt: Date;
}

export interface IpListAttributes {
  id: string;
  tenantId?: string;
  ipAddress: string;
  listType: string;
  reason?: string;
  expiresAt?: Date;
  createdBy?: string;
  createdAt: Date;
}
export interface IpListCreationAttributes extends Optional<IpListAttributes, "id" | "createdAt"> {}
export class IpList extends Model<IpListAttributes, IpListCreationAttributes> implements IpListAttributes {
  declare id: string;
  declare tenantId?: string;
  declare ipAddress: string;
  declare listType: string;
  declare reason?: string;
  declare expiresAt?: Date;
  declare createdBy?: string;
  declare readonly createdAt: Date;
}

// Audit Files
export interface AuditFileAttributes {
  id: string;
  tenantId: string;
  requestId?: string;
  fileType: string;
  pathOnDisk: string;
  sizeBytes?: number;
  mimeType?: string;
  isCompressed: boolean;
  createdAt: Date;
}
export interface AuditFileCreationAttributes extends Optional<AuditFileAttributes, "id" | "createdAt"> {}
export class AuditFile extends Model<AuditFileAttributes, AuditFileCreationAttributes> implements AuditFileAttributes {
  declare id: string;
  declare tenantId: string;
  declare requestId?: string;
  declare fileType: string;
  declare pathOnDisk: string;
  declare sizeBytes?: number;
  declare mimeType?: string;
  declare isCompressed: boolean;
  declare readonly createdAt: Date;
}

// Analytics Aggregates
export interface AnalyticsAggregateAttributes {
  id: string;
  tenantId: string;
  periodStart: Date;
  periodEnd: Date;
  periodType: string;
  totalRequests: number;
  blockedRequests: number;
  monitoredRequests: number;
  allowedRequests: number;
  challengedRequests: number;
  uniqueIps: number;
  avgScore: number;
  topRulesJson?: any;
  topIpsJson?: any;
  topPathsJson?: any;
  createdAt: Date;
}
export interface AnalyticsAggregateCreationAttributes extends Optional<AnalyticsAggregateAttributes, "id" | "createdAt"> {}
export class AnalyticsAggregate extends Model<AnalyticsAggregateAttributes, AnalyticsAggregateCreationAttributes> implements AnalyticsAggregateAttributes {
  declare id: string;
  declare tenantId: string;
  declare periodStart: Date;
  declare periodEnd: Date;
  declare periodType: string;
  declare totalRequests: number;
  declare blockedRequests: number;
  declare monitoredRequests: number;
  declare allowedRequests: number;
  declare challengedRequests: number;
  declare uniqueIps: number;
  declare avgScore: number;
  declare topRulesJson?: any;
  declare topIpsJson?: any;
  declare topPathsJson?: any;
  declare readonly createdAt: Date;
}

// DDoS Events
export interface DDoSEventAttributes {
  id: string;
  tenantId: string;
  clientIp: string;
  severity: "low" | "medium" | "high" | "critical";
  eventType: "volumetric" | "connection_limit" | "rate_limit" | "protocol_anomaly" | "normalization_violation";
  requestsPerSecond?: number;
  uniqueIPs?: number;
  volumetricScore?: number;
  reason: string;
  action: "allow" | "throttle" | "challenge" | "block";
  metadata?: any;
  createdAt: Date;
}
export interface DDoSEventCreationAttributes extends Optional<DDoSEventAttributes, "id" | "createdAt"> {}
export class DDoSEvent extends Model<DDoSEventAttributes, DDoSEventCreationAttributes> implements DDoSEventAttributes {
  declare id: string;
  declare tenantId: string;
  declare clientIp: string;
  declare severity: "low" | "medium" | "high" | "critical";
  declare eventType: "volumetric" | "connection_limit" | "rate_limit" | "protocol_anomaly" | "normalization_violation";
  declare requestsPerSecond?: number;
  declare uniqueIPs?: number;
  declare volumetricScore?: number;
  declare reason: string;
  declare action: "allow" | "throttle" | "challenge" | "block";
  declare metadata?: any;
  declare readonly createdAt: Date;
}

// Initialize models
export function initializeModels() {
  User.init(
    {
      id: { type: DataTypes.STRING, primaryKey: true, defaultValue: () => uuidv4() },
      email: { type: DataTypes.STRING, unique: true },
      firstName: DataTypes.STRING,
      lastName: DataTypes.STRING,
      profileImageUrl: DataTypes.STRING,
      avatarType: { type: DataTypes.ENUM("astronaut", "avatar", "bear", "bot", "cat", "dog", "robot", "user"), defaultValue: "user" },
      role: { type: DataTypes.ENUM("admin", "operator", "viewer"), defaultValue: "viewer" },
      tenantIds: { type: DataTypes.JSON, defaultValue: [] },
      createdAt: { type: DataTypes.DATE, defaultValue: DataTypes.NOW },
      updatedAt: { type: DataTypes.DATE, defaultValue: DataTypes.NOW },
    },
    { sequelize, tableName: "users", timestamps: true }
  );

  Tenant.init(
    {
      id: { type: DataTypes.STRING, primaryKey: true, defaultValue: () => uuidv4() },
      name: DataTypes.STRING,
      domain: { type: DataTypes.STRING, unique: true },
      upstreamUrl: DataTypes.STRING,
      sslEnabled: { type: DataTypes.BOOLEAN, defaultValue: false },
      sslCertPath: DataTypes.STRING,
      sslKeyPath: DataTypes.STRING,
      isActive: { type: DataTypes.BOOLEAN, defaultValue: true },
      retentionDays: { type: DataTypes.INTEGER, defaultValue: 30 },
      anonymizeIpAfterDays: { type: DataTypes.INTEGER, defaultValue: 7 },
      scrubCookies: { type: DataTypes.BOOLEAN, defaultValue: true },
      scrubAuthHeaders: { type: DataTypes.BOOLEAN, defaultValue: true },
      createdAt: { type: DataTypes.DATE, defaultValue: DataTypes.NOW },
      updatedAt: { type: DataTypes.DATE, defaultValue: DataTypes.NOW },
    },
    { sequelize, tableName: "tenants", timestamps: true }
  );

  Policy.init(
    {
      id: { type: DataTypes.STRING, primaryKey: true, defaultValue: () => uuidv4() },
      tenantId: { type: DataTypes.STRING, references: { model: Tenant, key: 'id' } },
      name: DataTypes.STRING,
      enforcementMode: { type: DataTypes.ENUM("monitor", "block"), defaultValue: "monitor" },
      securityEngine: { type: DataTypes.ENUM("waf-engine", "modsecurity", "both"), defaultValue: "both" },
      blockThreshold: { type: DataTypes.FLOAT, defaultValue: 70 },
      challengeThreshold: { type: DataTypes.FLOAT, defaultValue: 50 },
      monitorThreshold: { type: DataTypes.FLOAT, defaultValue: 30 },
      rateLimit: { type: DataTypes.INTEGER, defaultValue: 100 },
      rateLimitWindow: { type: DataTypes.INTEGER, defaultValue: 60 },
      isDefault: { type: DataTypes.BOOLEAN, defaultValue: false },
      allowedCountries: { type: DataTypes.JSON, defaultValue: null },
      blockedCountries: { type: DataTypes.JSON, defaultValue: null },
      geoRateLimitByCountry: { type: DataTypes.JSON, defaultValue: null },
      vpnDetectionEnabled: { type: DataTypes.BOOLEAN, defaultValue: false },
      vpnBlockAction: { type: DataTypes.ENUM("block", "challenge", "monitor"), defaultValue: "monitor" },
      rules: { type: DataTypes.JSON, defaultValue: "[]" },
      enabled: { type: DataTypes.BOOLEAN, defaultValue: true },
      createdAt: { type: DataTypes.DATE, defaultValue: DataTypes.NOW },
      updatedAt: { type: DataTypes.DATE, defaultValue: DataTypes.NOW },
    },
    { sequelize, tableName: "policies", timestamps: true }
  );

  WafRule.init(
    {
      id: { type: DataTypes.STRING, primaryKey: true, defaultValue: () => uuidv4() },
      tenantId: { type: DataTypes.STRING, references: { model: Tenant, key: 'id' }, allowNull: true },
      name: DataTypes.STRING,
      description: DataTypes.TEXT,
      category: DataTypes.STRING,
      severity: { type: DataTypes.STRING, defaultValue: "medium" },
      pattern: DataTypes.TEXT,
      patternType: { type: DataTypes.STRING, defaultValue: "regex" },
      targetField: DataTypes.STRING,
      action: { type: DataTypes.ENUM("allow", "monitor", "challenge", "deny"), defaultValue: "deny" },
      score: { type: DataTypes.INTEGER, defaultValue: 10 },
      enabled: { type: DataTypes.BOOLEAN, defaultValue: true },
      isBuiltIn: { type: DataTypes.BOOLEAN, defaultValue: false },
      hitCount: { type: DataTypes.INTEGER, defaultValue: 0 },
      createdAt: { type: DataTypes.DATE, defaultValue: DataTypes.NOW },
      updatedAt: { type: DataTypes.DATE, defaultValue: DataTypes.NOW },
    },
    { sequelize, tableName: "waf_rules", timestamps: true }
  );

  Request.init(
    {
      id: { type: DataTypes.STRING, primaryKey: true, defaultValue: () => uuidv4() },
      tenantId: { type: DataTypes.STRING, references: { model: Tenant, key: 'id' } },
      timestamp: { type: DataTypes.DATE, defaultValue: DataTypes.NOW },
      clientIp: DataTypes.STRING,
      clientIpAnonymized: { type: DataTypes.BOOLEAN, defaultValue: false },
      method: DataTypes.STRING,
      path: DataTypes.TEXT,
      queryString: DataTypes.TEXT,
      headersJson: DataTypes.JSON,
      bodyRef: DataTypes.STRING,
      bodyPreview: DataTypes.TEXT,
      userAgent: DataTypes.TEXT,
      referer: DataTypes.TEXT,
      contentType: DataTypes.STRING,
      contentLength: DataTypes.INTEGER,
      responseCode: DataTypes.INTEGER,
      responseHeadersJson: DataTypes.JSON,
      responseBodyRef: DataTypes.STRING,
      responseTime: DataTypes.INTEGER,
      analysisId: DataTypes.STRING,
      actionTaken: { type: DataTypes.ENUM("allow", "monitor", "challenge", "deny"), defaultValue: "allow" },
      wafHitsJson: DataTypes.JSON,
      country: DataTypes.STRING,
      city: DataTypes.STRING,
      createdAt: { type: DataTypes.DATE, defaultValue: DataTypes.NOW },
    },
    { sequelize, tableName: "requests", timestamps: false }
  );

  Analysis.init(
    {
      id: { type: DataTypes.STRING, primaryKey: true, defaultValue: () => uuidv4() },
      requestId: { type: DataTypes.STRING, references: { model: Request, key: 'id' } },
      totalScore: { type: DataTypes.FLOAT, defaultValue: 0 },
      suggestedAction: { type: DataTypes.ENUM("allow", "monitor", "challenge", "deny"), defaultValue: "allow" },
      finalAction: { type: DataTypes.ENUM("allow", "monitor", "challenge", "deny"), defaultValue: "allow" },
      breakdownJson: DataTypes.JSON,
      matchedRulesJson: DataTypes.JSON,
      ipReputationScore: { type: DataTypes.FLOAT, defaultValue: 0 },
      rateAnomalyScore: { type: DataTypes.FLOAT, defaultValue: 0 },
      headerAnomalyScore: { type: DataTypes.FLOAT, defaultValue: 0 },
      pathAnomalyScore: { type: DataTypes.FLOAT, defaultValue: 0 },
      bodyAnomalyScore: { type: DataTypes.FLOAT, defaultValue: 0 },
      processingTimeMs: DataTypes.INTEGER,
      explanationText: DataTypes.TEXT,
      createdAt: { type: DataTypes.DATE, defaultValue: DataTypes.NOW },
    },
    { sequelize, tableName: "analysis", timestamps: false }
  );

  Override.init(
    {
      id: { type: DataTypes.STRING, primaryKey: true, defaultValue: () => uuidv4() },
      overrideType: { type: DataTypes.ENUM("request", "rule", "ip") },
      targetId: DataTypes.STRING,
      tenantId: { type: DataTypes.STRING, references: { model: Tenant, key: 'id' }, allowNull: true },
      action: { type: DataTypes.ENUM("allow", "monitor", "challenge", "deny") },
      operatorId: { type: DataTypes.STRING, references: { model: User, key: 'id' } },
      reason: DataTypes.TEXT,
      expiresAt: DataTypes.DATE,
      isActive: { type: DataTypes.BOOLEAN, defaultValue: true },
      createdAt: { type: DataTypes.DATE, defaultValue: DataTypes.NOW },
    },
    { sequelize, tableName: "overrides", timestamps: false }
  );

  Alert.init(
    {
      id: { type: DataTypes.STRING, primaryKey: true, defaultValue: () => uuidv4() },
      tenantId: { type: DataTypes.STRING, references: { model: Tenant, key: 'id' }, allowNull: true },
      severity: DataTypes.STRING,
      type: DataTypes.STRING,
      title: DataTypes.STRING,
      message: DataTypes.TEXT,
      metadata: DataTypes.JSON,
      isRead: { type: DataTypes.BOOLEAN, defaultValue: false },
      isDismissed: { type: DataTypes.BOOLEAN, defaultValue: false },
      createdAt: { type: DataTypes.DATE, defaultValue: DataTypes.NOW },
    },
    { sequelize, tableName: "alerts", timestamps: false }
  );

  Webhook.init(
    {
      id: { type: DataTypes.STRING, primaryKey: true, defaultValue: () => uuidv4() },
      tenantId: { type: DataTypes.STRING, references: { model: Tenant, key: 'id' }, allowNull: true },
      name: DataTypes.STRING,
      url: DataTypes.STRING,
      secret: DataTypes.STRING,
      events: DataTypes.JSON,
      isActive: { type: DataTypes.BOOLEAN, defaultValue: true },
      lastTriggeredAt: DataTypes.DATE,
      failureCount: { type: DataTypes.INTEGER, defaultValue: 0 },
      createdAt: { type: DataTypes.DATE, defaultValue: DataTypes.NOW },
    },
    { sequelize, tableName: "webhooks", timestamps: false }
  );

  IpList.init(
    {
      id: { type: DataTypes.STRING, primaryKey: true, defaultValue: () => uuidv4() },
      tenantId: { type: DataTypes.STRING, references: { model: Tenant, key: 'id' }, allowNull: true },
      ipAddress: DataTypes.STRING,
      listType: DataTypes.STRING,
      reason: DataTypes.TEXT,
      expiresAt: DataTypes.DATE,
      createdBy: { type: DataTypes.STRING, references: { model: User, key: 'id' }, allowNull: true },
      createdAt: { type: DataTypes.DATE, defaultValue: DataTypes.NOW },
    },
    { sequelize, tableName: "ip_lists", timestamps: false }
  );

  AuditFile.init(
    {
      id: { type: DataTypes.STRING, primaryKey: true, defaultValue: () => uuidv4() },
      tenantId: { type: DataTypes.STRING, references: { model: Tenant, key: 'id' }, allowNull: false },
      requestId: { type: DataTypes.STRING, references: { model: Request, key: 'id' }, allowNull: true },
      fileType: { type: DataTypes.STRING, allowNull: false },
      pathOnDisk: { type: DataTypes.STRING, allowNull: false },
      sizeBytes: DataTypes.INTEGER,
      mimeType: DataTypes.STRING,
      isCompressed: { type: DataTypes.BOOLEAN, defaultValue: false },
      createdAt: { type: DataTypes.DATE, defaultValue: DataTypes.NOW },
    },
    { sequelize, tableName: "audit_files", timestamps: false }
  );

  AnalyticsAggregate.init(
    {
      id: { type: DataTypes.STRING, primaryKey: true, defaultValue: () => uuidv4() },
      tenantId: { type: DataTypes.STRING, references: { model: Tenant, key: 'id' }, allowNull: false },
      periodStart: { type: DataTypes.DATE, allowNull: false },
      periodEnd: { type: DataTypes.DATE, allowNull: false },
      periodType: { type: DataTypes.STRING, allowNull: false },
      totalRequests: { type: DataTypes.INTEGER, defaultValue: 0 },
      blockedRequests: { type: DataTypes.INTEGER, defaultValue: 0 },
      monitoredRequests: { type: DataTypes.INTEGER, defaultValue: 0 },
      allowedRequests: { type: DataTypes.INTEGER, defaultValue: 0 },
      challengedRequests: { type: DataTypes.INTEGER, defaultValue: 0 },
      uniqueIps: { type: DataTypes.INTEGER, defaultValue: 0 },
      avgScore: { type: DataTypes.FLOAT, defaultValue: 0 },
      topRulesJson: DataTypes.JSON,
      topIpsJson: DataTypes.JSON,
      topPathsJson: DataTypes.JSON,
      createdAt: { type: DataTypes.DATE, defaultValue: DataTypes.NOW },
    },
    { sequelize, tableName: "analytics_aggregates", timestamps: false }
  );
}

// Behavioral Profiles
export interface BehavioralProfileAttributes {
  id: string;
  email: string;
  tenantId?: string;
  totalAttempts: number;
  failedAttempts: number;
  successfulAttempts: number;
  lastAttempt?: Date;
  isLocked: boolean;
  lockExpiresAt?: Date;
  botScore: number;
  anomalyScore: number;
  riskLevel: string;
  ipsJson?: any;
  createdAt: Date;
  updatedAt: Date;
}
export interface BehavioralProfileCreationAttributes extends Optional<BehavioralProfileAttributes, "id" | "createdAt" | "updatedAt"> {}
export class BehavioralProfile extends Model<BehavioralProfileAttributes, BehavioralProfileCreationAttributes> implements BehavioralProfileAttributes {
  declare id: string;
  declare email: string;
  declare tenantId?: string;
  declare totalAttempts: number;
  declare failedAttempts: number;
  declare successfulAttempts: number;
  declare lastAttempt?: Date;
  declare isLocked: boolean;
  declare lockExpiresAt?: Date;
  declare botScore: number;
  declare anomalyScore: number;
  declare riskLevel: string;
  declare ipsJson?: any;
  declare readonly createdAt: Date;
  declare readonly updatedAt: Date;
}

// Behavioral Events
export interface BehavioralEventAttributes {
  id: string;
  profileId: string;
  email: string;
  eventType: string;
  ipAddress?: string;
  userAgent?: string;
  success?: boolean;
  score?: number;
  reason?: string;
  createdAt: Date;
}
export interface BehavioralEventCreationAttributes extends Optional<BehavioralEventAttributes, "id" | "createdAt"> {}
export class BehavioralEvent extends Model<BehavioralEventAttributes, BehavioralEventCreationAttributes> implements BehavioralEventAttributes {
  declare id: string;
  declare profileId: string;
  declare email: string;
  declare eventType: string;
  declare ipAddress?: string;
  declare userAgent?: string;
  declare success?: boolean;
  declare score?: number;
  declare reason?: string;
  declare readonly createdAt: Date;
}

export function initDDoSModels() {
  DDoSEvent.init(
    {
      id: { type: DataTypes.STRING, primaryKey: true, defaultValue: () => uuidv4() },
      tenantId: { type: DataTypes.STRING, references: { model: Tenant, key: 'id' }, allowNull: false },
      clientIp: { type: DataTypes.STRING, allowNull: false },
      severity: { type: DataTypes.ENUM("low", "medium", "high", "critical"), allowNull: false },
      eventType: { type: DataTypes.ENUM("volumetric", "connection_limit", "rate_limit", "protocol_anomaly", "normalization_violation"), allowNull: false },
      requestsPerSecond: DataTypes.INTEGER,
      uniqueIPs: DataTypes.INTEGER,
      volumetricScore: DataTypes.REAL,
      reason: { type: DataTypes.TEXT, allowNull: false },
      action: { type: DataTypes.ENUM("allow", "throttle", "challenge", "block"), allowNull: false },
      metadata: DataTypes.JSON,
      createdAt: { type: DataTypes.DATE, defaultValue: DataTypes.NOW },
    },
    { sequelize, tableName: "ddos_events", timestamps: false }
  );
}

// Compliance Framework Types
export interface ComplianceFrameworkAttributes {
  id: string;
  name: string;
  description: string;
  category: string;
  region: string;
  ruleCount: number;
  createdAt: Date;
}
export interface ComplianceFrameworkCreationAttributes extends Optional<ComplianceFrameworkAttributes, "id" | "createdAt"> {}
export class ComplianceFramework extends Model<ComplianceFrameworkAttributes, ComplianceFrameworkCreationAttributes> implements ComplianceFrameworkAttributes {
  declare id: string;
  declare name: string;
  declare description: string;
  declare category: string;
  declare region: string;
  declare ruleCount: number;
  declare readonly createdAt: Date;
}

// Compliance Rule Types
export interface ComplianceRuleAttributes {
  id: string;
  wafRuleId: string;
  complianceFrameworkId: string;
  complianceRuleId: string;
  mappedCategory: string;
  severity: "mandatory" | "recommended" | "optional";
  description: string;
  proof: string;
  createdAt: Date;
}
export interface ComplianceRuleCreationAttributes extends Optional<ComplianceRuleAttributes, "id" | "createdAt"> {}
export class ComplianceRule extends Model<ComplianceRuleAttributes, ComplianceRuleCreationAttributes> implements ComplianceRuleAttributes {
  declare id: string;
  declare wafRuleId: string;
  declare complianceFrameworkId: string;
  declare complianceRuleId: string;
  declare mappedCategory: string;
  declare severity: "mandatory" | "recommended" | "optional";
  declare description: string;
  declare proof: string;
  declare readonly createdAt: Date;
}

// Tenant Compliance Types
export interface TenantComplianceAttributes {
  id: string;
  tenantId: string;
  complianceFrameworkId: string;
  enabled: boolean;
  complianceStatus: "active" | "in-review" | "failed" | "compliant";
  lastAuditDate?: Date;
  nextAuditDate?: Date;
  selectedRuleIds?: string[];
  enabledRuleIds?: string[];
  createdAt: Date;
}
export interface TenantComplianceCreationAttributes extends Optional<TenantComplianceAttributes, "id" | "createdAt"> {}
export class TenantCompliance extends Model<TenantComplianceAttributes, TenantComplianceCreationAttributes> implements TenantComplianceAttributes {
  declare id: string;
  declare tenantId: string;
  declare complianceFrameworkId: string;
  declare enabled: boolean;
  declare complianceStatus: "active" | "in-review" | "failed" | "compliant";
  declare lastAuditDate?: Date;
  declare nextAuditDate?: Date;
  declare selectedRuleIds?: string[];
  declare enabledRuleIds?: string[];
  declare readonly createdAt: Date;
}

// Compliance Audit Types
export interface ComplianceAuditAttributes {
  id: string;
  tenantId: string;
  complianceFrameworkId: string;
  auditDate: Date;
  totalRequirements: number;
  metRequirements: number;
  failedRequirements: number;
  compliancePercentage: number;
  failedRules?: any[];
  actionItems?: any[];
  auditorNotes?: string;
  action?: string;
  details?: string;
  userEmail?: string;
  frameworkName?: string;
  createdAt: Date;
}
export interface ComplianceAuditCreationAttributes extends Optional<ComplianceAuditAttributes, "id" | "createdAt"> {}
export class ComplianceAudit extends Model<ComplianceAuditAttributes, ComplianceAuditCreationAttributes> implements ComplianceAuditAttributes {
  declare id: string;
  declare tenantId: string;
  declare complianceFrameworkId: string;
  declare auditDate: Date;
  declare totalRequirements: number;
  declare metRequirements: number;
  declare failedRequirements: number;
  declare compliancePercentage: number;
  declare failedRules?: any[];
  declare actionItems?: any[];
  declare auditorNotes?: string;
  declare action?: string;
  declare details?: string;
  declare userEmail?: string;
  declare frameworkName?: string;
  declare readonly createdAt: Date;
}

export function initComplianceModels() {
  ComplianceFramework.init(
    {
      id: { type: DataTypes.STRING, primaryKey: true, defaultValue: () => uuidv4() },
      name: { type: DataTypes.STRING, allowNull: false, unique: true },
      description: { type: DataTypes.TEXT, allowNull: false },
      category: { type: DataTypes.STRING, allowNull: false },
      region: { type: DataTypes.STRING, allowNull: false },
      ruleCount: { type: DataTypes.INTEGER, defaultValue: 0 },
      createdAt: { type: DataTypes.DATE, defaultValue: DataTypes.NOW },
    },
    { sequelize, tableName: "compliance_frameworks", timestamps: false }
  );

  ComplianceRule.init(
    {
      id: { type: DataTypes.STRING, primaryKey: true, defaultValue: () => uuidv4() },
      wafRuleId: { type: DataTypes.STRING, references: { model: WafRule, key: 'id' }, allowNull: false },
      complianceFrameworkId: { type: DataTypes.STRING, references: { model: ComplianceFramework, key: 'id' }, allowNull: false },
      complianceRuleId: { type: DataTypes.STRING, allowNull: false },
      mappedCategory: { type: DataTypes.STRING, allowNull: false },
      severity: { type: DataTypes.ENUM("mandatory", "recommended", "optional"), allowNull: false },
      description: { type: DataTypes.TEXT, allowNull: false },
      proof: { type: DataTypes.TEXT, allowNull: false },
      createdAt: { type: DataTypes.DATE, defaultValue: DataTypes.NOW },
    },
    { sequelize, tableName: "compliance_rules", timestamps: false }
  );

  TenantCompliance.init(
    {
      id: { type: DataTypes.STRING, primaryKey: true, defaultValue: () => uuidv4() },
      tenantId: { type: DataTypes.STRING, references: { model: Tenant, key: 'id' }, allowNull: false },
      complianceFrameworkId: { type: DataTypes.STRING, references: { model: ComplianceFramework, key: 'id' }, allowNull: false },
      enabled: { type: DataTypes.BOOLEAN, defaultValue: false },
      complianceStatus: { type: DataTypes.ENUM("active", "in-review", "failed", "compliant"), defaultValue: "active" },
      lastAuditDate: DataTypes.DATE,
      nextAuditDate: DataTypes.DATE,
      selectedRuleIds: DataTypes.JSON,
      enabledRuleIds: DataTypes.JSON,
      createdAt: { type: DataTypes.DATE, defaultValue: DataTypes.NOW },
    },
    { sequelize, tableName: "tenant_compliance", timestamps: false }
  );

  ComplianceAudit.init(
    {
      id: { type: DataTypes.STRING, primaryKey: true, defaultValue: () => uuidv4() },
      tenantId: { type: DataTypes.STRING, references: { model: Tenant, key: 'id' }, allowNull: false },
      complianceFrameworkId: { type: DataTypes.STRING, references: { model: ComplianceFramework, key: 'id' }, allowNull: false },
      auditDate: { type: DataTypes.DATE, defaultValue: DataTypes.NOW },
      totalRequirements: { type: DataTypes.INTEGER, allowNull: false },
      metRequirements: { type: DataTypes.INTEGER, allowNull: false },
      failedRequirements: { type: DataTypes.INTEGER, allowNull: false },
      compliancePercentage: { type: DataTypes.REAL, allowNull: false },
      failedRules: DataTypes.JSON,
      actionItems: DataTypes.JSON,
      auditorNotes: DataTypes.TEXT,
      action: { type: DataTypes.STRING, defaultValue: "review" },
      details: DataTypes.TEXT,
      userEmail: DataTypes.STRING,
      frameworkName: DataTypes.STRING,
      createdAt: { type: DataTypes.DATE, defaultValue: DataTypes.NOW },
    },
    { sequelize, tableName: "compliance_audits", timestamps: false }
  );
}

export function initComplianceAssociations() {
  // ComplianceFramework associations
  ComplianceFramework.hasMany(ComplianceRule, {
    foreignKey: 'complianceFrameworkId',
    as: 'rules',
  });
  ComplianceRule.belongsTo(ComplianceFramework, {
    foreignKey: 'complianceFrameworkId',
    as: 'framework',
  });

  // TenantCompliance associations
  Tenant.hasMany(TenantCompliance, {
    foreignKey: 'tenantId',
    as: 'compliance',
  });
  TenantCompliance.belongsTo(Tenant, {
    foreignKey: 'tenantId',
    as: 'tenant',
  });

  ComplianceFramework.hasMany(TenantCompliance, {
    foreignKey: 'complianceFrameworkId',
    as: 'tenants',
  });
  TenantCompliance.belongsTo(ComplianceFramework, {
    foreignKey: 'complianceFrameworkId',
    as: 'framework',
  });

  // ComplianceAudit associations
  Tenant.hasMany(ComplianceAudit, {
    foreignKey: 'tenantId',
    as: 'audits',
  });
  ComplianceAudit.belongsTo(Tenant, {
    foreignKey: 'tenantId',
    as: 'tenant',
  });

  ComplianceFramework.hasMany(ComplianceAudit, {
    foreignKey: 'complianceFrameworkId',
    as: 'audits',
  });
  ComplianceAudit.belongsTo(ComplianceFramework, {
    foreignKey: 'complianceFrameworkId',
    as: 'framework',
  });

  // WafRule associations
  WafRule.hasMany(ComplianceRule, {
    foreignKey: 'wafRuleId',
    as: 'compliance',
  });
  ComplianceRule.belongsTo(WafRule, {
    foreignKey: 'wafRuleId',
    as: 'wafRule',
  });
}

export function initBehavioralModels() {
  BehavioralProfile.init(
    {
      id: { type: DataTypes.STRING, primaryKey: true, defaultValue: () => uuidv4() },
      email: { type: DataTypes.STRING, unique: true, allowNull: false },
      tenantId: { type: DataTypes.STRING, references: { model: Tenant, key: 'id' }, allowNull: true },
      totalAttempts: { type: DataTypes.INTEGER, defaultValue: 0 },
      failedAttempts: { type: DataTypes.INTEGER, defaultValue: 0 },
      successfulAttempts: { type: DataTypes.INTEGER, defaultValue: 0 },
      lastAttempt: DataTypes.DATE,
      isLocked: { type: DataTypes.BOOLEAN, defaultValue: false },
      lockExpiresAt: DataTypes.DATE,
      botScore: { type: DataTypes.REAL, defaultValue: 0 },
      anomalyScore: { type: DataTypes.REAL, defaultValue: 0 },
      riskLevel: { type: DataTypes.STRING, defaultValue: "low" },
      ipsJson: DataTypes.JSON,
      createdAt: { type: DataTypes.DATE, defaultValue: DataTypes.NOW },
      updatedAt: { type: DataTypes.DATE, defaultValue: DataTypes.NOW },
    },
    { sequelize, tableName: "behavioral_profiles", timestamps: false }
  );

  BehavioralEvent.init(
    {
      id: { type: DataTypes.STRING, primaryKey: true, defaultValue: () => uuidv4() },
      profileId: { type: DataTypes.STRING, references: { model: BehavioralProfile, key: 'id' }, allowNull: false },
      email: { type: DataTypes.STRING, allowNull: false },
      eventType: { type: DataTypes.STRING, allowNull: false },
      ipAddress: DataTypes.STRING,
      userAgent: DataTypes.TEXT,
      success: DataTypes.BOOLEAN,
      score: DataTypes.REAL,
      reason: DataTypes.TEXT,
      createdAt: { type: DataTypes.DATE, defaultValue: DataTypes.NOW },
    },
    { sequelize, tableName: "behavioral_events", timestamps: false }
  );
}
