import {
  type InsertUser,
  type InsertTenant,
  type InsertPolicy,
  type InsertWafRule,
  type InsertRequest,
  type InsertAnalysis,
  type InsertOverride,
  type InsertAlert,
  type InsertWebhook,
  type InsertIpList,
} from "./schemas";
import {
  User as UserModel,
  Tenant as TenantModel,
  Policy as PolicyModel,
  WafRule as WafRuleModel,
  Request as RequestModel,
  Analysis as AnalysisModel,
  Override as OverrideModel,
  Alert as AlertModel,
  Webhook as WebhookModel,
  IpList as IpListModel,
  type UserAttributes as User,
  type TenantAttributes as Tenant,
  type PolicyAttributes as Policy,
  type WafRuleAttributes as WafRule,
  type RequestAttributes as Request,
  type AnalysisAttributes as Analysis,
  type OverrideAttributes as Override,
  type AlertAttributes as Alert,
  type WebhookAttributes as Webhook,
  type IpListAttributes as IpList,
} from "./models";

export interface DashboardStats {
  totalRequests: number;
  blockedRequests: number;
  flaggedRequests: number;
  allowedRequests: number;
  blockPercentage: number;
  activeTenants: number;
  activeRules: number;
  recentAlerts: Alert[];
  requestTrend?: number;
  blockTrend?: number;
  flagTrend?: number;
}

type UpsertUser = Partial<User>;
import { Op } from "sequelize";

export interface IStorage {
  // Users
  getUser(id: string): Promise<User | undefined>;
  getUserByEmail(email: string): Promise<User | undefined>;
  upsertUser(user: UpsertUser): Promise<User>;
  getUsers(): Promise<User[]>;
  createUser(user: InsertUser): Promise<User>;
  updateUser(id: string, data: Partial<User>): Promise<User | undefined>;
  deleteUser(id: string): Promise<void>;

  // Tenants
  getTenants(): Promise<Tenant[]>;
  getTenant(id: string): Promise<Tenant | undefined>;
  createTenant(tenant: InsertTenant): Promise<Tenant>;
  updateTenant(id: string, data: Partial<Tenant>): Promise<Tenant | undefined>;
  deleteTenant(id: string): Promise<void>;

  // Policies
  getPolicies(): Promise<Policy[]>;
  getPolicy(id: string): Promise<Policy | undefined>;
  getPolicyByTenant(tenantId: string): Promise<Policy | undefined>;
  createPolicy(policy: InsertPolicy): Promise<Policy>;
  updatePolicy(id: string, data: Partial<Policy>): Promise<Policy | undefined>;
  deletePolicy(id: string): Promise<void>;

  // WAF Rules
  getRules(): Promise<WafRule[]>;
  getRule(id: string): Promise<WafRule | undefined>;
  getRulesByTenant(tenantId: string | null): Promise<WafRule[]>;
  createRule(rule: InsertWafRule): Promise<WafRule>;
  updateRule(id: string, data: Partial<WafRule>): Promise<WafRule | undefined>;
  deleteRule(id: string): Promise<void>;

  // Requests
  getRequests(tenantId?: string): Promise<Request[]>;
  getRequest(id: string): Promise<Request | undefined>;
  createRequest(request: InsertRequest): Promise<Request>;
  getRequestWithAnalysis(id: string): Promise<Request & { analysis?: Analysis } | undefined>;
  getRequestsWithAnalysis(tenantId?: string): Promise<(Request & { analysis?: Analysis })[]>;
  anonymizeOldIPs(tenantId: string, anonymizeDays: number): Promise<number>;

  // Analysis
  createAnalysis(analysisData: InsertAnalysis): Promise<Analysis>;

  // Overrides
  createOverride(override: InsertOverride): Promise<Override>;
  getOverridesByTenant(tenantId: string): Promise<Override[]>;

  // Alerts
  getAlerts(): Promise<Alert[]>;
  getAlert(id: string): Promise<Alert | undefined>;
  createAlert(alert: InsertAlert): Promise<Alert>;
  updateAlert(id: string, data: Partial<Alert>): Promise<Alert | undefined>;
  markAllAlertsRead(): Promise<void>;

  // Webhooks
  getWebhooks(): Promise<Webhook[]>;
  getWebhook(id: string): Promise<Webhook | undefined>;
  createWebhook(webhook: InsertWebhook): Promise<Webhook>;
  updateWebhook(id: string, data: Partial<Webhook>): Promise<Webhook | undefined>;
  deleteWebhook(id: string): Promise<void>;

  // Export
  getRequestsForExport(tenantId?: string, startDate?: Date, endDate?: Date): Promise<Request[]>;
  deleteOldRequests(tenantId: string, retentionDays: number): Promise<number>;

  // IP Lists
  createIpList(ipList: InsertIpList): Promise<IpList>;
  getIpListsByTenant(tenantId: string): Promise<IpList[]>;

  // Dashboard
  getDashboardStats(): Promise<DashboardStats>;

  // Behavioral Profiles
  getBehavioralProfile(email: string): Promise<any>;
  createOrUpdateBehavioralProfile(email: string, data: any): Promise<any>;
  recordBehavioralEvent(profileId: string, email: string, eventData: any): Promise<void>;
  getBehavioralEvents(email: string, limit?: number): Promise<any[]>;
  getBehavioralProfiles(tenantId?: string, limit?: number): Promise<any[]>;
}

export class DatabaseStorage implements IStorage {
  // Users
  async getUser(id: string): Promise<User | undefined> {
    const user = await UserModel.findByPk(id);
    return user?.toJSON() as User | undefined;
  }

  async getUserByEmail(email: string): Promise<User | undefined> {
    const user = await UserModel.findOne({ where: { email } });
    return user?.toJSON() as User | undefined;
  }

  async upsertUser(user: UpsertUser): Promise<User> {
    const [u] = await UserModel.upsert(user as any);
    return u.toJSON() as User;
  }

  async getUsers(): Promise<User[]> {
    const users = await UserModel.findAll();
    return users.map(u => u.toJSON() as User);
  }

  async createUser(user: InsertUser): Promise<User> {
    const created = await UserModel.create(user as any);
    return created.toJSON() as User;
  }

  async updateUser(id: string, data: Partial<User>): Promise<User | undefined> {
    const user = await UserModel.findByPk(id);
    if (!user) return undefined;
    await user.update(data);
    return user.toJSON() as User;
  }

  async deleteUser(id: string): Promise<void> {
    await UserModel.destroy({ where: { id } });
  }

  // Tenants
  async getTenants(): Promise<Tenant[]> {
    const tenants = await TenantModel.findAll();
    return tenants.map(t => t.toJSON() as Tenant);
  }

  async getTenant(id: string): Promise<Tenant | undefined> {
    const tenant = await TenantModel.findByPk(id);
    return tenant?.toJSON() as Tenant | undefined;
  }

  async createTenant(tenant: InsertTenant): Promise<Tenant> {
    const created = await TenantModel.create(tenant as any);
    return created.toJSON() as Tenant;
  }

  async updateTenant(id: string, data: Partial<Tenant>): Promise<Tenant | undefined> {
    const tenant = await TenantModel.findByPk(id);
    if (!tenant) return undefined;
    await tenant.update(data);
    return tenant.toJSON() as Tenant;
  }

  async deleteTenant(id: string): Promise<void> {
    await TenantModel.destroy({ where: { id } });
  }

  // Policies
  async getPolicies(): Promise<Policy[]> {
    const policies = await PolicyModel.findAll();
    return policies.map(p => p.toJSON() as Policy);
  }

  async getPolicy(id: string): Promise<Policy | undefined> {
    const policy = await PolicyModel.findByPk(id);
    return policy?.toJSON() as Policy | undefined;
  }

  async getPolicyByTenant(tenantId: string): Promise<Policy | undefined> {
    const policy = await PolicyModel.findOne({ where: { tenantId, isDefault: true } });
    return policy?.toJSON() as Policy | undefined;
  }

  async createPolicy(policy: InsertPolicy): Promise<Policy> {
    const created = await PolicyModel.create(policy as any);
    return created.toJSON() as Policy;
  }

  async updatePolicy(id: string, data: Partial<Policy>): Promise<Policy | undefined> {
    const policy = await PolicyModel.findByPk(id);
    if (!policy) return undefined;
    await policy.update(data);
    return policy.toJSON() as Policy;
  }

  async deletePolicy(id: string): Promise<void> {
    await PolicyModel.destroy({ where: { id } });
  }

  // WAF Rules
  async getRules(): Promise<WafRule[]> {
    const rules = await WafRuleModel.findAll();
    return rules.map(r => r.toJSON() as WafRule);
  }

  async getRule(id: string): Promise<WafRule | undefined> {
    const rule = await WafRuleModel.findByPk(id);
    return rule?.toJSON() as WafRule | undefined;
  }

  async getRulesByTenant(tenantId: string | null): Promise<WafRule[]> {
    const rules = await WafRuleModel.findAll({
      where: tenantId ? { tenantId } : { tenantId: null }
    });
    return rules.map(r => r.toJSON() as WafRule);
  }

  async createRule(rule: InsertWafRule): Promise<WafRule> {
    const created = await WafRuleModel.create(rule as any);
    return created.toJSON() as WafRule;
  }

  async updateRule(id: string, data: Partial<WafRule>): Promise<WafRule | undefined> {
    const rule = await WafRuleModel.findByPk(id);
    if (!rule) return undefined;
    await rule.update(data);
    return rule.toJSON() as WafRule;
  }

  async deleteRule(id: string): Promise<void> {
    await WafRuleModel.destroy({ where: { id } });
  }

  // Requests
  async getRequests(tenantId?: string): Promise<Request[]> {
    const requests = await RequestModel.findAll(tenantId ? { where: { tenantId } } : {});
    return requests.map(r => r.toJSON() as Request);
  }

  async getRequest(id: string): Promise<Request | undefined> {
    const request = await RequestModel.findByPk(id);
    return request?.toJSON() as Request | undefined;
  }

  async createRequest(request: InsertRequest): Promise<Request> {
    const created = await RequestModel.create(request as any);
    return created.toJSON() as Request;
  }

  async getRequestWithAnalysis(id: string): Promise<Request & { analysis?: Analysis } | undefined> {
    const request = await RequestModel.findByPk(id);
    if (!request) return undefined;
    const analysis = await AnalysisModel.findOne({ where: { requestId: id } });
    return {
      ...request.toJSON() as Request,
      analysis: analysis?.toJSON() as Analysis | undefined
    };
  }

  async getRequestsWithAnalysis(tenantId?: string): Promise<(Request & { analysis?: Analysis })[]> {
    const requests = await RequestModel.findAll(tenantId ? { where: { tenantId } } : {});
    const results: (Request & { analysis?: Analysis })[] = [];
    for (const request of requests) {
      const analysis = await AnalysisModel.findOne({ where: { requestId: request.id } });
      results.push({
        ...request.toJSON() as Request,
        analysis: analysis?.toJSON() as Analysis | undefined
      });
    }
    return results;
  }

  async anonymizeOldIPs(tenantId: string, anonymizeDays: number): Promise<number> {
    const cutoffDate = new Date(Date.now() - anonymizeDays * 24 * 60 * 60 * 1000);
    const result = await RequestModel.update(
      { clientIp: null, clientIpAnonymized: true },
      { where: { tenantId, timestamp: { [Op.lt]: cutoffDate } } }
    );
    return result[0];
  }

  // Analysis
  async createAnalysis(analysisData: InsertAnalysis): Promise<Analysis> {
    const created = await AnalysisModel.create(analysisData as any);
    return created.toJSON() as Analysis;
  }

  // Overrides
  async createOverride(override: InsertOverride): Promise<Override> {
    const created = await OverrideModel.create(override as any);
    return created.toJSON() as Override;
  }

  async getOverridesByTenant(tenantId: string): Promise<Override[]> {
    const overrides = await OverrideModel.findAll({
      where: { tenantId, isActive: true, expiresAt: { [Op.or]: [null, { [Op.gt]: new Date() }] } }
    });
    return overrides.map(o => o.toJSON() as Override);
  }

  // Alerts
  async getAlerts(): Promise<Alert[]> {
    const alerts = await AlertModel.findAll({ order: [['createdAt', 'DESC']] });
    return alerts.map(a => a.toJSON() as Alert);
  }

  async getAlert(id: string): Promise<Alert | undefined> {
    const alert = await AlertModel.findByPk(id);
    return alert?.toJSON() as Alert | undefined;
  }

  async createAlert(alert: InsertAlert): Promise<Alert> {
    const created = await AlertModel.create(alert as any);
    return created.toJSON() as Alert;
  }

  async updateAlert(id: string, data: Partial<Alert>): Promise<Alert | undefined> {
    const alert = await AlertModel.findByPk(id);
    if (!alert) return undefined;
    await alert.update(data);
    return alert.toJSON() as Alert;
  }

  async markAllAlertsRead(): Promise<void> {
    await AlertModel.update({ isRead: true }, { where: {} });
  }

  // Webhooks
  async getWebhooks(): Promise<Webhook[]> {
    const webhooks = await WebhookModel.findAll();
    return webhooks.map(w => w.toJSON() as Webhook);
  }

  async getWebhook(id: string): Promise<Webhook | undefined> {
    const webhook = await WebhookModel.findByPk(id);
    return webhook?.toJSON() as Webhook | undefined;
  }

  async createWebhook(webhook: InsertWebhook): Promise<Webhook> {
    const created = await WebhookModel.create(webhook as any);
    return created.toJSON() as Webhook;
  }

  async updateWebhook(id: string, data: Partial<Webhook>): Promise<Webhook | undefined> {
    const webhook = await WebhookModel.findByPk(id);
    if (!webhook) return undefined;
    await webhook.update(data);
    return webhook.toJSON() as Webhook;
  }

  async deleteWebhook(id: string): Promise<void> {
    await WebhookModel.destroy({ where: { id } });
  }

  // Export
  async getRequestsForExport(tenantId?: string, startDate?: Date, endDate?: Date): Promise<Request[]> {
    const where: any = {};
    if (tenantId) where.tenantId = tenantId;
    if (startDate || endDate) {
      where.timestamp = {};
      if (startDate) where.timestamp[Op.gte] = startDate;
      if (endDate) where.timestamp[Op.lte] = endDate;
    }
    const requests = await RequestModel.findAll({ where });
    return requests.map(r => r.toJSON() as Request);
  }

  async deleteOldRequests(tenantId: string, retentionDays: number): Promise<number> {
    const cutoffDate = new Date(Date.now() - retentionDays * 24 * 60 * 60 * 1000);
    const result = await RequestModel.destroy({
      where: { tenantId, timestamp: { [Op.lt]: cutoffDate } }
    });
    return result;
  }

  // IP Lists
  async createIpList(ipList: InsertIpList): Promise<IpList> {
    const created = await IpListModel.create(ipList as any);
    return created.toJSON() as IpList;
  }

  async getIpListsByTenant(tenantId: string): Promise<IpList[]> {
    const lists = await IpListModel.findAll({ where: { tenantId } });
    return lists.map(l => l.toJSON() as IpList);
  }

  // Dashboard
  async getDashboardStats(): Promise<DashboardStats> {
    const requestCount = await RequestModel.count();
    const tenantCount = await TenantModel.count();
    const userCount = await UserModel.count();
    const alertCount = await AlertModel.count({ where: { isRead: false } });
    const ruleCount = await WafRuleModel.count();
    const recentAlerts = await AlertModel.findAll({ limit: 5, order: [['createdAt', 'DESC']] });

    return {
      totalRequests: requestCount,
      totalTenants: tenantCount,
      totalUsers: userCount,
      openAlerts: alertCount,
      activeRules: ruleCount,
      recentAlerts: recentAlerts.map(a => a.toJSON() as Alert),
    };
  }

  // Behavioral Profiles
  async getBehavioralProfile(email: string): Promise<any> {
    return null; // Placeholder - profiles stored in memory in behavioral-analysis.ts
  }

  async createOrUpdateBehavioralProfile(email: string, data: any): Promise<any> {
    return null; // Placeholder - profiles stored in memory in behavioral-analysis.ts
  }

  async recordBehavioralEvent(profileId: string, email: string, eventData: any): Promise<void> {
    // Placeholder - events stored in memory in behavioral-analysis.ts
  }

  async getBehavioralEvents(email: string, limit = 100): Promise<any[]> {
    return []; // Placeholder - events stored in memory in behavioral-analysis.ts
  }

  async getBehavioralProfiles(tenantId?: string, limit = 100): Promise<any[]> {
    return []; // Placeholder - profiles stored in memory in behavioral-analysis.ts
  }
}

export const storage = new DatabaseStorage();
