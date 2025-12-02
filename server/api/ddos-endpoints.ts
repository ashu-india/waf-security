/**
 * DDoS Detection API Endpoints - TENANT-SCOPED
 * Provides real-time DDoS metrics, configuration, and control per tenant
 */

import type { Express } from 'express';
import { ddosDetection } from '../waf/ddos-detection';
import { DDoSConfigSchema } from '../schemas/ddos-validation';

export function registerDDoSEndpoints(app: Express, requireAuth: any, requireRole?: any) {
  /**
   * GET /api/tenants/:tenantId/ddos/metrics
   * Get DDoS detection metrics for specific tenant
   */
  app.get('/api/tenants/:tenantId/ddos/metrics', requireAuth, (req, res) => {
    try {
      const { tenantId } = req.params;
      const metrics = ddosDetection.getTenantMetrics(tenantId);
      res.json({
        success: true,
        tenantId,
        metrics,
        timestamp: new Date().toISOString(),
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: error instanceof Error ? error.message : 'Failed to get DDoS metrics',
      });
    }
  });

  /**
   * GET /api/ddos/metrics-all
   * Get all tenants' DDoS metrics (admin only)
   */
  app.get('/api/ddos/metrics-all', requireAuth, requireRole?.('admin'), (req, res) => {
    try {
      const allMetrics = ddosDetection.getAllTenantMetrics();
      res.json({
        success: true,
        metrics: Object.fromEntries(allMetrics),
        timestamp: new Date().toISOString(),
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: error instanceof Error ? error.message : 'Failed to get all DDoS metrics',
      });
    }
  });

  /**
   * POST /api/tenants/:tenantId/ddos/config
   * Update DDoS detection configuration for specific tenant
   */
  app.post('/api/tenants/:tenantId/ddos/config', requireAuth, requireRole?.('admin'), (req, res) => {
    try {
      const { tenantId } = req.params;
      const { config } = req.body;
      if (!config) {
        return res.status(400).json({
          success: false,
          error: 'Configuration required',
        });
      }

      // Validate configuration using Zod
      const validationResult = DDoSConfigSchema.safeParse(config);
      if (!validationResult.success) {
        return res.status(400).json({
          success: false,
          error: 'Invalid configuration',
          details: validationResult.error.errors.map(e => ({
            field: e.path.join('.'),
            message: e.message,
          })),
        });
      }

      ddosDetection.updateTenantConfig(tenantId, validationResult.data);
      const updatedConfig = ddosDetection.getTenantConfig(tenantId);

      res.json({
        success: true,
        tenantId,
        message: 'DDoS configuration updated',
        config: updatedConfig,
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: error instanceof Error ? error.message : 'Failed to update configuration',
      });
    }
  });

  /**
   * GET /api/tenants/:tenantId/ddos/config
   * Get DDoS detection configuration for specific tenant
   */
  app.get('/api/tenants/:tenantId/ddos/config', requireAuth, (req, res) => {
    try {
      const { tenantId } = req.params;
      const config = ddosDetection.getTenantConfig(tenantId);
      res.json({
        success: true,
        tenantId,
        config,
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: error instanceof Error ? error.message : 'Failed to get configuration',
      });
    }
  });

  /**
   * POST /api/tenants/:tenantId/ddos/reset
   * Reset DDoS detection state for specific tenant
   */
  app.post('/api/tenants/:tenantId/ddos/reset', requireAuth, requireRole?.('admin'), (req, res) => {
    try {
      const { tenantId } = req.params;
      ddosDetection.resetTenant(tenantId);
      res.json({
        success: true,
        tenantId,
        message: 'DDoS detection state reset for tenant',
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: error instanceof Error ? error.message : 'Failed to reset',
      });
    }
  });

  /**
   * POST /api/ddos/reset-all
   * Reset DDoS detection state for all tenants (admin only)
   */
  app.post('/api/ddos/reset-all', requireAuth, requireRole?.('admin'), (req, res) => {
    try {
      ddosDetection.resetAll();
      res.json({
        success: true,
        message: 'DDoS detection state reset for all tenants',
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: error instanceof Error ? error.message : 'Failed to reset all',
      });
    }
  });
}
