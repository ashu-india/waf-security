import { z } from "zod";

/**
 * DDoS Configuration Validation Schemas
 */

export const DDoSConfigSchema = z.object({
  maxConnections: z.number().int().min(1).max(100000).optional(),
  maxConnectionsPerIP: z.number().int().min(1).max(10000).optional(),
  maxRequestsPerSecond: z.number().int().min(1).max(100000).optional(),
  maxRequestsPerIPPerSecond: z.number().int().min(1).max(10000).optional(),
  volumetricThreshold: z.number().int().min(1).max(100000).optional(),
  uniqueIPThreshold: z.number().int().min(1).max(10000).optional(),
  anomalyThreshold: z.number().min(0).max(1).optional(),
  enableAutomaticMitigation: z.boolean().optional(),
  graduatedResponseEnabled: z.boolean().optional(),
  enableNormalization: z.boolean().optional(),
});

export const DDoSEventSchema = z.object({
  id: z.string().uuid().optional(),
  tenantId: z.string().uuid(),
  clientIp: z.string().ip(),
  severity: z.enum(["low", "medium", "high", "critical"]),
  eventType: z.enum(["volumetric", "connection_limit", "rate_limit", "protocol_anomaly", "normalization_violation"]),
  requestsPerSecond: z.number().int().min(0).optional(),
  uniqueIPs: z.number().int().min(0).optional(),
  volumetricScore: z.number().min(0).max(1).optional(),
  reason: z.string(),
  action: z.enum(["allow", "throttle", "challenge", "block"]),
  metadata: z.record(z.any()).optional(),
  timestamp: z.date().optional(),
});

export type DDoSConfig = z.infer<typeof DDoSConfigSchema>;
export type DDoSEvent = z.infer<typeof DDoSEventSchema>;
