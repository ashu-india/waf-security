import { Request, Response, NextFunction } from "express";

interface RateLimitEntry {
  timestamps: number[];
  blocked: boolean;
  blockedUntil?: number;
}

interface TenantRateLimit {
  requests: Map<string, RateLimitEntry>;
  config: {
    windowMs: number;
    maxRequests: number;
    blockDurationMs: number;
  };
}

const globalRateLimitStore = new Map<string, RateLimitEntry>();
const tenantRateLimits = new Map<string, TenantRateLimit>();

export function rateLimit(windowMs: number = 60000, maxRequests: number = 100, blockDurationMs: number = 300000) {
  return (req: any, res: any, next: any) => {
    const key = `${req.ip}-${req.path}`;
    const now = Date.now();
    
    let entry = globalRateLimitStore.get(key);
    
    if (!entry) {
      entry = { timestamps: [now], blocked: false };
      globalRateLimitStore.set(key, entry);
      return next();
    }
    
    if (entry.blocked && entry.blockedUntil && entry.blockedUntil > now) {
      const retryAfter = Math.ceil((entry.blockedUntil - now) / 1000);
      res.set('Retry-After', retryAfter.toString());
      res.set('X-RateLimit-Limit', maxRequests.toString());
      res.set('X-RateLimit-Remaining', '0');
      res.set('X-RateLimit-Reset', Math.ceil(entry.blockedUntil / 1000).toString());
      return res.status(429).json({ 
        message: "Too many requests, please try again later",
        retryAfter 
      });
    }
    
    if (entry.blocked && (!entry.blockedUntil || entry.blockedUntil <= now)) {
      entry.blocked = false;
      entry.blockedUntil = undefined;
      entry.timestamps = [now];
    }
    
    entry.timestamps = entry.timestamps.filter(ts => ts > now - windowMs);
    entry.timestamps.push(now);
    
    const remaining = Math.max(0, maxRequests - entry.timestamps.length);
    const resetTime = now + windowMs;
    
    res.set('X-RateLimit-Limit', maxRequests.toString());
    res.set('X-RateLimit-Remaining', remaining.toString());
    res.set('X-RateLimit-Reset', Math.ceil(resetTime / 1000).toString());
    
    if (entry.timestamps.length > maxRequests) {
      entry.blocked = true;
      entry.blockedUntil = now + blockDurationMs;
      
      const retryAfter = Math.ceil(blockDurationMs / 1000);
      res.set('Retry-After', retryAfter.toString());
      return res.status(429).json({ 
        message: "Too many requests, please try again later",
        retryAfter 
      });
    }
    
    if (Math.random() < 0.01) {
      cleanupRateLimitStore(now, windowMs);
    }
    
    next();
  };
}

export function tenantRateLimit(tenantId: string, windowMs: number = 60000, maxRequests: number = 100) {
  return (req: any, res: any, next: any) => {
    const now = Date.now();
    
    let tenant = tenantRateLimits.get(tenantId);
    if (!tenant) {
      tenant = {
        requests: new Map(),
        config: { windowMs, maxRequests, blockDurationMs: 300000 }
      };
      tenantRateLimits.set(tenantId, tenant);
    }
    
    const key = req.ip;
    let entry = tenant.requests.get(key);
    
    if (!entry) {
      entry = { timestamps: [now], blocked: false };
      tenant.requests.set(key, entry);
      cleanupTenantRateLimits(tenantId, now, windowMs);
      return next();
    }
    
    if (entry.blocked) {
      if (entry.blockedUntil && entry.blockedUntil > now) {
        return res.status(429).json({ message: "Rate limit exceeded for this tenant" });
      }
      entry.blocked = false;
      entry.blockedUntil = undefined;
      entry.timestamps = [];
    }
    
    entry.timestamps = entry.timestamps.filter(ts => ts > now - windowMs);
    entry.timestamps.push(now);
    
    if (entry.timestamps.length > maxRequests) {
      entry.blocked = true;
      entry.blockedUntil = now + tenant.config.blockDurationMs;
      return res.status(429).json({ message: "Rate limit exceeded for this tenant" });
    }
    
    if (Math.random() < 0.01) {
      cleanupTenantRateLimits(tenantId, now, windowMs);
    }
    
    next();
  };
}

function cleanupTenantRateLimits(tenantId: string, now: number, windowMs: number) {
  const tenant = tenantRateLimits.get(tenantId);
  if (!tenant) return;
  
  const entries = Array.from(tenant.requests.entries());
  for (const [key, entry] of entries) {
    if (entry.blocked && entry.blockedUntil && entry.blockedUntil <= now) {
      entry.blocked = false;
      entry.blockedUntil = undefined;
      entry.timestamps = [];
    }
    
    const validTimestamps = entry.timestamps.filter(ts => ts > now - windowMs);
    if (validTimestamps.length === 0 && !entry.blocked) {
      tenant.requests.delete(key);
    } else {
      entry.timestamps = validTimestamps;
    }
  }
  
  if (tenant.requests.size > 10000) {
    const updatedEntries = Array.from(tenant.requests.entries());
    const oldestEntries = updatedEntries
      .filter(([_, e]) => !e.blocked)
      .sort((a, b) => Math.max(...a[1].timestamps, 0) - Math.max(...b[1].timestamps, 0))
      .slice(0, 5000);
    oldestEntries.forEach(([k]) => tenant.requests.delete(k));
  }
}

function cleanupRateLimitStore(now: number, windowMs: number) {
  const entries = Array.from(globalRateLimitStore.entries());
  for (const [key, entry] of entries) {
    const validTimestamps = entry.timestamps.filter(ts => ts > now - windowMs);
    
    if (entry.blocked && entry.blockedUntil && entry.blockedUntil <= now) {
      entry.blocked = false;
      entry.blockedUntil = undefined;
    }
    
    if (validTimestamps.length === 0 && !entry.blocked) {
      globalRateLimitStore.delete(key);
    } else {
      entry.timestamps = validTimestamps;
    }
  }
  
  const maxEntries = 10000;
  if (globalRateLimitStore.size > maxEntries) {
    const entriesToDelete = Array.from(globalRateLimitStore.entries())
      .filter(([_, e]) => !e.blocked)
      .sort((a, b) => Math.max(...a[1].timestamps, 0) - Math.max(...b[1].timestamps, 0))
      .slice(0, globalRateLimitStore.size - maxEntries);
    entriesToDelete.forEach(([k]) => globalRateLimitStore.delete(k));
  }
}

let cleanupInterval: NodeJS.Timeout | null = null;

export function startRateLimitCleanup(windowMs: number = 60000) {
  if (cleanupInterval) return;
  cleanupInterval = setInterval(() => {
    cleanupRateLimitStore(Date.now(), windowMs);
    
    const tenantEntries = Array.from(tenantRateLimits.entries());
    for (const [tenantId] of tenantEntries) {
      cleanupTenantRateLimits(tenantId, Date.now(), windowMs);
    }
  }, 60000);
}

export function createTenantRateLimiter(tenantId: string, windowMs: number = 60000, maxRequests: number = 100) {
  return tenantRateLimit(tenantId, windowMs, maxRequests);
}

export function requireRole(...roles: string[]) {
  return (req: any, res: any, next: any) => {
    if (!req.isAuthenticated || !req.isAuthenticated()) {
      return res.status(401).json({ message: "Unauthorized" });
    }
    if (!req.user?.role || !roles.includes(req.user.role)) {
      return res.status(403).json({ message: "Forbidden - Insufficient permissions" });
    }
    next();
  };
}

const HTML_ESCAPE_MAP: { [key: string]: string } = {
  "&": "&amp;",
  "<": "&lt;",
  ">": "&gt;",
  '"': "&quot;",
  "'": "&#x27;",
  "/": "&#x2F;",
  "`": "&#x60;",
  "=": "&#x3D;"
};

export function sanitizeInput(input: string): string {
  if (typeof input !== 'string') return input;
  return input.replace(/[&<>"'`=/]/g, (char) => HTML_ESCAPE_MAP[char] || char);
}

export function sanitizeObject(obj: any, depth: number = 0): any {
  if (depth > 10) return obj;
  
  if (typeof obj === 'string') {
    return sanitizeInput(obj);
  }
  
  if (Array.isArray(obj)) {
    return obj.map(item => sanitizeObject(item, depth + 1));
  }
  
  if (obj && typeof obj === 'object') {
    const sanitized: any = {};
    for (const key of Object.keys(obj)) {
      const sanitizedKey = sanitizeInput(key);
      sanitized[sanitizedKey] = sanitizeObject(obj[key], depth + 1);
    }
    return sanitized;
  }
  
  return obj;
}

export function securityHeaders() {
  return (req: Request, res: Response, next: NextFunction) => {
    res.set('X-Content-Type-Options', 'nosniff');
    res.set('X-Frame-Options', 'SAMEORIGIN');
    res.set('X-XSS-Protection', '1; mode=block');
    res.set('Referrer-Policy', 'strict-origin-when-cross-origin');
    res.set('Permissions-Policy', 'geolocation=(), camera=(), microphone=()');
    
    const cspDirectives = [
      "default-src 'self'",
      "script-src 'self' 'unsafe-inline' 'unsafe-eval'",
      "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
      "style-src-elem 'self' 'unsafe-inline' https://fonts.googleapis.com",
      "font-src 'self' https://fonts.gstatic.com data:",
      "img-src 'self' data: https:",
      "connect-src 'self' https: wss: ws:",
      "frame-ancestors 'self'"
    ];
    
    if (process.env.NODE_ENV === 'production') {
      res.set('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
    }
    
    res.set('Content-Security-Policy', cspDirectives.join('; '));
    
    next();
  };
}

export function requestSanitizer() {
  return (req: Request, res: Response, next: NextFunction) => {
    if (req.body && isPlainObject(req.body)) {
      sanitizePrototypePollution(req.body, new WeakSet());
    }
    
    if (req.query && isPlainObject(req.query)) {
      sanitizePrototypePollution(req.query as Record<string, unknown>, new WeakSet());
    }
    
    next();
  };
}

function isPlainObject(obj: unknown): obj is Record<string, unknown> {
  if (obj === null || typeof obj !== 'object') return false;
  if (Buffer.isBuffer(obj)) return false;
  if (Array.isArray(obj)) return false;
  const proto = Object.getPrototypeOf(obj);
  return proto === null || proto === Object.prototype;
}

function sanitizePrototypePollution(obj: Record<string, unknown>, seen: WeakSet<object>, depth = 0): void {
  if (depth > 20) return;
  if (seen.has(obj)) return;
  seen.add(obj);
  
  const dangerousKeys = ['__proto__', 'constructor', 'prototype'];
  
  for (const key of Object.keys(obj)) {
    if (dangerousKeys.includes(key)) {
      delete obj[key];
      continue;
    }
    
    const value = obj[key];
    if (value && typeof value === 'object' && isPlainObject(value)) {
      sanitizePrototypePollution(value, seen, depth + 1);
    }
  }
}

export function validateContentType() {
  return (req: Request, res: Response, next: NextFunction) => {
    if (['POST', 'PUT', 'PATCH'].includes(req.method)) {
      const contentType = req.headers['content-type'] || '';
      
      if (req.body && Object.keys(req.body).length > 0) {
        if (!contentType.includes('application/json') && 
            !contentType.includes('application/x-www-form-urlencoded') &&
            !contentType.includes('multipart/form-data')) {
          return res.status(415).json({ message: 'Unsupported Media Type' });
        }
      }
    }
    next();
  };
}

export function requestLogger() {
  return (req: Request, res: Response, next: NextFunction) => {
    const start = Date.now();
    
    res.on('finish', () => {
      const duration = Date.now() - start;
      const logData = {
        method: req.method,
        path: req.path,
        status: res.statusCode,
        duration: `${duration}ms`,
        ip: req.ip,
        userAgent: req.headers['user-agent']?.substring(0, 100)
      };
      
      if (res.statusCode >= 400) {
        console.warn('Request error:', logData);
      }
    });
    
    next();
  };
}

export function corsConfig() {
  return (req: Request, res: Response, next: NextFunction) => {
    const allowedOrigins = process.env.ALLOWED_ORIGINS?.split(',') || ['*'];
    const origin = req.headers.origin || '';
    
    if (allowedOrigins.includes('*') || allowedOrigins.includes(origin)) {
      res.set('Access-Control-Allow-Origin', origin || '*');
    }
    
    res.set('Access-Control-Allow-Methods', 'GET, POST, PUT, PATCH, DELETE, OPTIONS');
    res.set('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With');
    res.set('Access-Control-Allow-Credentials', 'true');
    res.set('Access-Control-Max-Age', '86400');
    
    if (req.method === 'OPTIONS') {
      return res.status(204).end();
    }
    
    next();
  };
}
