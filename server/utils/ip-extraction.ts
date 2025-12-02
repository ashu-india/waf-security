/**
 * IP Extraction and Validation Utility
 * Handles X-Forwarded-For, X-Real-IP, and socket.remoteAddress
 * Validates IPv4 and IPv6 formats
 */

const IPV4_REGEX = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
const IPV6_REGEX = /^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))$/;

/**
 * Validates IP format (IPv4 or IPv6)
 */
export function isValidIp(ip: string): boolean {
  if (!ip || typeof ip !== 'string') return false;
  const trimmed = ip.trim();
  if (trimmed.length === 0) return false;
  return IPV4_REGEX.test(trimmed) || IPV6_REGEX.test(trimmed);
}

/**
 * Extracts first valid IP from comma-separated list
 */
function extractFirstValidIp(ips: string): string | null {
  if (!ips) return null;
  const ipList = ips.split(',').map(ip => ip.trim());
  for (const ip of ipList) {
    if (isValidIp(ip)) {
      return ip;
    }
  }
  return null;
}

/**
 * Main function: Extract client IP from request
 * Priority: X-Forwarded-For > X-Real-IP > socket.remoteAddress
 */
export function extractClientIp(req: any): string {
  try {
    // Priority 1: X-Forwarded-For (from proxies/load balancers)
    const xForwardedFor = req.headers?.['x-forwarded-for'];
    if (xForwardedFor) {
      const ip = extractFirstValidIp(xForwardedFor);
      if (ip) return ip;
    }

    // Priority 2: X-Real-IP (alternative proxy header)
    const xRealIp = req.headers?.['x-real-ip'];
    if (xRealIp && typeof xRealIp === 'string') {
      const ip = xRealIp.trim();
      if (isValidIp(ip)) return ip;
    }

    // Priority 3: socket.remoteAddress (direct connection)
    const remoteAddress = req.socket?.remoteAddress || req.connection?.remoteAddress;
    if (remoteAddress && typeof remoteAddress === 'string') {
      let ip = remoteAddress.trim();
      // Remove IPv6 prefix if present (::ffff:x.x.x.x)
      if (ip.startsWith('::ffff:')) {
        ip = ip.substring(7);
      }
      if (isValidIp(ip)) return ip;
    }

    // Fallback
    return 'unknown';
  } catch (error) {
    console.warn('Error extracting client IP:', error);
    return 'unknown';
  }
}

/**
 * Extract client IP from body (for API calls like /api/waf/ingress)
 * Falls back to request object if clientIp not in body
 */
export function extractClientIpFromRequest(req: any, requestBody?: any): string {
  // If clientIp provided in body, validate and use it
  if (requestBody?.clientIp && typeof requestBody.clientIp === 'string') {
    const ip = requestBody.clientIp.trim();
    if (isValidIp(ip)) return ip;
  }

  // Otherwise extract from HTTP request
  return extractClientIp(req);
}

/**
 * Sanitize IP for storage (remove any invalid characters)
 */
export function sanitizeIp(ip: string): string {
  if (!ip) return 'unknown';
  const trimmed = ip.trim();
  if (isValidIp(trimmed)) return trimmed;
  // Clean up IPv6 prefix
  if (trimmed.startsWith('::ffff:')) {
    const cleaned = trimmed.substring(7);
    if (isValidIp(cleaned)) return cleaned;
  }
  return 'unknown';
}
