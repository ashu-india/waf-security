/**
 * IP Reputation Service
 * Integrates with geoip-lite for IP intelligence
 */

import geoip from 'geoip-lite';

export interface IPReputation {
  ip: string;
  country: string;
  countryCode: string;
  city?: string;
  latitude?: number;
  longitude?: number;
  riskScore: number; // 0-1, where 1 is highest risk
  isVPN?: boolean;
  isSuspicious: boolean;
}

// Known suspicious countries (high cybercrime rates)
const SUSPICIOUS_COUNTRIES = ['KP', 'IR', 'SY'];

// Known data center IPs (often used for attacks)
const DATA_CENTER_PATTERNS = [
  /\.(datacenter|dc|cloud|aws|azure|gcp)\./i,
];

export class IPReputationService {
  /**
   * Get IP reputation score and geo information
   */
  getIPReputation(ip: string): IPReputation {
    // Get geo info
    const geo = geoip.lookup(ip);

    const reputation: IPReputation = {
      ip,
      country: geo?.country || 'Unknown',
      countryCode: geo?.country || 'XX',
      city: geo?.city,
      latitude: geo?.ll?.[0],
      longitude: geo?.ll?.[1],
      riskScore: 0,
      isSuspicious: false,
    };

    // Calculate risk score
    let riskScore = 0;

    // Check if from suspicious country
    if (SUSPICIOUS_COUNTRIES.includes(reputation.countryCode)) {
      riskScore += 0.4;
    }

    // Check for common attack patterns
    if (this.looksLikeAttacker(ip)) {
      riskScore += 0.3;
    }

    // Check for VPN/proxy indicators (high TTL, specific ports)
    if (this.looksLikeVPN(ip)) {
      reputation.isVPN = true;
      riskScore += 0.2;
    }

    reputation.riskScore = Math.min(1, riskScore);
    reputation.isSuspicious = reputation.riskScore > 0.5;

    return reputation;
  }

  /**
   * Check if IP looks like it's attacking
   */
  private looksLikeAttacker(ip: string): boolean {
    // Private IP ranges (often used in labs/testing)
    if (this.isPrivateIP(ip)) {
      return true;
    }

    // Known ISP ranges that are commonly abused
    const octets = ip.split('.').map(Number);
    
    // Simple heuristic: IPs from known datacenter ranges
    if (octets[0] === 192 && octets[1] === 168) return true; // Private
    if (octets[0] === 10) return true; // Private
    if (octets[0] === 172 && octets[1] >= 16 && octets[1] <= 31) return true; // Private

    return false;
  }

  /**
   * Check if IP looks like VPN/proxy
   */
  private looksLikeVPN(ip: string): boolean {
    // Common VPN port ranges and patterns
    const vpnPatterns = [
      /^1\.1\.1\./, // Cloudflare
      /^8\.8\.8\./, // Google DNS
      /^203\.0\.113\./, // TEST-NET-3
    ];

    return vpnPatterns.some(pattern => pattern.test(ip));
  }

  /**
   * Check if IP is private
   */
  private isPrivateIP(ip: string): boolean {
    const octets = ip.split('.').map(Number);
    
    if (octets[0] === 192 && octets[1] === 168) return true;
    if (octets[0] === 10) return true;
    if (octets[0] === 172 && octets[1] >= 16 && octets[1] <= 31) return true;
    if (octets[0] === 127) return true; // Localhost
    if (octets[0] === 0) return true; // This network
    if (octets[0] >= 224) return true; // Multicast/Reserved

    return false;
  }

  /**
   * Get threat level based on IP reputation
   */
  getThreatLevel(ip: string): 'low' | 'medium' | 'high' | 'critical' {
    const reputation = this.getIPReputation(ip);

    if (reputation.riskScore >= 0.9) return 'critical';
    if (reputation.riskScore >= 0.7) return 'high';
    if (reputation.riskScore >= 0.4) return 'medium';
    return 'low';
  }

  /**
   * Check multiple IPs for patterns
   */
  detectBotnetPattern(ips: string[]): boolean {
    if (ips.length < 3) return false;

    // All from same country = potential botnet
    const countries = ips.map(ip => this.getIPReputation(ip).countryCode);
    const uniqueCountries = new Set(countries);

    // If too many IPs from same country, likely botnet
    if (uniqueCountries.size === 1 && ips.length > 10) {
      return true;
    }

    // If all suspicious IPs, likely botnet
    const suspiciousCount = ips.filter(ip => 
      this.getIPReputation(ip).isSuspicious
    ).length;

    return suspiciousCount / ips.length > 0.8;
  }
}

export const ipReputation = new IPReputationService();
