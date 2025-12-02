import geoip from 'geoip-lite';

interface GeoLocation {
  country: string;
  countryName: string;
  city?: string;
  isVPN?: boolean;
}

export class GeolocationService {
  static lookup(ip: string): GeoLocation | null {
    try {
      const geo = geoip.lookup(ip);
      if (!geo) return null;

      return {
        country: geo.country,
        countryName: this.getCountryName(geo.country),
        city: geo.city,
        isVPN: this.detectVPN(geo)
      };
    } catch (error) {
      console.error('Geolocation lookup error:', error);
      return null;
    }
  }

  static checkGeoRestriction(
    ip: string,
    allowedCountries?: string[],
    blockedCountries?: string[]
  ): { allowed: boolean; country?: string; reason?: string } {
    const geo = this.lookup(ip);
    if (!geo) {
      return { allowed: true, country: "Unknown", reason: "Could not determine location" };
    }

    // Blocked countries have priority (highest security)
    if (blockedCountries?.includes(geo.country)) {
      return { 
        allowed: false, 
        country: geo.country,
        reason: `Country ${geo.country} (${geo.countryName}) is on the blocked list` 
      };
    }

    // If allowed list exists, only allow those countries
    if (allowedCountries && allowedCountries.length > 0) {
      if (!allowedCountries.includes(geo.country)) {
        return { 
          allowed: false, 
          country: geo.country,
          reason: `Country ${geo.country} (${geo.countryName}) is not in the allowed list` 
        };
      }
    }

    return { 
      allowed: true, 
      country: geo.country,
      reason: `Country ${geo.country} (${geo.countryName}) is allowed` 
    };
  }

  static checkVPN(ip: string): boolean {
    const geo = geoip.lookup(ip);
    if (!geo) return false;
    return this.detectVPN(geo);
  }

  private static detectVPN(geo: any): boolean {
    // Detect if public IP is from common cloud providers
    const org = geo.org || '';
    const cloudPatterns = ['AWS', 'Google', 'Microsoft', 'Azure', 'Linode', 'DigitalOcean', 'Vultr', 'OVH', 'Hetzner'];
    return cloudPatterns.some(provider => org.toUpperCase().includes(provider.toUpperCase()));
  }

  private static getCountryName(code: string): string {
    const countries: Record<string, string> = {
      'US': 'United States', 'UK': 'United Kingdom', 'CA': 'Canada',
      'AU': 'Australia', 'DE': 'Germany', 'FR': 'France', 'IT': 'Italy',
      'ES': 'Spain', 'NL': 'Netherlands', 'SE': 'Sweden', 'NO': 'Norway',
      'DK': 'Denmark', 'CH': 'Switzerland', 'AT': 'Austria', 'BE': 'Belgium',
      'JP': 'Japan', 'CN': 'China', 'IN': 'India', 'BR': 'Brazil', 'MX': 'Mexico',
      'SG': 'Singapore', 'HK': 'Hong Kong', 'RU': 'Russia', 'KR': 'South Korea',
      'TW': 'Taiwan', 'TH': 'Thailand', 'MY': 'Malaysia', 'PH': 'Philippines',
      'ID': 'Indonesia', 'VN': 'Vietnam', 'NZ': 'New Zealand', 'ZA': 'South Africa',
      'EG': 'Egypt', 'NG': 'Nigeria', 'KE': 'Kenya', 'UA': 'Ukraine', 'PL': 'Poland',
      'CZ': 'Czech Republic', 'GR': 'Greece', 'TR': 'Turkey', 'IL': 'Israel',
      'KP': 'North Korea', 'IR': 'Iran', 'SY': 'Syria', 'CU': 'Cuba'
    };
    return countries[code] || code;
  }
}
