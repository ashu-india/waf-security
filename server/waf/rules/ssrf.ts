// Server-Side Request Forgery Rules
export const SSRF_RULES = [
  {
    id: 'ssrf-localhost-access',
    name: 'SSRF - Localhost Access',
    pattern: /(localhost|127\.0\.0\.1|0\.0\.0\.0|::1|%7f%7f%7f%7f|0x7f000001)/i,
    field: 'request',
    severity: 'critical',
    score: 96,
    category: 'ssrf',
    description: 'Attempt to access localhost or loopback addresses',
    recommendation: 'Whitelist allowed external URLs, block internal IPs'
  },
  {
    id: 'ssrf-private-ips',
    name: 'SSRF - Private IP Ranges',
    pattern: /(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2[0-9]|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|169\.254\.\d{1,3}\.\d{1,3})/,
    field: 'request',
    severity: 'critical',
    score: 95,
    category: 'ssrf',
    description: 'Attempt to access private IP addresses (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)',
    recommendation: 'Reject requests to private IP ranges'
  },
  {
    id: 'ssrf-metadata-services',
    name: 'SSRF - Cloud Metadata Services',
    pattern: /(169\.254\.169\.254|metadata\.google\.internal|instance-data|kube-system|imds)/i,
    field: 'request',
    severity: 'critical',
    score: 97,
    category: 'ssrf',
    description: 'Attempt to access cloud metadata services (AWS, GCP, Azure)',
    recommendation: 'Block access to cloud metadata endpoints'
  },
  {
    id: 'ssrf-url-schemes',
    name: 'SSRF - Dangerous URL Schemes',
    pattern: /(file:\/\/|ftp:\/\/|gopher:\/\/|dict:\/\/|ldap:\/\/|ldapi:\/\/|tftp:\/\/|sftp:\/\/|telnet:\/\/)/i,
    field: 'request',
    severity: 'high',
    score: 88,
    category: 'ssrf',
    description: 'Dangerous URL schemes for SSRF exploitation',
    recommendation: 'Only allow http and https schemes'
  },
  {
    id: 'ssrf-port-scanning',
    name: 'SSRF - Port Scanning Attempts',
    pattern: /:\d{1,5}\s*(\/|$)|port=\d{1,5}|host=[^&\s]*:\d{1,5}/i,
    field: 'request',
    severity: 'high',
    score: 82,
    category: 'ssrf',
    description: 'Apparent port scanning attempts via SSRF',
    recommendation: 'Restrict URL parsing to standard ports'
  },
  {
    id: 'ssrf-host-header-injection',
    name: 'SSRF - Host Header Injection',
    pattern: /host\s*:\s*[^:]*@|@[^\/]*host\s*:/i,
    field: 'request',
    severity: 'high',
    score: 85,
    category: 'ssrf',
    description: 'Host header manipulation for SSRF',
    recommendation: 'Validate Host header matches expected domain'
  },
  {
    id: 'ssrf-dns-rebinding',
    name: 'SSRF - DNS Rebinding',
    pattern: /(localhost\.localdomain|127\.0\.0\.1\.xip\.io|127\.0\.0\.1\.nip\.io|0x7f\.0x0\.0x0\.0x1)/i,
    field: 'request',
    severity: 'high',
    score: 84,
    category: 'ssrf',
    description: 'DNS rebinding techniques for SSRF bypass',
    recommendation: 'Use IP address validation instead of hostname'
  },
  {
    id: 'ssrf-url-encoding-bypass',
    name: 'SSRF - URL Encoding Bypass',
    pattern: /%2e%2e|%3f|%23|%40|%3a|%2f%2f/i,
    field: 'request',
    severity: 'high',
    score: 81,
    category: 'ssrf',
    description: 'URL-encoded characters for SSRF bypass',
    recommendation: 'Normalize and decode URLs before validation'
  },
  {
    id: 'ssrf-redirect-chain',
    name: 'SSRF - Redirect Chain Exploitation',
    pattern: /(redirect|redir|return|goto|url|callback|continue|destination|next)=https?:\/\/[^&\s]+https?:\/\//i,
    field: 'request',
    severity: 'high',
    score: 83,
    category: 'ssrf',
    description: 'Chained redirects for internal access',
    recommendation: 'Limit redirect depth, validate all redirect targets'
  },
  {
    id: 'ssrf-hex-ip-encoding',
    name: 'SSRF - Hex IP Encoding',
    pattern: /0x[0-9a-fA-F]{2}\.0x[0-9a-fA-F]{2}|0x7f|0xa9fe/i,
    field: 'request',
    severity: 'high',
    score: 80,
    category: 'ssrf',
    description: 'Hex-encoded IP addresses for bypass',
    recommendation: 'Validate IP addresses in multiple formats'
  },
  {
    id: 'ssrf-octal-notation',
    name: 'SSRF - Octal Notation IP Bypass',
    pattern: /\b0[0-7]{1,3}\.0[0-7]{1,3}\.0[0-7]{1,3}\.0[0-7]{1,3}\b/,
    field: 'request',
    severity: 'high',
    score: 79,
    category: 'ssrf',
    description: 'Octal notation IP addresses for bypass',
    recommendation: 'Validate all IP notation formats'
  },
  {
    id: 'ssrf-unicode-bypass',
    name: 'SSRF - Unicode/UTF-8 Bypass',
    pattern: /127%00|localhost%00|%c0%ae|%uff0e|%c1%9c/i,
    field: 'request',
    severity: 'high',
    score: 77,
    category: 'ssrf',
    description: 'Unicode encoding for SSRF bypass',
    recommendation: 'Normalize URLs before validation'
  }
];
