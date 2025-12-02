// Denial of Service Rules (ModSecurity CRS 912)
export const DOS_RULES = [
  {
    id: 'dos-large-payload',
    name: 'DoS - Excessively Large Payload',
    pattern: /.{10000}/,
    field: 'body',
    severity: 'high',
    score: 75,
    category: 'dos',
    description: 'Request body exceeds 10KB (potential DoS)',
    recommendation: 'Implement strict content-length limits'
  },
  {
    id: 'dos-slow-request',
    name: 'DoS - Slow Request Detection',
    pattern: /^$/,
    field: 'body',
    severity: 'medium',
    score: 45,
    category: 'dos',
    description: 'Slowloris or slow request attack pattern',
    recommendation: 'Implement request timeouts and connection limits'
  },
  {
    id: 'dos-compression-bomb',
    name: 'DoS - Compression Bomb Detection',
    pattern: /content-encoding\s*:\s*(gzip|deflate|br)|x-compressed-bomb/i,
    field: 'headers',
    severity: 'high',
    score: 70,
    category: 'dos',
    description: 'Potential compression bomb or decompression attack',
    recommendation: 'Limit decompressed content size and detect bombs'
  },
  {
    id: 'dos-regex-complexity',
    name: 'DoS - ReDoS Pattern Detection',
    pattern: /(\w+\*){5,}|(\w+\+){5,}|\(\w+\|{2,}/,
    field: 'request',
    severity: 'high',
    score: 72,
    category: 'dos',
    description: 'Regular expression complexity (ReDoS attack)',
    recommendation: 'Validate regex complexity and use timeouts'
  },
  {
    id: 'dos-hash-collision',
    name: 'DoS - Hash Collision Attack',
    pattern: /[?&][a-z0-9]{100,}=|POST.*content-type.*x-www-form.*[a-z0-9]{500,}/i,
    field: 'request',
    severity: 'high',
    score: 68,
    category: 'dos',
    description: 'Potential hash table collision attack',
    recommendation: 'Use secure hash functions and limit parameter counts'
  },
  {
    id: 'dos-xml-bomb',
    name: 'DoS - XML Bomb (Billion Laughs)',
    pattern: /<!ENTITY|<\!ENTITY.*?SYSTEM|&[a-z]+;.*&[a-z]+;.*&[a-z]+;/i,
    field: 'body',
    severity: 'high',
    score: 76,
    category: 'dos',
    description: 'XML bomb or entity expansion attack',
    recommendation: 'Disable external entities, limit entity nesting'
  },
  {
    id: 'dos-request-flooding',
    name: 'DoS - Request Flooding Indicators',
    pattern: /^$/,
    field: 'path',
    severity: 'medium',
    score: 50,
    category: 'dos',
    description: 'Multiple rapid requests from same IP',
    recommendation: 'Implement rate limiting and connection pooling'
  },
  {
    id: 'dos-pipe-pollution',
    name: 'DoS - HTTP Pipe Pollution',
    pattern: /\r\n\r\n.*GET\s+\/|POST\s+\/.*\r\n\r\nGET/i,
    field: 'request',
    severity: 'high',
    score: 71,
    category: 'dos',
    description: 'HTTP request pipelining or cache poisoning',
    recommendation: 'Enforce strict request parsing and disable pipelining'
  },
  {
    id: 'dos-memory-exhaustion',
    name: 'DoS - Memory Exhaustion Pattern',
    pattern: /\barray_fill\b|\bstr_repeat\b|\bmemset\b|malloc.*1000000|allocate.*\d{10}/i,
    field: 'request',
    severity: 'high',
    score: 74,
    category: 'dos',
    description: 'Potential memory allocation explosion',
    recommendation: 'Limit allocation sizes and monitor memory usage'
  },
  {
    id: 'dos-algorithmic-complexity',
    name: 'DoS - Algorithmic Complexity Attack',
    pattern: /sort|shuffle|permutation|factorial|fibonacci|recursive.*call|\.{3,}/,
    field: 'request',
    severity: 'medium',
    score: 62,
    category: 'dos',
    description: 'Algorithmic complexity exploitation',
    recommendation: 'Implement complexity analysis and execution timeouts'
  },
  {
    id: 'dos-cpu-intensive',
    name: 'DoS - CPU Intensive Operations',
    pattern: /(crypto|bcrypt|argon2|scrypt|pbkdf2)[\s\S]*?iterations?[\s\S]*?100000|sleep\(\d{6,}|usleep\(\d{8,}/i,
    field: 'request',
    severity: 'high',
    score: 73,
    category: 'dos',
    description: 'CPU-intensive operation requests',
    recommendation: 'Throttle expensive operations'
  },
  {
    id: 'dos-bandwidth-exhaustion',
    name: 'DoS - Bandwidth Exhaustion',
    pattern: /content-length\s*:\s*\d{8,}|range\s*:\s*bytes.*-\d{8,}/i,
    field: 'headers',
    severity: 'high',
    score: 69,
    category: 'dos',
    description: 'Large range requests for bandwidth exhaustion',
    recommendation: 'Limit range request sizes'
  },
  {
    id: 'dos-connection-exhaustion',
    name: 'DoS - Connection Pool Exhaustion',
    pattern: /keep-alive\s*:\s*\d{6,}|connection\s*:\s*keep-alive[\s\S]*?content-length\s*:\s*0/i,
    field: 'headers',
    severity: 'medium',
    score: 61,
    category: 'dos',
    description: 'Connection pool exhaustion via keep-alive',
    recommendation: 'Implement connection limits'
  },
  {
    id: 'dos-querystring-explosion',
    name: 'DoS - Query String Explosion',
    pattern: /\?[^=&]*=[^&]*(&[^=&]*=[^&]*){100,}/,
    field: 'request',
    severity: 'high',
    score: 67,
    category: 'dos',
    description: 'Excessive query parameters',
    recommendation: 'Limit parameter counts'
  }
];
