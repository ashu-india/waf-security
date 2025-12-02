// Local File Inclusion Rules (ModSecurity CRS 930)
export const LFI_RULES = [
  {
    id: 'lfi-directory-traversal',
    name: 'LFI - Directory Traversal',
    pattern: /\.\.\/|\.\.\\|%2e%2e%2f|%2e%2e%5c|\.\.;\/|..;\\|%252e%252e/i,
    field: 'request',
    severity: 'critical',
    score: 96,
    category: 'lfi',
    description: 'Directory traversal sequences detected',
    recommendation: 'Canonicalize paths and validate against whitelist'
  },
  {
    id: 'lfi-null-byte-injection',
    name: 'LFI - Null Byte Injection',
    pattern: /%00|\.php%00|\.jsp%00|\.asp%00|\.exe%00/i,
    field: 'request',
    severity: 'critical',
    score: 94,
    category: 'lfi',
    description: 'Null byte injection for file extension bypass',
    recommendation: 'Validate and reject null bytes in filenames'
  },
  {
    id: 'lfi-absolute-paths',
    name: 'LFI - Absolute File Paths',
    pattern: /^(\/etc\/|\/var\/|\/proc\/|\/sys\/|\/root\/|\/home\/|C:\\(Windows|Program Files)|file:\/\/\/)/i,
    field: 'request',
    severity: 'critical',
    score: 93,
    category: 'lfi',
    description: 'Absolute file system paths for sensitive files',
    recommendation: 'Only allow relative paths, use base directory'
  },
  {
    id: 'lfi-php-wrappers',
    name: 'LFI - PHP Stream Wrappers',
    pattern: /(php|filter|data|glob|phar|rar|ogg|expect):\/\//i,
    field: 'request',
    severity: 'critical',
    score: 95,
    category: 'lfi',
    description: 'PHP stream wrapper abuse (filter, data, etc.)',
    recommendation: 'Disable stream wrapper handlers'
  },
  {
    id: 'lfi-log-poisoning',
    name: 'LFI - Log Poisoning',
    pattern: /\/var\/log\/.*|\/var\/www\/.*|access\.log|error\.log|apache2\/logs|nginx\/logs/i,
    field: 'request',
    severity: 'high',
    score: 85,
    category: 'lfi',
    description: 'Attempting to include application logs',
    recommendation: 'Restrict log file access, implement proper logging'
  },
  {
    id: 'lfi-unicode-encoding',
    name: 'LFI - Unicode Path Encoding',
    pattern: /%c0%ae|%uff0e|%u002e|%c1%9c|%e0%80%ae/i,
    field: 'request',
    severity: 'high',
    score: 82,
    category: 'lfi',
    description: 'Unicode-encoded directory traversal',
    recommendation: 'Normalize Unicode before path validation'
  },
  {
    id: 'lfi-double-encoding',
    name: 'LFI - Double Encoding Bypass',
    pattern: /%252e%252e|%252f|%255c|%25c0%25ae/i,
    field: 'request',
    severity: 'high',
    score: 88,
    category: 'lfi',
    description: 'Double-encoded traversal sequences',
    recommendation: 'Decode recursively and normalize paths'
  },
  {
    id: 'lfi-sensitive-windows-files',
    name: 'LFI - Windows Sensitive Files',
    pattern: /(win\.ini|system32|boot\.ini|windows\\\\system32|pagefile\.sys|hiberfil\.sys)/i,
    field: 'request',
    severity: 'high',
    score: 86,
    category: 'lfi',
    description: 'Windows sensitive file access attempts',
    recommendation: 'Implement strict file whitelisting'
  },
  {
    id: 'lfi-unix-system-files',
    name: 'LFI - Unix System Files',
    pattern: /\/etc\/(passwd|shadow|group|hosts|resolv\.conf|fstab|sudoers)|\/proc\/self\/(cmdline|environ|maps)/i,
    field: 'request',
    severity: 'critical',
    score: 97,
    category: 'lfi',
    description: 'Unix system and credential file access',
    recommendation: 'Block access to /etc/ and /proc/ files'
  },
  {
    id: 'lfi-archive-extraction',
    name: 'LFI - Archive File Exploitation',
    pattern: /\.zip%00|\.tar%00|\.gz%00|\.rar%00|\.7z%00|phar:\/\//i,
    field: 'request',
    severity: 'high',
    score: 84,
    category: 'lfi',
    description: 'Archive file inclusion/extraction attempts',
    recommendation: 'Disable archive wrappers and validate extensions'
  }
];
