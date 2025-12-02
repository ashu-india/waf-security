// HTTP Request Desynchronization Rules (CL.TE, TE.CL, TE.TE attacks)
export const HTTP_DESYNC_RULES = [
  {
    id: 'desync-cl-te',
    name: 'HTTP Desync - CL.TE (Content-Length vs Transfer-Encoding)',
    pattern: /content-length\s*:\s*\d+[\s\S]*?transfer-encoding\s*:\s*(chunked|gzip)/i,
    field: 'headers',
    severity: 'critical',
    score: 95,
    category: 'http-desync',
    description: 'Content-Length and Transfer-Encoding both present (CL.TE desync)',
    recommendation: 'Reject requests with both CL and TE headers, normalize at proxy'
  },
  {
    id: 'desync-te-cl',
    name: 'HTTP Desync - TE.CL (Transfer-Encoding vs Content-Length)',
    pattern: /transfer-encoding\s*:\s*(chunked|gzip)[\s\S]*?content-length\s*:\s*\d+/i,
    field: 'headers',
    severity: 'critical',
    score: 95,
    category: 'http-desync',
    description: 'Transfer-Encoding before Content-Length (TE.CL desync)',
    recommendation: 'Normalize header ordering, reject conflicting headers'
  },
  {
    id: 'desync-te-te',
    name: 'HTTP Desync - TE.TE (Duplicate Transfer-Encoding)',
    pattern: /transfer-encoding[\s\S]*?transfer-encoding/i,
    field: 'headers',
    severity: 'high',
    score: 88,
    category: 'http-desync',
    description: 'Multiple Transfer-Encoding headers (TE.TE desync)',
    recommendation: 'Consolidate duplicate headers, reject ambiguous cases'
  },
  {
    id: 'desync-chunk-smuggling',
    name: 'HTTP Desync - Chunk Encoding Smuggling',
    pattern: /transfer-encoding\s*:\s*chunked[\s\S]*?0\r\n\r\nGET|0\r\n\r\nPOST|0\r\n\r\nHEAD/i,
    field: 'request',
    severity: 'critical',
    score: 94,
    category: 'http-desync',
    description: 'Chunk-encoded request with embedded request after final chunk',
    recommendation: 'Validate chunk boundaries, strip smuggled requests'
  },
  {
    id: 'desync-invalid-chunk-size',
    name: 'HTTP Desync - Invalid Chunk Size',
    pattern: /transfer-encoding\s*:\s*chunked[\s\S]*?[^\da-fA-F\r\n]\s*\r\n/,
    field: 'request',
    severity: 'high',
    score: 82,
    category: 'http-desync',
    description: 'Chunk size contains non-hex characters or invalid format',
    recommendation: 'Validate chunk size format strictly (only hex)'
  },
  {
    id: 'desync-space-before-colon',
    name: 'HTTP Desync - Space Before Header Colon',
    pattern: /[a-z0-9\-]\s+:/i,
    field: 'headers',
    severity: 'high',
    score: 80,
    category: 'http-desync',
    description: 'Whitespace before colon in header (ambiguous parsing)',
    recommendation: 'Normalize headers, reject malformed header syntax'
  },
  {
    id: 'desync-tab-in-header',
    name: 'HTTP Desync - Tab Character in Header',
    pattern: /.*\t.*:/i,
    field: 'headers',
    severity: 'high',
    score: 78,
    category: 'http-desync',
    description: 'Tab character used in header field (RFC ambiguity)',
    recommendation: 'Strip tabs, use strict header validation'
  },
  {
    id: 'desync-line-folding',
    name: 'HTTP Desync - Line Folding (Header Continuation)',
    pattern: /\r\n[\s\t]+/,
    field: 'headers',
    severity: 'high',
    score: 81,
    category: 'http-desync',
    description: 'Header line folding/continuation (deprecated in HTTP/1.1)',
    recommendation: 'Reject folded headers, enforce strict parsing'
  },
  {
    id: 'desync-obfuscated-te',
    name: 'HTTP Desync - Obfuscated Transfer-Encoding',
    pattern: /transfer-encoding\s*:\s*(chunked\s*;\s*q|gzip\s*,\s*chunked|chunked\s*,|deflate\s*,\s*chunked)/i,
    field: 'headers',
    severity: 'high',
    score: 79,
    category: 'http-desync',
    description: 'Transfer-Encoding with obfuscated or unusual values',
    recommendation: 'Only accept standard values: chunked, gzip, deflate'
  },
  {
    id: 'desync-request-prefix',
    name: 'HTTP Desync - HTTP Request in Body',
    pattern: /\r\n\r\n(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|TRACE|CONNECT)\s+\/.*HTTP\/1\.[01]/i,
    field: 'body',
    severity: 'critical',
    score: 93,
    category: 'http-desync',
    description: 'Complete HTTP request embedded in body (request smuggling)',
    recommendation: 'Strip request prefixes, enforce single-request-per-connection'
  },
  {
    id: 'desync-cr-lf-injection',
    name: 'HTTP Desync - CRLF in Header Value',
    pattern: /[a-z0-9\-]+\s*:\s*[^\r\n]*\r\n[^\s]/i,
    field: 'headers',
    severity: 'high',
    score: 85,
    category: 'http-desync',
    description: 'CRLF sequence within header value enabling header injection',
    recommendation: 'Strip CRLF sequences, validate header values'
  },
  {
    id: 'desync-null-prefix',
    name: 'HTTP Desync - Null Byte Prefix',
    pattern: /\x00[\w\s]+(GET|POST|PUT|DELETE|PATCH|HEAD)/i,
    field: 'request',
    severity: 'high',
    score: 84,
    category: 'http-desync',
    description: 'Null byte prefix used to bypass request parsing',
    recommendation: 'Strip null bytes from all requests'
  },
  {
    id: 'desync-mixed-case-te',
    name: 'HTTP Desync - Mixed-Case Transfer-Encoding',
    pattern: /[Tt][Rr][Aa][Nn][Ss][Ff][Ee][Rr]-[Ee][Nn][Cc][Oo][Dd][Ii][Nn][Gg]|TrAnSfEr-EnCoDiNg/i,
    field: 'headers',
    severity: 'medium',
    score: 72,
    category: 'http-desync',
    description: 'Transfer-Encoding header with mixed case (parser ambiguity)',
    recommendation: 'Normalize header names to lowercase, strict comparison'
  }
];
