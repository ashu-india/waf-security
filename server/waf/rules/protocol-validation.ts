// Protocol Validation Rules (ModSecurity CRS 920-922)
export const PROTOCOL_VALIDATION_RULES = [
  {
    id: 'protocol-invalid-content-length',
    name: 'Invalid Content-Length',
    pattern: /content-length\s*:\s*[^0-9\r\n]/i,
    field: 'headers',
    severity: 'high',
    score: 75,
    category: 'protocol-validation',
    description: 'Content-Length header contains non-numeric characters',
    recommendation: 'Ensure Content-Length contains only numeric values'
  },
  {
    id: 'protocol-duplicate-content-length',
    name: 'Multiple Content-Length Headers',
    pattern: /(?:content-length[\s\S]*?){2,}/i,
    field: 'headers',
    severity: 'high',
    score: 80,
    category: 'protocol-validation',
    description: 'Request contains duplicate Content-Length headers (HTTP smuggling)',
    recommendation: 'Reject requests with multiple Content-Length headers'
  },
  {
    id: 'protocol-post-no-body',
    name: 'POST Request with No Body',
    pattern: /^POST.*content-length\s*:\s*0\s*$/mi,
    field: 'headers',
    severity: 'medium',
    score: 50,
    category: 'protocol-validation',
    description: 'POST request with Content-Length: 0',
    recommendation: 'Validate POST request has expected content'
  },
  {
    id: 'protocol-null-byte',
    name: 'Null Byte in Request',
    pattern: /\x00/,
    field: 'request',
    severity: 'critical',
    score: 95,
    category: 'protocol-validation',
    description: 'Null byte detected in HTTP request',
    recommendation: 'Strip null bytes from all user input'
  },
  {
    id: 'protocol-invalid-method',
    name: 'Invalid HTTP Method',
    pattern: /^(?!GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|TRACE|CONNECT|PROPFIND|PROPPATCH|MKCOL|COPY|MOVE|LOCK|UNLOCK)\S+/i,
    field: 'method',
    severity: 'high',
    score: 70,
    category: 'protocol-validation',
    description: 'Non-standard HTTP method detected',
    recommendation: 'Only allow standard HTTP methods'
  },
  {
    id: 'protocol-http-version',
    name: 'Invalid HTTP Version',
    pattern: /HTTP\/(?!0\.9|1\.0|1\.1|2\.0|3\.0)/i,
    field: 'headers',
    severity: 'medium',
    score: 55,
    category: 'protocol-validation',
    description: 'Invalid or unsupported HTTP version',
    recommendation: 'Only support HTTP/1.0, HTTP/1.1, HTTP/2.0'
  },
  {
    id: 'protocol-missing-host',
    name: 'Missing Host Header',
    pattern: /^(?!.*Host\s*:)/i,
    field: 'headers',
    severity: 'medium',
    score: 45,
    category: 'protocol-validation',
    description: 'HTTP/1.1 request without Host header',
    recommendation: 'Enforce Host header for HTTP/1.1 requests'
  },
  {
    id: 'protocol-absolute-uri',
    name: 'Absolute URI in Request Line',
    pattern: /^(GET|POST|PUT|DELETE|PATCH|HEAD)\s+https?:\/\//i,
    field: 'request',
    severity: 'high',
    score: 65,
    category: 'protocol-validation',
    description: 'Absolute URI in request line (potential proxy bypass)',
    recommendation: 'Only allow relative URIs in request line'
  },
  {
    id: 'protocol-method-override',
    name: 'HTTP Method Override Header',
    pattern: /(x-http-method-override|x-method-override|x-real-method)\s*:\s*(GET|POST|PUT|DELETE|PATCH)/i,
    field: 'headers',
    severity: 'high',
    score: 70,
    category: 'protocol-validation',
    description: 'HTTP method override header detected (security risk)',
    recommendation: 'Disable HTTP method override headers if not needed'
  },
  {
    id: 'protocol-transfer-encoding-null',
    name: 'Transfer-Encoding with Null Bytes',
    pattern: /transfer-encoding\s*:[\s\S]*?\x00/i,
    field: 'headers',
    severity: 'critical',
    score: 90,
    category: 'protocol-validation',
    description: 'Transfer-Encoding header with null bytes',
    recommendation: 'Strip null bytes and validate Transfer-Encoding values'
  },
  {
    id: 'protocol-chunked-encoding-invalid',
    name: 'Invalid Chunked Transfer Encoding',
    pattern: /transfer-encoding\s*:\s*chunked[\s\S]*?[^\da-fA-F\r\n]/i,
    field: 'headers',
    severity: 'high',
    score: 78,
    category: 'protocol-validation',
    description: 'Invalid chunked transfer encoding format'
  },
  {
    id: 'protocol-double-transfer-encoding',
    name: 'Multiple Transfer-Encoding Headers',
    pattern: /(?:transfer-encoding[\s\S]*?){2,}/i,
    field: 'headers',
    severity: 'critical',
    score: 92,
    category: 'protocol-validation',
    description: 'HTTP smuggling via duplicate Transfer-Encoding'
  },
  {
    id: 'protocol-conflicting-headers',
    name: 'Conflicting Content-Length and Transfer-Encoding',
    pattern: /content-length\s*:[^:\r\n]*[\r\n][\s\S]*?transfer-encoding\s*:/i,
    field: 'headers',
    severity: 'critical',
    score: 94,
    category: 'protocol-validation',
    description: 'Both Content-Length and Transfer-Encoding present'
  },
  {
    id: 'protocol-invalid-uri',
    name: 'Invalid URI Characters',
    pattern: /^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+[^\s]*[\x00-\x1f<>\\"]/i,
    field: 'request',
    severity: 'high',
    score: 77,
    category: 'protocol-validation',
    description: 'Invalid characters in request URI'
  },
  {
    id: 'protocol-uri-encoding-bypass',
    name: 'Double-Encoded URI',
    pattern: /%25[0-9a-fA-F]{2}|%252[0-7a-fA-F]/i,
    field: 'request',
    severity: 'high',
    score: 75,
    category: 'protocol-validation',
    description: 'Double URL encoding in request URI'
  },
  {
    id: 'protocol-header-injection',
    name: 'CRLF Injection in Headers',
    pattern: /[\r\n]{2,}|%0d%0a|%0a%0d/i,
    field: 'headers',
    severity: 'critical',
    score: 93,
    category: 'protocol-validation',
    description: 'CRLF injection for header injection attacks'
  },
  {
    id: 'protocol-host-header-injection',
    name: 'Host Header Injection',
    pattern: /host\s*:\s*[^:]*@|host\s*:\s*[^:]*:[^:]*:[^:]*/i,
    field: 'headers',
    severity: 'high',
    score: 76,
    category: 'protocol-validation',
    description: 'Malformed or malicious Host header'
  },
  {
    id: 'protocol-invalid-content-type',
    name: 'Invalid Content-Type Header',
    pattern: /content-type\s*:\s*(?![a-z]+\/[a-z+.-]+)/i,
    field: 'headers',
    severity: 'medium',
    score: 65,
    category: 'protocol-validation',
    description: 'Invalid Content-Type format'
  },
  {
    id: 'protocol-accept-header-bomb',
    name: 'Accept Header Bomb',
    pattern: /accept\s*:[^:\r\n]*,[^:\r\n]*,[^:\r\n]*,[^:\r\n]*,[^:\r\n]*,[^:\r\n]*,/i,
    field: 'headers',
    severity: 'medium',
    score: 60,
    category: 'protocol-validation',
    description: 'Excessive Accept header values'
  },
  {
    id: 'protocol-user-agent-long',
    name: 'Excessively Long User-Agent',
    pattern: /user-agent\s*:\s*.{500,}/i,
    field: 'headers',
    severity: 'medium',
    score: 55,
    category: 'protocol-validation',
    description: 'User-Agent header exceeds reasonable length'
  },
  {
    id: 'protocol-referer-injection',
    name: 'Referer Header Injection',
    pattern: /referer\s*:\s*.*(?:javascript:|data:|about:)/i,
    field: 'headers',
    severity: 'high',
    score: 72,
    category: 'protocol-validation',
    description: 'Dangerous URI scheme in Referer header'
  },
  {
    id: 'protocol-cookie-injection',
    name: 'CRLF in Cookie Header',
    pattern: /cookie\s*:[\s\S]*?[\r\n](?![\s])/i,
    field: 'headers',
    severity: 'high',
    score: 79,
    category: 'protocol-validation',
    description: 'CRLF characters in Cookie header'
  },
  {
    id: 'protocol-authorization-injection',
    name: 'CRLF in Authorization Header',
    pattern: /authorization\s*:[\s\S]*?[\r\n](?![\s])/i,
    field: 'headers',
    severity: 'critical',
    score: 91,
    category: 'protocol-validation',
    description: 'CRLF injection in Authorization header'
  },
  {
    id: 'protocol-range-attack',
    name: 'Range Request DoS',
    pattern: /range\s*:\s*bytes\s*=.*-.*,.*-.*,.*-.*,.*-.*,.*-.*/i,
    field: 'headers',
    severity: 'high',
    score: 74,
    category: 'protocol-validation',
    description: 'Excessive range requests (multipart range attack)'
  },
  {
    id: 'protocol-if-range-mismatch',
    name: 'If-Range and Range Mismatch',
    pattern: /if-range\s*:.*\r\n[\s\S]*?range\s*:/i,
    field: 'headers',
    severity: 'medium',
    score: 58,
    category: 'protocol-validation',
    description: 'Conflicting If-Range and Range headers'
  },
  {
    id: 'protocol-date-format-invalid',
    name: 'Invalid Date Header Format',
    pattern: /date\s*:\s*(?!(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun),)/i,
    field: 'headers',
    severity: 'medium',
    score: 52,
    category: 'protocol-validation',
    description: 'Invalid HTTP date format in Date header'
  },
  {
    id: 'protocol-cache-control-confusion',
    name: 'Conflicting Cache-Control Directives',
    pattern: /cache-control\s*:[\s\S]*?public[\s\S]*?private/i,
    field: 'headers',
    severity: 'medium',
    score: 61,
    category: 'protocol-validation',
    description: 'Conflicting Cache-Control directives'
  },
  {
    id: 'protocol-pragma-cache-mismatch',
    name: 'Pragma and Cache-Control Mismatch',
    pattern: /pragma\s*:\s*(?!no-cache)[\s\S]*?cache-control\s*:\s*no-cache/i,
    field: 'headers',
    severity: 'medium',
    score: 59,
    category: 'protocol-validation',
    description: 'Mismatched Pragma and Cache-Control'
  },
  {
    id: 'protocol-age-negative',
    name: 'Negative Age Header',
    pattern: /age\s*:\s*-\d+/i,
    field: 'headers',
    severity: 'medium',
    score: 54,
    category: 'protocol-validation',
    description: 'Negative value in Age header'
  },
  {
    id: 'protocol-max-age-negative',
    name: 'Negative Max-Age in Cache-Control',
    pattern: /cache-control\s*:[\s\S]*?max-age\s*=\s*-/i,
    field: 'headers',
    severity: 'medium',
    score: 56,
    category: 'protocol-validation',
    description: 'Negative max-age value'
  },
  {
    id: 'protocol-expires-invalid',
    name: 'Invalid Expires Header',
    pattern: /expires\s*:\s*(?!0|(?:(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun),))/i,
    field: 'headers',
    severity: 'medium',
    score: 53,
    category: 'protocol-validation',
    description: 'Invalid date/time in Expires header'
  },
  {
    id: 'protocol-connection-upgrade',
    name: 'Suspicious Connection Header',
    pattern: /connection\s*:\s*(?!keep-alive|close|upgrade)[\s\S]*?upgrade/i,
    field: 'headers',
    severity: 'high',
    score: 71,
    category: 'protocol-validation',
    description: 'Connection header with upgrade request'
  },
  {
    id: 'protocol-upgrade-invalid',
    name: 'Invalid Upgrade Header Protocol',
    pattern: /upgrade\s*:\s*(?!websocket|h2|h2c|h2-14|h2-15|h2-16|h2c-14)/i,
    field: 'headers',
    severity: 'high',
    score: 70,
    category: 'protocol-validation',
    description: 'Unknown protocol in Upgrade header'
  },
  {
    id: 'protocol-proxy-injection',
    name: 'Proxy Header Injection',
    pattern: /(?:x-forwarded-for|x-real-ip|cf-connecting-ip)\s*:[\s\S]*?[\r\n]/i,
    field: 'headers',
    severity: 'high',
    score: 73,
    category: 'protocol-validation',
    description: 'Suspicious proxy headers'
  },
  {
    id: 'protocol-expect-100',
    name: 'Invalid Expect Header',
    pattern: /expect\s*:\s*(?!100-continue)/i,
    field: 'headers',
    severity: 'medium',
    score: 57,
    category: 'protocol-validation',
    description: 'Invalid value in Expect header'
  },
  {
    id: 'protocol-via-chain',
    name: 'Excessive Via Header Chain',
    pattern: /via\s*:[\s\S]*?,[\s\S]*?,[\s\S]*?,[\s\S]*?,[\s\S]*?,/i,
    field: 'headers',
    severity: 'high',
    score: 69,
    category: 'protocol-validation',
    description: 'Excessively long proxy chain'
  },
  {
    id: 'protocol-warning-header',
    name: 'Invalid Warning Header',
    pattern: /warning\s*:\s*(?!\d{3})/i,
    field: 'headers',
    severity: 'medium',
    score: 51,
    category: 'protocol-validation',
    description: 'Invalid Warning header format'
  },
  {
    id: 'protocol-allow-methods',
    name: 'Invalid Allow Header',
    pattern: /allow\s*:[\s\S]*?[^A-Z\s,]/i,
    field: 'headers',
    severity: 'medium',
    score: 48,
    category: 'protocol-validation',
    description: 'Invalid methods in Allow header'
  },
  {
    id: 'protocol-accept-encoding-bomb',
    name: 'Accept-Encoding Bomb',
    pattern: /accept-encoding\s*:[^:\r\n]*,[^:\r\n]*,[^:\r\n]*,[^:\r\n]*,[^:\r\n]*,/i,
    field: 'headers',
    severity: 'medium',
    score: 59,
    category: 'protocol-validation',
    description: 'Excessive Accept-Encoding values'
  },
  {
    id: 'protocol-te-header-abuse',
    name: 'TE Header HTTP Smuggling',
    pattern: /te\s*:\s*(?!trailers)[\s\S]*?trailers/i,
    field: 'headers',
    severity: 'high',
    score: 81,
    category: 'protocol-validation',
    description: 'TE header smuggling techniques'
  },
  {
    id: 'protocol-content-encoding-invalid',
    name: 'Invalid Content-Encoding',
    pattern: /content-encoding\s*:\s*(?!gzip|deflate|br|compress|identity|x-gzip)/i,
    field: 'headers',
    severity: 'medium',
    score: 63,
    category: 'protocol-validation',
    description: 'Unknown Content-Encoding value'
  },
  {
    id: 'protocol-content-location-invalid',
    name: 'Invalid Content-Location',
    pattern: /content-location\s*:\s*(?:\/\/|javascript:|data:|about:)/i,
    field: 'headers',
    severity: 'high',
    score: 68,
    category: 'protocol-validation',
    description: 'Dangerous protocol in Content-Location'
  },
  {
    id: 'protocol-link-header-injection',
    name: 'Link Header Injection',
    pattern: /link\s*:[\s\S]*?>;[\s\S]*?[<>]/i,
    field: 'headers',
    severity: 'high',
    score: 66,
    category: 'protocol-validation',
    description: 'Malformed Link header'
  },
  {
    id: 'protocol-retry-after-invalid',
    name: 'Invalid Retry-After Format',
    pattern: /retry-after\s*:\s*(?!\d{1,3}|(?:(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun),))/i,
    field: 'headers',
    severity: 'medium',
    score: 49,
    category: 'protocol-validation',
    description: 'Invalid Retry-After value'
  },
  {
    id: 'protocol-request-line-splitting',
    name: 'Request Line Injection',
    pattern: /^(GET|POST|PUT|DELETE)\s+[^\s]*(?:\r|\n|%0[ad])/i,
    field: 'request',
    severity: 'critical',
    score: 90,
    category: 'protocol-validation',
    description: 'CRLF in HTTP request line'
  },
  {
    id: 'protocol-empty-header-name',
    name: 'Empty Header Name',
    pattern: /^\s*:\s*[^:\r\n]/m,
    field: 'headers',
    severity: 'high',
    score: 67,
    category: 'protocol-validation',
    description: 'Header with empty name'
  },
  {
    id: 'protocol-header-line-folding',
    name: 'Obsolete Header Line Folding',
    pattern: /\r\n[\s\t]+/m,
    field: 'headers',
    severity: 'medium',
    score: 64,
    category: 'protocol-validation',
    description: 'Obsolete line folding in headers'
  },
  {
    id: 'protocol-space-in-header-name',
    name: 'Space in Header Name',
    pattern: /^[^\s:]*\s+[^\s:]*\s*:/m,
    field: 'headers',
    severity: 'high',
    score: 74,
    category: 'protocol-validation',
    description: 'Spaces in header field name'
  },
  {
    id: 'protocol-tab-in-uri',
    name: 'Tab Character in URI',
    pattern: /^(GET|POST|PUT|DELETE|PATCH|HEAD)\s+[^\s]*\t/i,
    field: 'request',
    severity: 'high',
    score: 72,
    category: 'protocol-validation',
    description: 'Tab character in request URI'
  },
  {
    id: 'protocol-form-urlencoded-invalid',
    name: 'Invalid Form URL Encoding',
    pattern: /application\/x-www-form-urlencoded[\s\S]*?(?:[^a-zA-Z0-9_%\-\.&=](?!%[0-9a-fA-F]{2}))/i,
    field: 'request',
    severity: 'medium',
    score: 62,
    category: 'protocol-validation',
    description: 'Invalid characters in form data'
  },
  {
    id: 'protocol-multipart-boundary',
    name: 'Invalid Multipart Boundary',
    pattern: /multipart\/(?:form-data|mixed)[\s\S]*?boundary\s*=(?![a-zA-Z0-9._-]{1,70})/i,
    field: 'headers',
    severity: 'high',
    score: 75,
    category: 'protocol-validation',
    description: 'Invalid or missing multipart boundary'
  },
  {
    id: 'protocol-path-traversal',
    name: 'Path Traversal in URI',
    pattern: /^(GET|POST|PUT|DELETE|PATCH|HEAD)\s+[^\s]*\.\.\/|\.\.\\\\/i,
    field: 'request',
    severity: 'high',
    score: 77,
    category: 'protocol-validation',
    description: 'Path traversal sequences in request URI'
  },
  {
    id: 'protocol-backslash-uri',
    name: 'Backslash in URI Path',
    pattern: /^(GET|POST|PUT|DELETE|PATCH|HEAD)\s+[^\s]*\\(?!\/)/i,
    field: 'request',
    severity: 'high',
    score: 71,
    category: 'protocol-validation',
    description: 'Backslash used as path separator'
  },
  {
    id: 'protocol-raw-unicode-uri',
    name: 'Raw Unicode in URI',
    pattern: /^(GET|POST|PUT|DELETE)\s+[^\s]*[^\x00-\x7F]/i,
    field: 'request',
    severity: 'medium',
    score: 60,
    category: 'protocol-validation',
    description: 'Non-ASCII characters in request URI'
  },
  {
    id: 'protocol-fragment-identifier',
    name: 'Fragment Identifier in Request',
    pattern: /^(GET|POST|PUT|DELETE|PATCH|HEAD)\s+[^\s]*#/i,
    field: 'request',
    severity: 'medium',
    score: 57,
    category: 'protocol-validation',
    description: 'Fragment identifier in HTTP request URI'
  },
  {
    id: 'protocol-query-string-bomb',
    name: 'Excessive Query String',
    pattern: /\?[^=&]*=[^&]*(&[^=&]*=[^&]*){100,}/,
    field: 'request',
    severity: 'high',
    score: 70,
    category: 'protocol-validation',
    description: 'Query string with 100+ parameters'
  },
  {
    id: 'protocol-status-line-invalid',
    name: 'Invalid Status Line Format',
    pattern: /^HTTP\/(?!1\.[01]|2\.0|3\.0)\S+\s+(?!\d{3})/i,
    field: 'response',
    severity: 'medium',
    score: 51,
    category: 'protocol-validation',
    description: 'Malformed HTTP status line'
  },
  {
    id: 'protocol-reason-phrase-invalid',
    name: 'Invalid Reason Phrase',
    pattern: /HTTP\/\d\.\d\s+\d{3}\s+[^\x20-\x7E]/,
    field: 'response',
    severity: 'medium',
    score: 50,
    category: 'protocol-validation',
    description: 'Invalid characters in reason phrase'
  },
  {
    id: 'protocol-status-code-range',
    name: 'Invalid HTTP Status Code',
    pattern: /HTTP\/\d\.\d\s+(?!100|101|[23]\d{2}|400|40[134567]|41[0-7]|5\d{2})\d{3}/i,
    field: 'response',
    severity: 'medium',
    score: 47,
    category: 'protocol-validation',
    description: 'Non-standard HTTP status code'
  },
  {
    id: 'protocol-http2-pseudo-headers',
    name: 'HTTP/2 Pseudo-Header Abuse',
    pattern: /:\w+\s*:[^\s]/i,
    field: 'headers',
    severity: 'high',
    score: 76,
    category: 'protocol-validation',
    description: 'Invalid HTTP/2 pseudo-header'
  },
  {
    id: 'protocol-header-name-uppercase',
    name: 'Uppercase in Header Name',
    pattern: /^[a-z]*[A-Z][a-z]*:/m,
    field: 'headers',
    severity: 'low',
    score: 35,
    category: 'protocol-validation',
    description: 'Non-standard header name capitalization'
  },
  {
    id: 'protocol-http09-request',
    name: 'HTTP/0.9 Request Detection',
    pattern: /^(GET|HEAD)\s+[^\s]+\s*\r?\n(?!HTTP)/i,
    field: 'request',
    severity: 'medium',
    score: 58,
    category: 'protocol-validation',
    description: 'HTTP/0.9 simple request format'
  },
  {
    id: 'protocol-connect-method-abuse',
    name: 'CONNECT Method Abuse',
    pattern: /^CONNECT\s+[^\s]*[^\d]\s+HTTP/i,
    field: 'request',
    severity: 'high',
    score: 73,
    category: 'protocol-validation',
    description: 'CONNECT method with invalid destination'
  },
  {
    id: 'protocol-trace-method-abuse',
    name: 'TRACE Method Detected',
    pattern: /^TRACE\s+/i,
    field: 'request',
    severity: 'high',
    score: 68,
    category: 'protocol-validation',
    description: 'TRACE method which can expose headers'
  },
  {
    id: 'protocol-options-wildcard-abuse',
    name: 'OPTIONS * Wildcard Abuse',
    pattern: /^OPTIONS\s+\*\s+HTTP\/1\.1/i,
    field: 'request',
    severity: 'medium',
    score: 59,
    category: 'protocol-validation',
    description: 'OPTIONS request to server root'
  },
  {
    id: 'protocol-content-length-large',
    name: 'Excessively Large Content-Length',
    pattern: /content-length\s*:\s*(?:[5-9]\d{8}|\d{10,})/i,
    field: 'headers',
    severity: 'high',
    score: 72,
    category: 'protocol-validation',
    description: 'Content-Length exceeds 500MB'
  },
  {
    id: 'protocol-content-length-format',
    name: 'Invalid Content-Length Format',
    pattern: /content-length\s*:\s*[+-]|content-length\s*:\s*0[xX]/i,
    field: 'headers',
    severity: 'high',
    score: 70,
    category: 'protocol-validation',
    description: 'Content-Length with sign or hex prefix'
  },
  {
    id: 'protocol-header-value-spaces',
    name: 'Excessive Spaces in Header Value',
    pattern: /:\s{5,}[^\s]|:\s*[^\s]*\s{10,}[^\s]/,
    field: 'headers',
    severity: 'medium',
    score: 56,
    category: 'protocol-validation',
    description: 'Abnormal whitespace in header values'
  },
  {
    id: 'protocol-host-port-mismatch',
    name: 'Host Header Port Mismatch',
    pattern: /host\s*:\s*[^\s:]+:(\d+)/i,
    field: 'headers',
    severity: 'medium',
    score: 61,
    category: 'protocol-validation',
    description: 'Host header with port number'
  },
  {
    id: 'protocol-accept-charset-bomb',
    name: 'Accept-Charset Bomb',
    pattern: /accept-charset\s*:[^:\r\n]*,[^:\r\n]*,[^:\r\n]*,[^:\r\n]*,[^:\r\n]*,/i,
    field: 'headers',
    severity: 'medium',
    score: 55,
    category: 'protocol-validation',
    description: 'Excessive Accept-Charset values'
  },
  {
    id: 'protocol-accept-language-bomb',
    name: 'Accept-Language Bomb',
    pattern: /accept-language\s*:[^:\r\n]*,[^:\r\n]*,[^:\r\n]*,[^:\r\n]*,[^:\r\n]*,/i,
    field: 'headers',
    severity: 'medium',
    score: 54,
    category: 'protocol-validation',
    description: 'Excessive Accept-Language values'
  },
  {
    id: 'protocol-x-forwarded-for-spoof',
    name: 'X-Forwarded-For Spoofing',
    pattern: /x-forwarded-for\s*:\s*(?:127\.|192\.168\.|10\.|172\.1[6-9]\.|172\.2[0-9]\.|172\.3[01]\.)/i,
    field: 'headers',
    severity: 'high',
    score: 71,
    category: 'protocol-validation',
    description: 'Private IP in X-Forwarded-For'
  },
  {
    id: 'protocol-etag-weak-strong-mismatch',
    name: 'ETag Format Invalid',
    pattern: /etag\s*:\s*(?!W?"[^"]*"|"[^"]*")/i,
    field: 'headers',
    severity: 'medium',
    score: 52,
    category: 'protocol-validation',
    description: 'Invalid ETag format'
  },
  {
    id: 'protocol-if-match-mismatch',
    name: 'If-Match Multiple ETags',
    pattern: /if-match\s*:(?:[^,]*,){5,}/i,
    field: 'headers',
    severity: 'medium',
    score: 50,
    category: 'protocol-validation',
    description: 'Multiple ETags in If-Match'
  },
  {
    id: 'protocol-if-none-match-conflict',
    name: 'If-None-Match with If-Modified-Since',
    pattern: /if-none-match[\s\S]*?if-modified-since|if-modified-since[\s\S]*?if-none-match/i,
    field: 'headers',
    severity: 'medium',
    score: 49,
    category: 'protocol-validation',
    description: 'Conflicting conditional headers'
  },
  {
    id: 'protocol-location-header-crlf',
    name: 'Location Header CRLF Injection',
    pattern: /location\s*:[\s\S]*?[\r\n](?![\s])/i,
    field: 'headers',
    severity: 'critical',
    score: 89,
    category: 'protocol-validation',
    description: 'CRLF in Location header'
  },
  {
    id: 'protocol-set-cookie-crlf',
    name: 'Set-Cookie CRLF Injection',
    pattern: /set-cookie\s*:[\s\S]*?[\r\n](?![\s])/i,
    field: 'headers',
    severity: 'critical',
    score: 88,
    category: 'protocol-validation',
    description: 'CRLF injection in Set-Cookie'
  },
  {
    id: 'protocol-www-authenticate-crlf',
    name: 'WWW-Authenticate CRLF Injection',
    pattern: /www-authenticate\s*:[\s\S]*?[\r\n](?![\s])/i,
    field: 'headers',
    severity: 'critical',
    score: 87,
    category: 'protocol-validation',
    description: 'CRLF in WWW-Authenticate header'
  },
  {
    id: 'protocol-sec-websocket-key-invalid',
    name: 'Invalid WebSocket Key',
    pattern: /sec-websocket-key\s*:\s*(?![A-Za-z0-9+\/]{24}==)/i,
    field: 'headers',
    severity: 'high',
    score: 69,
    category: 'protocol-validation',
    description: 'Malformed Sec-WebSocket-Key'
  },
  {
    id: 'protocol-sec-fetch-mode-invalid',
    name: 'Invalid Sec-Fetch-Mode',
    pattern: /sec-fetch-mode\s*:\s*(?!navigate|nested-navigate|same-origin|same-site|cross-site|no-cors|cors|websocket|document)/i,
    field: 'headers',
    severity: 'medium',
    score: 57,
    category: 'protocol-validation',
    description: 'Unknown Sec-Fetch-Mode value'
  },
  {
    id: 'protocol-sec-fetch-site-invalid',
    name: 'Invalid Sec-Fetch-Site',
    pattern: /sec-fetch-site\s*:\s*(?!cross-site|same-origin|same-site|none)/i,
    field: 'headers',
    severity: 'medium',
    score: 56,
    category: 'protocol-validation',
    description: 'Unknown Sec-Fetch-Site value'
  },
  {
    id: 'protocol-origin-header-mismatch',
    name: 'Origin Header Mismatch',
    pattern: /origin\s*:\s*(?:null|about:blank)/i,
    field: 'headers',
    severity: 'medium',
    score: 58,
    category: 'protocol-validation',
    description: 'Suspicious Origin header value'
  },
  {
    id: 'protocol-referrer-policy-crlf',
    name: 'Referrer-Policy CRLF Injection',
    pattern: /referrer-policy\s*:[\s\S]*?[\r\n](?![\s])/i,
    field: 'headers',
    severity: 'high',
    score: 75,
    category: 'protocol-validation',
    description: 'CRLF in Referrer-Policy header'
  },
  {
    id: 'protocol-content-security-policy-crlf',
    name: 'CSP Header CRLF Injection',
    pattern: /content-security-policy[\s\S]*?:\s*[\s\S]*?[\r\n](?![\s])/i,
    field: 'headers',
    severity: 'critical',
    score: 92,
    category: 'protocol-validation',
    description: 'CRLF in CSP header'
  },
  {
    id: 'protocol-x-frame-options-crlf',
    name: 'X-Frame-Options CRLF Injection',
    pattern: /x-frame-options\s*:[\s\S]*?[\r\n](?![\s])/i,
    field: 'headers',
    severity: 'high',
    score: 74,
    category: 'protocol-validation',
    description: 'CRLF in X-Frame-Options'
  },
  {
    id: 'protocol-x-content-type-options-invalid',
    name: 'Invalid X-Content-Type-Options',
    pattern: /x-content-type-options\s*:\s*(?!nosniff)/i,
    field: 'headers',
    severity: 'medium',
    score: 51,
    category: 'protocol-validation',
    description: 'Unknown X-Content-Type-Options value'
  },
  {
    id: 'protocol-hsts-invalid',
    name: 'Invalid HSTS Header',
    pattern: /strict-transport-security\s*:(?!.*max-age\s*=\s*\d+)/i,
    field: 'headers',
    severity: 'medium',
    score: 53,
    category: 'protocol-validation',
    description: 'Invalid HSTS format'
  },
  {
    id: 'protocol-request-id-length',
    name: 'Excessively Long Request ID',
    pattern: /x-request-id\s*:\s*.{256,}/i,
    field: 'headers',
    severity: 'low',
    score: 38,
    category: 'protocol-validation',
    description: 'Request ID exceeds 256 characters'
  },
  {
    id: 'protocol-correlation-id-length',
    name: 'Excessively Long Correlation ID',
    pattern: /x-correlation-id\s*:\s*.{256,}/i,
    field: 'headers',
    severity: 'low',
    score: 37,
    category: 'protocol-validation',
    description: 'Correlation ID exceeds 256 characters'
  },
  {
    id: 'protocol-custom-header-bomb',
    name: 'Excessive Custom Headers',
    pattern: /^x-[^:]*:[^\r\n]*\r\nx-[^:]*:[^\r\n]*\r\nx-[^:]*:[^\r\n]*\r\nx-[^:]*:[^\r\n]*\r\nx-[^:]*:[^\r\n]*\r\nx-[^:]*:/im,
    field: 'headers',
    severity: 'high',
    score: 66,
    category: 'protocol-validation',
    description: 'More than 5 custom X-* headers'
  },
  {
    id: 'protocol-header-byte-count',
    name: 'Excessively Large Header Section',
    pattern: /./,
    field: 'headers',
    severity: 'high',
    score: 64,
    category: 'protocol-validation',
    description: 'Total header section exceeds safe size'
  },
  {
    id: 'protocol-request-uri-length',
    name: 'Excessively Long Request URI',
    pattern: /^(GET|POST|PUT|DELETE|PATCH|HEAD)\s+.{8192,}/i,
    field: 'request',
    severity: 'high',
    score: 70,
    category: 'protocol-validation',
    description: 'Request URI exceeds 8192 bytes'
  },
  {
    id: 'protocol-null-byte-header-name',
    name: 'Null Byte in Header Name',
    pattern: /^\w*\x00[^:]*:/m,
    field: 'headers',
    severity: 'critical',
    score: 91,
    category: 'protocol-validation',
    description: 'Null byte in header field name'
  },
  {
    id: 'protocol-null-byte-header-value',
    name: 'Null Byte in Header Value',
    pattern: /:\s*[^\r\n]*\x00[^\r\n]*/m,
    field: 'headers',
    severity: 'critical',
    score: 90,
    category: 'protocol-validation',
    description: 'Null byte in header field value'
  },
  {
    id: 'protocol-null-byte-uri',
    name: 'Null Byte in Request URI',
    pattern: /^(GET|POST|PUT|DELETE|PATCH|HEAD)\s+[^\s]*\x00/i,
    field: 'request',
    severity: 'critical',
    score: 95,
    category: 'protocol-validation',
    description: 'Null byte in request URI'
  },
  {
    id: 'protocol-parameter-pollution',
    name: 'HTTP Parameter Pollution',
    pattern: /[?&]\w+=(?:[^&]*&){4}\w+=/,
    field: 'request',
    severity: 'high',
    score: 73,
    category: 'protocol-validation',
    description: 'Duplicate parameter names (HPP attack)'
  },
  {
    id: 'protocol-unicode-directory-traversal',
    name: 'Unicode Directory Traversal',
    pattern: /(?:%u002e|%u252e)+(?:%u002f|%u252f)/i,
    field: 'request',
    severity: 'high',
    score: 76,
    category: 'protocol-validation',
    description: 'Unicode-encoded directory traversal'
  },
  {
    id: 'protocol-utf8-bypass',
    name: 'UTF-8 Encoding Bypass',
    pattern: /%c0%ae|%c1%9c|%e0%80%ae/i,
    field: 'request',
    severity: 'high',
    score: 75,
    category: 'protocol-validation',
    description: 'Overlong UTF-8 sequences'
  },
  {
    id: 'protocol-semicolon-separator',
    name: 'Semicolon Path Separator',
    pattern: /;\s*(?:GET|POST|PUT|DELETE|PATCH|HEAD)/i,
    field: 'request',
    severity: 'high',
    score: 72,
    category: 'protocol-validation',
    description: 'Semicolon as path separator (ASP.NET abuse)'
  },
  {
    id: 'protocol-content-type-charset',
    name: 'Suspicious Charset in Content-Type',
    pattern: /content-type\s*:[^;]*;\s*charset\s*=(?:utf-7|utf7|cp1252|iso-2022-jp)/i,
    field: 'headers',
    severity: 'high',
    score: 71,
    category: 'protocol-validation',
    description: 'Dangerous charset declaration'
  },
  {
    id: 'protocol-xml-content-type-bomb',
    name: 'XML Content-Type with Large Body',
    pattern: /content-type\s*:\s*application\/xml/i,
    field: 'headers',
    severity: 'medium',
    score: 60,
    category: 'protocol-validation',
    description: 'XML content type (XXE risk)'
  },
  {
    id: 'protocol-request-body-no-content-type',
    name: 'Request Body Without Content-Type',
    pattern: /^(POST|PUT|PATCH)\s+[^\s]+\s+HTTP\/1\.1[\s\S]*(?!content-type)/i,
    field: 'request',
    severity: 'medium',
    score: 55,
    category: 'protocol-validation',
    description: 'POST/PUT without Content-Type header'
  },
  {
    id: 'protocol-get-with-body',
    name: 'GET Request with Body',
    pattern: /^GET\s+[^\s]+\s+HTTP\/1\.1[\s\S]*content-length\s*:\s*[1-9]/i,
    field: 'request',
    severity: 'medium',
    score: 54,
    category: 'protocol-validation',
    description: 'GET request with Content-Length'
  },
  {
    id: 'protocol-delete-with-body',
    name: 'DELETE Request with Body',
    pattern: /^DELETE\s+[^\s]+\s+HTTP\/1\.1[\s\S]*content-length\s*:\s*[1-9]/i,
    field: 'request',
    severity: 'medium',
    score: 53,
    category: 'protocol-validation',
    description: 'DELETE request with body'
  },
  {
    id: 'protocol-head-with-body',
    name: 'HEAD Request with Body',
    pattern: /^HEAD\s+[^\s]+\s+HTTP\/1\.1[\s\S]*content-length\s*:\s*[1-9]/i,
    field: 'request',
    severity: 'medium',
    score: 52,
    category: 'protocol-validation',
    description: 'HEAD request with Content-Length'
  },
  {
    id: 'protocol-http-tunnel-abuse',
    name: 'HTTP TUNNEL Abuse',
    pattern: /^TUNNEL\s+/i,
    field: 'request',
    severity: 'high',
    score: 74,
    category: 'protocol-validation',
    description: 'Illegal HTTP TUNNEL method'
  },
  {
    id: 'protocol-webdav-method-abuse',
    name: 'WebDAV Method Injection',
    pattern: /^(?:PROPFIND|PROPPATCH|MKCOL|COPY|MOVE|LOCK|UNLOCK)\s+/i,
    field: 'request',
    severity: 'medium',
    score: 59,
    category: 'protocol-validation',
    description: 'WebDAV method in HTTP request'
  }
];
