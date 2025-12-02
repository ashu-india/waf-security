// XML External Entity (XXE) Injection Rules (ModSecurity CRS 921)
export const XXE_RULES = [
  {
    id: 'xxe-attack',
    name: 'XXE - XML External Entity',
    pattern: /<!ENTITY[^>]+SYSTEM[^>]+>/i,
    field: 'body',
    severity: 'critical',
    score: 95,
    category: 'xxe',
    description: 'XML External Entity injection attempt',
    recommendation: 'Disable external entities in XML parser'
  },
  {
    id: 'xxe-dtd',
    name: 'XXE - DOCTYPE Declaration',
    pattern: /<!DOCTYPE[^>]+\[/i,
    field: 'body',
    severity: 'high',
    score: 70,
    category: 'xxe',
    description: 'DOCTYPE with internal subset (potential XXE)',
    recommendation: 'Disable DTD processing in XML parser'
  },
  {
    id: 'xxe-billion-laughs',
    name: 'XXE - Billion Laughs Attack',
    pattern: /<!ENTITY\s+\w+\s*"&\w+;&\w+;[\s\S]*?"[\s\S]*?<!ENTITY\s+\w+\s*"&\w+;"/i,
    field: 'body',
    severity: 'high',
    score: 85,
    category: 'xxe',
    description: 'Exponential entity expansion (Billion Laughs/XML bomb)',
    recommendation: 'Limit entity expansion depth and disable entity substitution'
  },
  {
    id: 'xxe-file-disclosure',
    name: 'XXE - File Disclosure (file:// URI)',
    pattern: /<!ENTITY\s+\w+\s+SYSTEM\s+["']file:\/\//i,
    field: 'body',
    severity: 'critical',
    score: 96,
    category: 'xxe',
    description: 'File disclosure via file:// URI in ENTITY declaration',
    recommendation: 'Disable file URI scheme in XML entities'
  },
  {
    id: 'xxe-network-access',
    name: 'XXE - Network Access (http:// URI)',
    pattern: /<!ENTITY\s+\w+\s+SYSTEM\s+["'](https?|ftp):\/\//i,
    field: 'body',
    severity: 'high',
    score: 88,
    category: 'xxe',
    description: 'Network-based XXE for SSRF or data exfiltration',
    recommendation: 'Disable external URI schemes in XML parser'
  },
  {
    id: 'xxe-parameter-entity',
    name: 'XXE - Parameter Entity Injection',
    pattern: /<!ENTITY\s+%\w+\s+SYSTEM/i,
    field: 'body',
    severity: 'high',
    score: 86,
    category: 'xxe',
    description: 'Parameter entity injection for XXE exploitation',
    recommendation: 'Disable parameter entities in DTD'
  },
  {
    id: 'xxe-internal-subset',
    name: 'XXE - Internal DTD Subset with Entity',
    pattern: /<!DOCTYPE\s+\w+\s*\[\s*<!ENTITY\s+\w+\s+SYSTEM/i,
    field: 'body',
    severity: 'critical',
    score: 93,
    category: 'xxe',
    description: 'Internal DTD subset with SYSTEM entity declaration',
    recommendation: 'Disable internal DTD processing'
  },
  {
    id: 'xxe-public-identifier',
    name: 'XXE - PUBLIC Identifier Declaration',
    pattern: /<!ENTITY\s+\w+\s+PUBLIC\s+["'][^"']*["']\s+["'][^"']*["']/i,
    field: 'body',
    severity: 'high',
    score: 80,
    category: 'xxe',
    description: 'PUBLIC identifier in entity declaration for XXE',
    recommendation: 'Disable PUBLIC identifier resolution'
  },
  {
    id: 'xxe-wrapped-entity',
    name: 'XXE - Wrapped Entity Reference',
    pattern: /&[a-zA-Z0-9_\-]+;[\s\S]*?<!ENTITY|<!ENTITY[\s\S]*?&[a-zA-Z0-9_\-]+;/i,
    field: 'body',
    severity: 'high',
    score: 82,
    category: 'xxe',
    description: 'Entity reference combined with entity declaration (XXE nesting)',
    recommendation: 'Validate and sanitize entity references'
  },
  {
    id: 'xxe-remote-dtd',
    name: 'XXE - Remote DTD Fetching',
    pattern: /<!DOCTYPE\s+\w+\s+PUBLIC\s+["'][^"']*["']\s+["'](https?|ftp):\/\//i,
    field: 'body',
    severity: 'high',
    score: 87,
    category: 'xxe',
    description: 'Remote DTD URL for XXE exploitation',
    recommendation: 'Disable remote DTD loading'
  },
  {
    id: 'xxe-xmlns-injection',
    name: 'XXE - XML Namespace Injection',
    pattern: /xmlns\s*=\s*["'].*SYSTEM/i,
    field: 'body',
    severity: 'medium',
    score: 65,
    category: 'xxe',
    description: 'SYSTEM reference in xmlns attribute',
    recommendation: 'Validate and sanitize namespace declarations'
  },
  {
    id: 'xxe-comment-injection',
    name: 'XXE - XXE via XML Comments',
    pattern: /<!--[\s\S]*?<!ENTITY[\s\S]*?-->|<!--[\s\S]*?\$\{[\s\S]*?}[\s\S]*?-->/i,
    field: 'body',
    severity: 'medium',
    score: 60,
    category: 'xxe',
    description: 'XXE payload hidden in XML comments',
    recommendation: 'Strip and validate XML comments'
  },
  {
    id: 'xxe-cdata-injection',
    name: 'XXE - CDATA Section with Entity',
    pattern: /<!\[CDATA\[[\s\S]*?<!ENTITY|<!ENTITY[\s\S]*?\]\]>/i,
    field: 'body',
    severity: 'medium',
    score: 62,
    category: 'xxe',
    description: 'XXE payload combined with CDATA sections',
    recommendation: 'Validate CDATA content, disable entity processing'
  },
  {
    id: 'xxe-nested-entities',
    name: 'XXE - Nested Entity Declarations',
    pattern: /<!ENTITY[\s\S]*?<!ENTITY[\s\S]*?<!ENTITY/i,
    field: 'body',
    severity: 'high',
    score: 79,
    category: 'xxe',
    description: 'Multiple nested entity declarations for XXE',
    recommendation: 'Limit entity nesting depth'
  },
  {
    id: 'xxe-utf-bypass',
    name: 'XXE - UTF Encoding Bypass',
    pattern: /encoding\s*=\s*["']?(utf-32|utf-16|utf-8-sig)["']?[\s\S]*?<!ENTITY/i,
    field: 'body',
    severity: 'medium',
    score: 68,
    category: 'xxe',
    description: 'UTF encoding declarations to bypass XXE filters',
    recommendation: 'Normalize encoding before parsing'
  }
];
