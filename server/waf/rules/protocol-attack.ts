// Protocol Attack Rules
export const PROTOCOL_ATTACK_RULES = [
  {
    id: 'http-smuggling',
    name: 'HTTP Request Smuggling',
    pattern: /transfer-encoding\s*:\s*chunked.*content-length|content-length.*transfer-encoding\s*:\s*chunked/i,
    field: 'headers',
    severity: 'critical',
    score: 90,
    category: 'protocol-attack',
    description: 'HTTP request smuggling attempt',
    recommendation: 'Normalize HTTP requests at proxy level'
  }
];
