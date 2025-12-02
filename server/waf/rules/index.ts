// Modularized WAF Rules - All Categories
import { SQL_INJECTION_RULES } from './sql-injection';
import { XSS_RULES } from './xss';
import { RCE_RULES } from './rce';
import { LFI_RULES } from './lfi';
import { SSRF_RULES } from './ssrf';
import { JAVA_ATTACKS_RULES } from './java-attacks';
import { DOS_RULES } from './dos';
import { PROTOCOL_VALIDATION_RULES } from './protocol-validation';
import { HTTP_DESYNC_RULES } from './http-desync';
import { PROTOCOL_ATTACK_RULES } from './protocol-attack';
import { PATH_TRAVERSAL_RULES } from './path-traversal';
import { COMMAND_INJECTION_RULES } from './command-injection';
import { XXE_RULES } from './xxe';
import { HEADER_INJECTION_RULES } from './header-injection';
import { OPEN_REDIRECT_RULES } from './open-redirect';
import { NOSQL_RULES } from './nosql';
import { LDAP_RULES } from './ldap';
import { XPATH_RULES } from './xpath';
import { SSTI_RULES } from './ssti';
import { LOG_INJECTION_RULES } from './log-injection';
import { RECONNAISSANCE_RULES } from './reconnaissance';
import { MALWARE_RULES } from './malware';
import { RFI_RULES } from './rfi';
import { PROTOTYPE_POLLUTION_RULES } from './prototype-pollution';
import { AUTH_RULES } from './auth';
import { MASS_ASSIGNMENT_RULES } from './mass-assignment';
import { DATA_LEAKAGE_RULES } from './data-leakage';


export const OWASP_PATTERNS = [
  ...SQL_INJECTION_RULES,
  ...XSS_RULES,
  ...RCE_RULES,
  ...LFI_RULES,
  ...SSRF_RULES,
  ...JAVA_ATTACKS_RULES,
  ...DOS_RULES,
  ...PROTOCOL_VALIDATION_RULES,
  ...HTTP_DESYNC_RULES,
  ...PROTOCOL_ATTACK_RULES,
  ...PATH_TRAVERSAL_RULES,
  ...COMMAND_INJECTION_RULES,
  ...XXE_RULES,
  ...HEADER_INJECTION_RULES,
  ...OPEN_REDIRECT_RULES,
  ...NOSQL_RULES,
  ...LDAP_RULES,
  ...XPATH_RULES,
  ...SSTI_RULES,
  ...LOG_INJECTION_RULES,
  ...RECONNAISSANCE_RULES,
  ...MALWARE_RULES,
  ...RFI_RULES,
  ...PROTOTYPE_POLLUTION_RULES,
  ...AUTH_RULES,
  ...MASS_ASSIGNMENT_RULES,
  ...DATA_LEAKAGE_RULES
];
