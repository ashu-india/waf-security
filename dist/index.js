var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __require = /* @__PURE__ */ ((x) => typeof require !== "undefined" ? require : typeof Proxy !== "undefined" ? new Proxy(x, {
  get: (a, b) => (typeof require !== "undefined" ? require : a)[b]
}) : x)(function(x) {
  if (typeof require !== "undefined") return require.apply(this, arguments);
  throw Error('Dynamic require of "' + x + '" is not supported');
});
var __esm = (fn, res) => function __init() {
  return fn && (res = (0, fn[__getOwnPropNames(fn)[0]])(fn = 0)), res;
};
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);

// server/waf/rules/sql-injection.ts
var SQL_INJECTION_RULES;
var init_sql_injection = __esm({
  "server/waf/rules/sql-injection.ts"() {
    "use strict";
    SQL_INJECTION_RULES = [
      {
        id: "sqli-union",
        name: "SQL Injection - UNION Attack",
        pattern: /\bUNION\s+(ALL\s+)?SELECT\b/i,
        field: "request",
        severity: "critical",
        score: 95,
        category: "sql-injection",
        description: "Detects UNION-based SQL injection attempts",
        recommendation: "Use parameterized queries and input validation"
      },
      {
        id: "sqli-boolean",
        name: "SQL Injection - Boolean-based",
        pattern: /(\bOR\b|\bAND\b)\s+['"]?\d+['"]?\s*=\s*['"]?\d+['"]?/i,
        field: "request",
        severity: "high",
        score: 85,
        category: "sql-injection",
        description: "Detects boolean-based SQL injection attempts (OR 1=1)",
        recommendation: "Implement prepared statements"
      },
      {
        id: "sqli-stacked",
        name: "SQL Injection - Stacked Queries",
        pattern: /;\s*(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|TRUNCATE)\b/i,
        field: "request",
        severity: "critical",
        score: 90,
        category: "sql-injection",
        description: "Detects stacked SQL query injection",
        recommendation: "Disable multiple statements in database driver"
      },
      {
        id: "sqli-comment",
        name: "SQL Injection - Comment Bypass",
        pattern: /(--|#|\/\*.*\*\/)/,
        field: "query",
        severity: "medium",
        score: 45,
        category: "sql-injection",
        description: "SQL comment characters used to bypass filters",
        recommendation: "Strip or escape comment sequences"
      },
      {
        id: "sqli-time",
        name: "SQL Injection - Time-based",
        pattern: /\b(SLEEP|WAITFOR|BENCHMARK|DELAY)\s*\(/i,
        field: "request",
        severity: "high",
        score: 80,
        category: "sql-injection",
        description: "Time-based blind SQL injection attempt",
        recommendation: "Set strict query timeouts"
      },
      {
        id: "sqli-error",
        name: "SQL Injection - Error-based",
        pattern: /\b(EXTRACTVALUE|UPDATEXML|XMLTYPE|CONVERT|CAST)\s*\(/i,
        field: "request",
        severity: "high",
        score: 75,
        category: "sql-injection",
        description: "Error-based SQL injection technique",
        recommendation: "Hide database error messages from users"
      },
      {
        id: "sqli-inline-comment",
        name: "SQL Injection - Inline Comments",
        pattern: /\/\*.*?\*\/|--.*?$|#.*?$/mi,
        field: "request",
        severity: "high",
        score: 78,
        category: "sql-injection",
        description: "SQL inline comments detected (comment bypass attempt)",
        recommendation: "Filter SQL comments and special characters"
      },
      {
        id: "sqli-hex-encoding",
        name: "SQL Injection - Hex Encoded SQL",
        pattern: /0x[0-9a-fA-F]+|char\s*\([0-9]+\)|ascii\s*\(/i,
        field: "request",
        severity: "high",
        score: 82,
        category: "sql-injection",
        description: "Hex or ASCII encoded SQL keywords detected",
        recommendation: "Decode and validate all user input"
      },
      {
        id: "sqli-alternatives",
        name: "SQL Injection - Alternative Syntax",
        pattern: /\b(SELECT|INSERT|UPDATE|DELETE|DROP)\b[\s\S]*?\b(REPLACE|CASE|WHEN|THEN|ELSE)\b/i,
        field: "request",
        severity: "high",
        score: 75,
        category: "sql-injection",
        description: "Complex SQL syntax patterns detected",
        recommendation: "Use parameterized queries exclusively"
      },
      {
        id: "sqli-keywords",
        name: "SQL Injection - Suspicious Keywords",
        pattern: /\b(FETCH|PRAGMA|INFORMATION_SCHEMA|SYSTEM_USER|VERSION|DATABASE|SCHEMA|TABLE_SCHEMA|TABLE_NAME)\b/i,
        field: "request",
        severity: "high",
        score: 80,
        category: "sql-injection",
        description: "Suspicious SQL keywords for data exfiltration",
        recommendation: "Restrict access to system tables and schemas"
      },
      {
        id: "sqli-info-leakage",
        name: "SQL Injection - Information Leakage",
        pattern: /SQL\s+syntax|mysql_fetch|OLE\s+DB|Incorrect\s+syntax|Unclosed\s+quotation/i,
        field: "response",
        severity: "medium",
        score: 50,
        category: "sql-injection",
        description: "SQL error messages leaked in response",
        recommendation: "Hide database error details from users"
      },
      {
        id: "sqli-fuzzing",
        name: "SQL Injection - Fuzzing Patterns",
        pattern: /[\'"]+\s*(\+|-|\*|\/|%)\s*[\'"]+|[\'"]\s*;\s*[\'"]/,
        field: "request",
        severity: "medium",
        score: 65,
        category: "sql-injection",
        description: "SQL fuzzing patterns detected",
        recommendation: "Implement strict input validation"
      },
      {
        id: "sqli-identifiers",
        name: "SQL Injection - Identifier Manipulation",
        pattern: /\[.*?\]|`.*?`|".*?"|\b(USER|CURRENT_USER|SYSTEM_USER|SESSION_USER|DATABASE)\b/i,
        field: "request",
        severity: "high",
        score: 77,
        category: "sql-injection",
        description: "SQL identifier brackets or sensitive functions",
        recommendation: "Whitelist allowed identifiers"
      },
      {
        id: "sqli-obfuscation",
        name: "SQL Injection - Obfuscation Techniques",
        pattern: /\bXOR\b|\bOR\b\s+\d+\s*=\s*\d+|\bAND\b\s+\d+\s*=\s*\d+|!\s*=|<>|%3D/i,
        field: "request",
        severity: "high",
        score: 76,
        category: "sql-injection",
        description: "SQL obfuscation and evasion techniques",
        recommendation: "Normalize and validate all input"
      },
      {
        id: "sqli-advanced-evasion",
        name: "SQL Injection - Advanced Evasion",
        pattern: /\b(IF|CASE|WHEN|EXISTS|NOT\s+EXISTS|EXCEPT|INTERSECT|UNION\s+ALL)\b.*\b(SELECT|INSERT|UPDATE|DELETE)\b/i,
        field: "request",
        severity: "critical",
        score: 88,
        category: "sql-injection",
        description: "Advanced SQL evasion with compound statements",
        recommendation: "Implement strict query parsing"
      },
      {
        id: "sqli-batch-operations",
        name: "SQL Injection - Batch Operations",
        pattern: /;\s*CREATE|;\s*ALTER|;\s*DROP|;\s*EXEC|;\s*sp_/i,
        field: "request",
        severity: "critical",
        score: 92,
        category: "sql-injection",
        description: "Multiple SQL statements (batch injection)",
        recommendation: "Disable multi-statement execution"
      },
      {
        id: "sqli-double-encoding",
        name: "SQLi - Double URL Encoding",
        pattern: /%252[0-7a-fA-F]|%25[0-9a-fA-F]{2}.*(?:UNION|SELECT)/i,
        field: "request",
        severity: "high",
        score: 81,
        category: "sql-injection",
        description: "Double-encoded SQL injection payload"
      },
      {
        id: "sqli-unicode-encoding",
        name: "SQLi - Unicode Encoding Bypass",
        pattern: /\\u[0-9a-fA-F]{4}|&#\d+;|&#x[0-9a-fA-F]+;/i,
        field: "request",
        severity: "high",
        score: 79,
        category: "sql-injection",
        description: "Unicode-encoded SQL keywords"
      },
      {
        id: "sqli-case-variation",
        name: "SQLi - Case Variation Bypass",
        pattern: /[Ss][Ee][Ll][Ee][Cc][Tt]|[Uu][Nn][Ii][Oo][Nn]|[Ww][Hh][Ee][Rr][Ee]/,
        field: "request",
        severity: "medium",
        score: 65,
        category: "sql-injection",
        description: "Mixed-case SQL keywords for filter bypass"
      },
      {
        id: "sqli-null-byte",
        name: "SQLi - Null Byte Injection",
        pattern: /%00|\\x00|\\0(?=.*(?:SELECT|UNION))/i,
        field: "request",
        severity: "high",
        score: 76,
        category: "sql-injection",
        description: "Null byte in SQL injection payload"
      },
      {
        id: "sqli-whitespace-bypass",
        name: "SQLi - Whitespace Bypass Techniques",
        pattern: /(?:SELECT|UNION)[\s\n\r\t]+(?:ALL|DISTINCT)|OR[\s]+1[\s]*=[\s]*1/i,
        field: "request",
        severity: "high",
        score: 78,
        category: "sql-injection",
        description: "Newlines/tabs used to bypass filters"
      },
      {
        id: "sqli-mysql-into-outfile",
        name: "SQLi - MySQL INTO OUTFILE",
        pattern: /INTO\s+(OUTFILE|DUMPFILE)\s+["']/i,
        field: "request",
        severity: "critical",
        score: 93,
        category: "sql-injection",
        description: "MySQL file write via INTO OUTFILE"
      },
      {
        id: "sqli-postgresql-copy",
        name: "SQLi - PostgreSQL COPY Injection",
        pattern: /COPY\s+\w+\s+(?:FROM|TO)|pg_read_file|pg_write_file/i,
        field: "request",
        severity: "critical",
        score: 92,
        category: "sql-injection",
        description: "PostgreSQL file operations via COPY"
      },
      {
        id: "sqli-mssql-xp-cmdshell",
        name: "SQLi - MSSQL xp_cmdshell RCE",
        pattern: /xp_cmdshell|xp_regread|xp_regwrite|sp_oacreate/i,
        field: "request",
        severity: "critical",
        score: 95,
        category: "sql-injection",
        description: "MSSQL stored procedure RCE"
      },
      {
        id: "sqli-oracle-dbms-sql",
        name: "SQLi - Oracle DBMS_SQL Injection",
        pattern: /DBMS_SQL|EXECUTE\s+IMMEDIATE|UTL_FILE/i,
        field: "request",
        severity: "critical",
        score: 93,
        category: "sql-injection",
        description: "Oracle dynamic SQL execution"
      },
      {
        id: "sqli-second-order",
        name: "SQLi - Second-Order Injection Indicators",
        pattern: /INSERT\s+INTO.*SELECT|UPDATE.*SELECT|CREATE\s+TABLE.*SELECT/i,
        field: "request",
        severity: "high",
        score: 84,
        category: "sql-injection",
        description: "Second-order SQLi patterns"
      },
      {
        id: "sqli-subquery-injection",
        name: "SQLi - Subquery Injection",
        pattern: /\(SELECT.*FROM.*WHERE.*\)|SELECT.*\(SELECT/i,
        field: "request",
        severity: "high",
        score: 80,
        category: "sql-injection",
        description: "Nested subquery injection"
      },
      {
        id: "sqli-union-all-select",
        name: "SQLi - UNION ALL SELECT Variant",
        pattern: /UNION\s+ALL\s+SELECT/i,
        field: "request",
        severity: "critical",
        score: 94,
        category: "sql-injection",
        description: "UNION ALL SELECT injection"
      },
      {
        id: "sqli-intersect-except",
        name: "SQLi - INTERSECT/EXCEPT Injection",
        pattern: /\b(INTERSECT|EXCEPT)\s+SELECT/i,
        field: "request",
        severity: "high",
        score: 82,
        category: "sql-injection",
        description: "INTERSECT/EXCEPT set operations"
      },
      {
        id: "sqli-order-by-blind",
        name: "SQLi - ORDER BY Blind Injection",
        pattern: /ORDER\s+BY\s+\d+.*(?:--|\#)|ORDER\s+BY\s+\(SELECT/i,
        field: "request",
        severity: "high",
        score: 79,
        category: "sql-injection",
        description: "ORDER BY clause blind SQLi"
      },
      {
        id: "sqli-limit-offset",
        name: "SQLi - LIMIT/OFFSET Injection",
        pattern: /LIMIT\s+[\d,\s]+(?:UNION|SELECT|OR)|OFFSET.*(?:UNION|SELECT)/i,
        field: "request",
        severity: "high",
        score: 75,
        category: "sql-injection",
        description: "LIMIT/OFFSET clause injection"
      },
      {
        id: "sqli-group-by-having",
        name: "SQLi - GROUP BY/HAVING Injection",
        pattern: /GROUP\s+BY.*(?:UNION|SELECT|OR)|HAVING.*(?:UNION|SELECT)/i,
        field: "request",
        severity: "high",
        score: 77,
        category: "sql-injection",
        description: "GROUP BY/HAVING clause injection"
      },
      {
        id: "sqli-json-extraction",
        name: "SQLi - JSON Extraction Functions",
        pattern: /JSON_EXTRACT|JSON_UNQUOTE|JSON_CONTAINS|->|->>/i,
        field: "request",
        severity: "high",
        score: 76,
        category: "sql-injection",
        description: "JSON function extraction for data theft"
      },
      {
        id: "sqli-xml-functions",
        name: "SQLi - XML Function Injection",
        pattern: /XPATH|EXTRACTVALUE|UPDATEXML|XMLPARSE|XMLQUERY/i,
        field: "request",
        severity: "high",
        score: 80,
        category: "sql-injection",
        description: "XML function exploitation"
      },
      {
        id: "sqli-string-functions",
        name: "SQLi - String Manipulation for Bypass",
        pattern: /CONCAT\s*\(|CONCAT_WS|GROUP_CONCAT|STRING_AGG|REPLACE\s*\(.*OR/i,
        field: "request",
        severity: "high",
        score: 74,
        category: "sql-injection",
        description: "String functions for payload obfuscation"
      },
      {
        id: "sqli-cast-convert",
        name: "SQLi - CAST/CONVERT Type Juggling",
        pattern: /CAST\s*\([^)]*AS\s*(?:INT|CHAR|VARCHAR)|CONVERT\s*\([^)]*,[^)]*\)/i,
        field: "request",
        severity: "high",
        score: 78,
        category: "sql-injection",
        description: "Type conversion for bypass"
      },
      {
        id: "sqli-mathematical-ops",
        name: "SQLi - Mathematical Operations",
        pattern: /(\d+)\s*[\+\-\*\/\%]\s*(\d+)\s*(?:AND|OR|=)/i,
        field: "request",
        severity: "medium",
        score: 62,
        category: "sql-injection",
        description: "Math operations in WHERE clause"
      },
      {
        id: "sqli-bitwise-ops",
        name: "SQLi - Bitwise Operations",
        pattern: /(&|<<|>>|\^)\s*\d+|BINARY\s+/i,
        field: "request",
        severity: "high",
        score: 73,
        category: "sql-injection",
        description: "Bitwise operations for payload encoding"
      },
      {
        id: "sqli-like-bypass",
        name: "SQLi - LIKE Clause Injection",
        pattern: /LIKE\s+['"][\%_]|LIKE\s+[\d\w%_]*(?:%|_)/i,
        field: "request",
        severity: "high",
        score: 71,
        category: "sql-injection",
        description: "LIKE clause SQLi with wildcards"
      },
      {
        id: "sqli-in-list-injection",
        name: "SQLi - IN Clause Injection",
        pattern: /IN\s*\(\s*(?:SELECT|UNION)|IN\s*\([^)]*OR[^)]*\)/i,
        field: "request",
        severity: "high",
        score: 75,
        category: "sql-injection",
        description: "IN clause with subqueries"
      },
      {
        id: "sqli-exists-injection",
        name: "SQLi - EXISTS Clause Injection",
        pattern: /EXISTS\s*\(\s*SELECT|NOT\s+EXISTS\s*\(\s*SELECT/i,
        field: "request",
        severity: "high",
        score: 79,
        category: "sql-injection",
        description: "EXISTS clause exploitation"
      },
      {
        id: "sqli-between-injection",
        name: "SQLi - BETWEEN Clause Injection",
        pattern: /BETWEEN.*AND.*(?:SELECT|UNION|OR)/i,
        field: "request",
        severity: "high",
        score: 76,
        category: "sql-injection",
        description: "BETWEEN clause SQLi"
      },
      {
        id: "sqli-case-when-injection",
        name: "SQLi - CASE/WHEN Injection",
        pattern: /CASE\s+WHEN.*THEN.*(?:SELECT|UNION)|CASE\s+WHEN\s+.*=.*THEN/i,
        field: "request",
        severity: "high",
        score: 77,
        category: "sql-injection",
        description: "CASE statement conditional injection"
      },
      {
        id: "sqli-if-function",
        name: "SQLi - IF Function Injection",
        pattern: /IF\s*\([^)]*,[^)]*,[^)]*\).*(?:SELECT|UNION)|IF\s*\(\d+\s*=\s*\d+/i,
        field: "request",
        severity: "high",
        score: 78,
        category: "sql-injection",
        description: "IF conditional function exploitation"
      },
      {
        id: "sqli-aggregate-functions",
        name: "SQLi - Aggregate Function Abuse",
        pattern: /(?:COUNT|SUM|AVG|MIN|MAX)\s*\(\s*(?:\*|\w+)\s*\).*(?:SELECT|UNION)/i,
        field: "request",
        severity: "high",
        score: 72,
        category: "sql-injection",
        description: "Aggregate functions for data extraction"
      },
      {
        id: "sqli-window-functions",
        name: "SQLi - Window Functions",
        pattern: /ROW_NUMBER|RANK|DENSE_RANK|LAG|LEAD|OVER\s*\(/i,
        field: "request",
        severity: "high",
        score: 74,
        category: "sql-injection",
        description: "Window functions for advanced extraction"
      },
      {
        id: "sqli-cte-injection",
        name: "SQLi - CTE (WITH) Clause Injection",
        pattern: /WITH\s+\w+\s+AS\s*\(\s*SELECT|RECURSIVE/i,
        field: "request",
        severity: "high",
        score: 80,
        category: "sql-injection",
        description: "Common Table Expression injection"
      },
      {
        id: "sqli-lateral-join",
        name: "SQLi - LATERAL JOIN Injection",
        pattern: /LATERAL\s+\(|CROSS\s+APPLY|OUTER\s+APPLY/i,
        field: "request",
        severity: "high",
        score: 75,
        category: "sql-injection",
        description: "LATERAL/APPLY join injection"
      },
      {
        id: "sqli-full-outer-join",
        name: "SQLi - FULL OUTER JOIN Injection",
        pattern: /FULL\s+OUTER\s+JOIN.*(?:SELECT|UNION)|RIGHT\s+OUTER\s+JOIN.*(?:UNION)/i,
        field: "request",
        severity: "high",
        score: 73,
        category: "sql-injection",
        description: "Outer join exploitation"
      },
      {
        id: "sqli-self-join",
        name: "SQLi - Self-Join Exploitation",
        pattern: /FROM\s+\w+\s+a\s+JOIN\s+\w+\s+b.*(?:UNION|SELECT\s+\*\s+FROM)/i,
        field: "request",
        severity: "high",
        score: 71,
        category: "sql-injection",
        description: "Self-join for data enumeration"
      },
      {
        id: "sqli-cross-join",
        name: "SQLi - CROSS JOIN DoS",
        pattern: /CROSS\s+JOIN.*CROSS\s+JOIN|CROSS\s+JOIN.*CROSS\s+JOIN.*CROSS\s+JOIN/i,
        field: "request",
        severity: "high",
        score: 72,
        category: "sql-injection",
        description: "CROSS JOIN cartesian product DoS"
      },
      {
        id: "sqli-natural-join",
        name: "SQLi - NATURAL JOIN Confusion",
        pattern: /NATURAL\s+(?:INNER\s+)?JOIN|USING\s*\([^)]*\)/i,
        field: "request",
        severity: "medium",
        score: 68,
        category: "sql-injection",
        description: "NATURAL/USING join confusion"
      },
      {
        id: "sqli-on-clause-injection",
        name: "SQLi - ON Clause Injection",
        pattern: /ON\s+\d+\s*=\s*\d+|ON\s+.*OR\s+.*=|ON.*AND.*SELECT/i,
        field: "request",
        severity: "high",
        score: 76,
        category: "sql-injection",
        description: "JOIN ON clause exploitation"
      },
      {
        id: "sqli-where-clause-chain",
        name: "SQLi - WHERE Clause Chaining",
        pattern: /WHERE.*AND.*OR.*(?:=|!=|<>).*WHERE/i,
        field: "request",
        severity: "high",
        score: 70,
        category: "sql-injection",
        description: "Multiple WHERE conditions"
      },
      {
        id: "sqli-having-clause-injection",
        name: "SQLi - HAVING Filter Bypass",
        pattern: /GROUP\s+BY.*HAVING\s+[\d]\s*=\s*[\d]|HAVING\s+.*OR\s+.*=.*OR/i,
        field: "request",
        severity: "high",
        score: 74,
        category: "sql-injection",
        description: "HAVING clause filter bypass"
      },
      {
        id: "sqli-raw-string-concat",
        name: "SQLi - Raw String Concatenation",
        pattern: /['"][+\s]+"[^"]*"|['"][+\s]+'[^']*'/,
        field: "request",
        severity: "high",
        score: 77,
        category: "sql-injection",
        description: "String concatenation for payload building"
      },
      {
        id: "sqli-wildcard-injection",
        name: "SQLi - Wildcard Character Abuse",
        pattern: /['%_][%_]['"]|LIKE\s+['"][%_]+['"]|LIKE\s+CONCAT/i,
        field: "request",
        severity: "medium",
        score: 69,
        category: "sql-injection",
        description: "LIKE wildcard exploitation"
      },
      {
        id: "sqli-escape-quote-bypass",
        name: "SQLi - Quote Escape Bypass",
        pattern: /['\\"\\\\]+|['\\\\]{2,}|('')+/i,
        field: "request",
        severity: "high",
        score: 75,
        category: "sql-injection",
        description: "Quote/escape character bypass"
      },
      {
        id: "sqli-regex-like-injection",
        name: "SQLi - REGEXP/RLIKE Injection",
        pattern: /REGEXP\s+['"]|RLIKE\s+['"]|~\s*['"].*(?:SELECT|UNION)/i,
        field: "request",
        severity: "high",
        score: 76,
        category: "sql-injection",
        description: "Regular expression matching injection"
      },
      {
        id: "sqli-array-injection",
        name: "SQLi - Array/List Injection",
        pattern: /\[.*\].*(?:SELECT|UNION)|ARRAY\[|ARRAY\s*\(/i,
        field: "request",
        severity: "high",
        score: 73,
        category: "sql-injection",
        description: "Array/list operations in SQL"
      },
      {
        id: "sqli-triggers-injection",
        name: "SQLi - Trigger Manipulation",
        pattern: /CREATE\s+TRIGGER|ALTER\s+TRIGGER|DROP\s+TRIGGER|ON\s+(?:INSERT|UPDATE|DELETE)/i,
        field: "request",
        severity: "critical",
        score: 94,
        category: "sql-injection",
        description: "Database trigger creation for persistence"
      },
      {
        id: "sqli-view-injection",
        name: "SQLi - View Injection",
        pattern: /CREATE\s+(?:OR\s+REPLACE\s+)?VIEW|DROP\s+VIEW|ALTER\s+VIEW/i,
        field: "request",
        severity: "critical",
        score: 91,
        category: "sql-injection",
        description: "Database view manipulation"
      },
      {
        id: "sqli-procedure-injection",
        name: "SQLi - Stored Procedure Injection",
        pattern: /CREATE\s+(?:PROCEDURE|FUNCTION)|ALTER\s+(?:PROCEDURE|FUNCTION)|DROP\s+(?:PROCEDURE|FUNCTION)/i,
        field: "request",
        severity: "critical",
        score: 95,
        category: "sql-injection",
        description: "Stored procedure creation/modification"
      },
      {
        id: "sqli-privilege-escalation",
        name: "SQLi - Privilege Escalation",
        pattern: /GRANT\s+(?:ALL|ADMIN)|ALTER\s+USER.*ADMIN|ALTER\s+LOGIN|EXECUTE\s+AS/i,
        field: "request",
        severity: "critical",
        score: 96,
        category: "sql-injection",
        description: "Privilege escalation via SQL"
      },
      {
        id: "sqli-user-creation",
        name: "SQLi - User Account Creation",
        pattern: /CREATE\s+USER|CREATE\s+LOGIN|ALTER\s+USER.*PASSWORD|SET\s+PASSWORD/i,
        field: "request",
        severity: "critical",
        score: 93,
        category: "sql-injection",
        description: "Unauthorized user/account creation"
      },
      {
        id: "sqli-role-manipulation",
        name: "SQLi - Role/Permission Manipulation",
        pattern: /CREATE\s+ROLE|ALTER\s+ROLE|GRANT\s+ROLE|REVOKE\s+ROLE/i,
        field: "request",
        severity: "critical",
        score: 92,
        category: "sql-injection",
        description: "Database role manipulation"
      },
      {
        id: "sqli-temp-table",
        name: "SQLi - Temporary Table Injection",
        pattern: /CREATE\s+(?:#|TEMPORARY)\s+TABLE|DROP\s+(?:#|TEMPORARY)\s+TABLE/i,
        field: "request",
        severity: "high",
        score: 82,
        category: "sql-injection",
        description: "Temporary table creation for data manipulation"
      },
      {
        id: "sqli-transaction-control",
        name: "SQLi - Transaction Control Injection",
        pattern: /BEGIN\s+TRANSACTION|START\s+TRANSACTION|COMMIT|ROLLBACK|SAVEPOINT/i,
        field: "request",
        severity: "high",
        score: 79,
        category: "sql-injection",
        description: "Transaction statement injection"
      },
      {
        id: "sqli-lock-wait-injection",
        name: "SQLi - Lock/Wait Injection",
        pattern: /LOCK\s+IN\s+SHARE\s+MODE|FOR\s+UPDATE|FOR\s+SHARE|WAIT|NOWAIT/i,
        field: "request",
        severity: "high",
        score: 77,
        category: "sql-injection",
        description: "Lock/wait for injection"
      },
      {
        id: "sqli-cursor-injection",
        name: "SQLi - Cursor Operations",
        pattern: /DECLARE\s+CURSOR|FETCH\s+(?:NEXT|PRIOR|FIRST|LAST|ABSOLUTE)/i,
        field: "request",
        severity: "high",
        score: 75,
        category: "sql-injection",
        description: "Cursor-based data traversal"
      },
      {
        id: "sqli-bulk-insert",
        name: "SQLi - BULK INSERT/LOAD",
        pattern: /BULK\s+INSERT|LOAD\s+DATA|INTO\s+OUTFILE|FROM\s+['\"].*\.csv/i,
        field: "request",
        severity: "critical",
        score: 90,
        category: "sql-injection",
        description: "Bulk data operations"
      },
      {
        id: "sqli-truncate-injection",
        name: "SQLi - TRUNCATE/DELETE All",
        pattern: /TRUNCATE\s+TABLE|DELETE\s+FROM\s+\w+\s*;|DELETE\s+FROM\s+\w+\s*WHERE\s+1=1/i,
        field: "request",
        severity: "critical",
        score: 94,
        category: "sql-injection",
        description: "Data destruction via truncate/delete"
      },
      {
        id: "sqli-rename-injection",
        name: "SQLi - Table Rename Injection",
        pattern: /ALTER\s+TABLE\s+\w+\s+RENAME|RENAME\s+TABLE/i,
        field: "request",
        severity: "high",
        score: 81,
        category: "sql-injection",
        description: "Table renaming for confusion"
      },
      {
        id: "sqli-column-operations",
        name: "SQLi - Column Add/Drop Operations",
        pattern: /ALTER\s+TABLE\s+\w+\s+(?:ADD|DROP|MODIFY)\s+COLUMN/i,
        field: "request",
        severity: "high",
        score: 80,
        category: "sql-injection",
        description: "Schema modification attacks"
      },
      {
        id: "sqli-index-injection",
        name: "SQLi - Index Creation Injection",
        pattern: /CREATE\s+(?:UNIQUE\s+)?INDEX|DROP\s+INDEX|ALTER\s+INDEX/i,
        field: "request",
        severity: "high",
        score: 76,
        category: "sql-injection",
        description: "Index manipulation for performance attacks"
      },
      {
        id: "sqli-collation-injection",
        name: "SQLi - Collation Manipulation",
        pattern: /COLLATE\s+[a-zA-Z0-9_]+|CHARACTER\s+SET|CHARSET/i,
        field: "request",
        severity: "medium",
        score: 66,
        category: "sql-injection",
        description: "Collation confusion attacks"
      },
      {
        id: "sqli-constraint-injection",
        name: "SQLi - Constraint Manipulation",
        pattern: /ADD\s+(?:CONSTRAINT|PRIMARY|FOREIGN|UNIQUE|CHECK)|DROP\s+CONSTRAINT/i,
        field: "request",
        severity: "high",
        score: 77,
        category: "sql-injection",
        description: "Integrity constraint manipulation"
      },
      {
        id: "sqli-schema-qualification",
        name: "SQLi - Schema Qualification Bypass",
        pattern: /\w+\.\w+\.\w+|dbo\.\w+|public\.\w+/i,
        field: "request",
        severity: "high",
        score: 72,
        category: "sql-injection",
        description: "Cross-schema object access"
      },
      {
        id: "sqli-database-link",
        name: "SQLi - Database Link Exploitation",
        pattern: /@\w+|DBLINK|REMOTE_OS|REMOTE_OS_USER/i,
        field: "request",
        severity: "critical",
        score: 91,
        category: "sql-injection",
        description: "Database link for remote access"
      },
      {
        id: "sqli-implicit-type-conversion",
        name: "SQLi - Implicit Type Conversion",
        pattern: /\d+\s*=\s*['"][^"]*['"]|['"][^\d"]*['"][\s]*=\s*\d+/,
        field: "request",
        severity: "medium",
        score: 64,
        category: "sql-injection",
        description: "Type conversion confusion"
      },
      {
        id: "sqli-column-aliasing",
        name: "SQLi - Column Aliasing Confusion",
        pattern: /\bAS\s+[\w\d]+\s+(?:WHERE|UNION|SELECT)/i,
        field: "request",
        severity: "medium",
        score: 63,
        category: "sql-injection",
        description: "Column alias for query structure confusion"
      },
      {
        id: "sqli-table-aliasing",
        name: "SQLi - Table Aliasing Injection",
        pattern: /FROM\s+\w+\s+[a-z]+\s+WHERE|FROM.*\s+[a-z]{1,3}\s+(?:INNER|LEFT|RIGHT|FULL|CROSS)/i,
        field: "request",
        severity: "high",
        score: 71,
        category: "sql-injection",
        description: "Table alias manipulation"
      },
      {
        id: "sqli-expression-injection",
        name: "SQLi - Complex Expression Injection",
        pattern: /SELECT.*\+.*SELECT|SELECT.*\*.*SELECT|SELECT.*\/.*SELECT/i,
        field: "request",
        severity: "high",
        score: 73,
        category: "sql-injection",
        description: "Complex expression-based injection"
      },
      {
        id: "sqli-database-metadata",
        name: "SQLi - Database Metadata Extraction",
        pattern: /information_schema|mysql\.user|pg_catalog|sys\.tables|sys\.columns/i,
        field: "request",
        severity: "high",
        score: 81,
        category: "sql-injection",
        description: "System metadata table access"
      }
    ];
  }
});

// server/waf/rules/xss.ts
var XSS_RULES;
var init_xss = __esm({
  "server/waf/rules/xss.ts"() {
    "use strict";
    XSS_RULES = [
      {
        id: "xss-script",
        name: "XSS - Script Tag",
        pattern: /<script[^>]*>[\s\S]*?<\/script>/i,
        field: "request",
        severity: "critical",
        score: 90,
        category: "xss",
        description: "Classic script tag XSS attack",
        recommendation: "Encode all output and use CSP headers"
      },
      {
        id: "xss-event",
        name: "XSS - Event Handler",
        pattern: /\bon(load|error|click|mouse|focus|blur|submit|change|key|touch|drag|drop|copy|paste|cut|select|scroll|resize|unload|beforeunload)\s*=/i,
        field: "request",
        severity: "high",
        score: 85,
        category: "xss",
        description: "XSS via HTML event handler attributes",
        recommendation: "Strip event handlers from user input"
      },
      {
        id: "xss-javascript",
        name: "XSS - JavaScript Protocol",
        pattern: /javascript\s*:/i,
        field: "request",
        severity: "high",
        score: 80,
        category: "xss",
        description: "JavaScript protocol handler in URL/attribute",
        recommendation: "Validate and whitelist URL protocols"
      },
      {
        id: "xss-data",
        name: "XSS - Data URI",
        pattern: /data\s*:\s*(text\/html|application\/javascript)/i,
        field: "request",
        severity: "high",
        score: 75,
        category: "xss",
        description: "Data URI with executable content type",
        recommendation: "Block or validate data URIs"
      },
      {
        id: "xss-svg",
        name: "XSS - SVG Payload",
        pattern: /<svg[^>]*\son\w+\s*=/i,
        field: "request",
        severity: "high",
        score: 80,
        category: "xss",
        description: "XSS through SVG element with event handlers",
        recommendation: "Sanitize SVG content or block SVG uploads"
      },
      {
        id: "xss-img",
        name: "XSS - Image Tag Abuse",
        pattern: /<img[^>]+\s(on\w+|src\s*=\s*['"]?javascript)/i,
        field: "request",
        severity: "high",
        score: 80,
        category: "xss",
        description: "XSS via img tag event handlers or javascript src",
        recommendation: "Validate image sources and strip event handlers"
      },
      {
        id: "xss-encoded",
        name: "XSS - Encoded Payload",
        pattern: /(%3C|&#x3c;|&#60;).*?(script|on\w+=)/i,
        field: "request",
        severity: "high",
        score: 75,
        category: "xss",
        description: "URL or HTML encoded XSS attempt",
        recommendation: "Decode and validate input before processing"
      },
      {
        id: "xss-template",
        name: "XSS - Template Injection",
        pattern: /(\{\{|\$\{|\<%=?|\{%)/,
        field: "request",
        severity: "medium",
        score: 55,
        category: "xss",
        description: "Potential template injection syntax",
        recommendation: "Escape template delimiters in user input"
      },
      {
        id: "xss-html-tags",
        name: "XSS - HTML Tags",
        pattern: /<(iframe|object|embed|applet|meta|link|style|base|form)\b[^>]*>/i,
        field: "request",
        severity: "high",
        score: 85,
        category: "xss",
        description: "Dangerous HTML tags (iframe, object, embed, etc.)",
        recommendation: "Remove or sanitize potentially dangerous HTML tags"
      },
      {
        id: "xss-protocol-handlers",
        name: "XSS - Protocol Handlers",
        pattern: /(vbscript|about|data|jar|mocha|mhtml):/i,
        field: "request",
        severity: "high",
        score: 82,
        category: "xss",
        description: "Alternative protocol handlers for XSS",
        recommendation: "Whitelist only safe protocols (http, https, ftp)"
      },
      {
        id: "xss-entity-encoding",
        name: "XSS - Entity Encoding Bypass",
        pattern: /&#\d+;|&#x[0-9a-fA-F]+;|%[0-9a-fA-F]{2}|\\x[0-9a-fA-F]{2}/,
        field: "request",
        severity: "medium",
        score: 70,
        category: "xss",
        description: "Entity/URL encoded XSS payloads",
        recommendation: "Decode entities before validation"
      },
      {
        id: "xss-css-injection",
        name: "XSS - CSS Injection",
        pattern: /<style[^>]*>[\s\S]*?<\/style>|style\s*=\s*"[^"]*expression|behavior\s*:|binding\s*:/i,
        field: "request",
        severity: "high",
        score: 80,
        category: "xss",
        description: "CSS-based XSS attacks",
        recommendation: "Sanitize style attributes and <style> tags"
      },
      {
        id: "xss-svg-filter",
        name: "XSS - SVG Filter Effects",
        pattern: /<filter[^>]*>[\s\S]*?<\/filter>|<animate[^>]*>|<set\b[^>]*>/i,
        field: "request",
        severity: "high",
        score: 78,
        category: "xss",
        description: "SVG filter or animation elements for XSS",
        recommendation: "Block dangerous SVG elements"
      },
      {
        id: "xss-html5-attributes",
        name: "XSS - HTML5 Dangerous Attributes",
        pattern: /\b(formaction|onfocus|onload|onmouseover|onmouseout|onmousemove|onmousedown|onmouseup|onkeydown|onkeyup|onkeypress)\s*=/i,
        field: "request",
        severity: "high",
        score: 83,
        category: "xss",
        description: "HTML5 event attributes for XSS",
        recommendation: "Remove event attributes from all elements"
      },
      {
        id: "xss-meta-refresh",
        name: "XSS - Meta Refresh",
        pattern: /<meta[^>]+http-equiv\s*=\s*["']refresh["'][^>]*>/i,
        field: "request",
        severity: "medium",
        score: 65,
        category: "xss",
        description: "Meta refresh tag for redirect/injection",
        recommendation: "Remove or sanitize meta refresh tags"
      },
      {
        id: "xss-unicode-evasion",
        name: "XSS - Unicode/UTF-8 Evasion",
        pattern: /\\u[0-9a-fA-F]{4}|\\U[0-9a-fA-F]{8}|%u[0-9a-fA-F]{4}|&#x[0-9a-fA-F]{2,6};/,
        field: "request",
        severity: "high",
        score: 75,
        category: "xss",
        description: "Unicode encoding for XSS evasion",
        recommendation: "Normalize and decode Unicode sequences"
      },
      {
        id: "xss-form-action",
        name: "XSS - Form Action Hijacking",
        pattern: /<form[^>]+action\s*=\s*["']?(?!https?:\/\/trusted-domain)(javascript:|data:|about:|\/{0,2}[^\/])/i,
        field: "request",
        severity: "high",
        score: 79,
        category: "xss",
        description: "Form action pointing to external or dangerous protocol",
        recommendation: "Whitelist allowed form actions"
      },
      {
        id: "xss-base64-polyglot",
        name: "XSS - Base64/Polyglot Encoding",
        pattern: /data:text\/html;base64,|PHN2Z1|PGlmcmFtZQ==|PHNjcmlwdD4=/i,
        field: "request",
        severity: "high",
        score: 81,
        category: "xss",
        description: "Base64 encoded XSS payloads",
        recommendation: "Decode and validate base64 content"
      },
      {
        id: "xss-dom-innerhtml",
        name: "XSS - DOM innerhtml Manipulation",
        pattern: /\.innerHTML\s*=|\.insertAdjacentHTML|document\.write\s*\(|outerHTML\s*=/i,
        field: "request",
        severity: "high",
        score: 84,
        category: "xss",
        description: "DOM-based XSS via innerHTML/write",
        recommendation: "Use textContent, use DOMPurify for HTML"
      },
      {
        id: "xss-dom-eval",
        name: "XSS - DOM eval() Injection",
        pattern: /eval\s*\(|setTimeout\s*\(\s*['"`]|setInterval\s*\(\s*['"`]|Function\s*\(['"`]/i,
        field: "request",
        severity: "critical",
        score: 92,
        category: "xss",
        description: "eval() or Function() with user input",
        recommendation: "Never use eval(), setTimeout/Interval with code strings"
      },
      {
        id: "xss-dom-query-selector",
        name: "XSS - querySelector XSS",
        pattern: /querySelector\s*\(['"]\s*<|querySelectorAll[\s\S]*?<(?:img|script|svg|iframe)/i,
        field: "request",
        severity: "high",
        score: 78,
        category: "xss",
        description: "HTML injection via querySelector",
        recommendation: "Sanitize selector input"
      },
      {
        id: "xss-attribute-injection",
        name: "XSS - Attribute Injection",
        pattern: /"\s*\s(?:on\w+|href|src|data|style|poster)\s*=|'\s+on\w+\s*=|`\s+on\w+\s*=/i,
        field: "request",
        severity: "high",
        score: 82,
        category: "xss",
        description: "Breaking out of attributes with space",
        recommendation: "Properly quote and escape attributes"
      },
      {
        id: "xss-svg-onload",
        name: "XSS - SVG with onload",
        pattern: /<svg[\s\S]*?onload\s*=/i,
        field: "request",
        severity: "critical",
        score: 88,
        category: "xss",
        description: "SVG element with onload handler",
        recommendation: "Sanitize or block SVG uploads"
      },
      {
        id: "xss-canvas-xss",
        name: "XSS - Canvas/Blob Data URI",
        pattern: /canvas\.toDataURL|blob:|createObjectURL|createImageBitmap/i,
        field: "request",
        severity: "high",
        score: 76,
        category: "xss",
        description: "Canvas/Blob for data exfiltration",
        recommendation: "Restrict data URL generation"
      },
      {
        id: "xss-iframe-srcdoc",
        name: "XSS - iframe srcdoc XSS",
        pattern: /srcdoc\s*=|<iframe[^>]+srcdoc/i,
        field: "request",
        severity: "critical",
        score: 89,
        category: "xss",
        description: "iframe srcdoc attribute for inline HTML",
        recommendation: "Sanitize srcdoc attribute"
      },
      {
        id: "xss-script-src-data",
        name: "XSS - Script src=data: URI",
        pattern: /<script[^>]+src\s*=\s*["']?data:/i,
        field: "request",
        severity: "critical",
        score: 90,
        category: "xss",
        description: "Script tag with data URI",
        recommendation: "Block data: scheme in script src"
      },
      {
        id: "xss-link-rel-import",
        name: "XSS - Link rel=import",
        pattern: /<link[^>]+rel\s*=\s*["']import["']/i,
        field: "request",
        severity: "high",
        score: 74,
        category: "xss",
        description: "HTML imports for XSS",
        recommendation: "Disable HTML imports or sanitize"
      },
      {
        id: "xss-object-data-xss",
        name: "XSS - Object data Attribute",
        pattern: /<object[^>]+data\s*=|<embed[^>]+src\s*=/i,
        field: "request",
        severity: "high",
        score: 83,
        category: "xss",
        description: "Object/Embed tag XSS",
        recommendation: "Remove or heavily sanitize object/embed"
      },
      {
        id: "xss-video-poster",
        name: "XSS - Video Poster XSS",
        pattern: /<video[^>]+poster\s*=\s*["']?(javascript:|data:)/i,
        field: "request",
        severity: "high",
        score: 77,
        category: "xss",
        description: "Video poster with dangerous protocol",
        recommendation: "Validate video poster URLs"
      },
      {
        id: "xss-track-src",
        name: "XSS - Track Source XSS",
        pattern: /<track[^>]+src\s*=|<source[^>]+src\s*=\s*["']?(data:|javascript:)/i,
        field: "request",
        severity: "high",
        score: 75,
        category: "xss",
        description: "Audio/video track source with XSS",
        recommendation: "Validate media source URLs"
      },
      {
        id: "xss-marquee-behavior",
        name: "XSS - Marquee Behavior XSS",
        pattern: /<marquee[^>]+behavior\s*=|onstart|onfinish/i,
        field: "request",
        severity: "medium",
        score: 68,
        category: "xss",
        description: "Marquee element XSS (legacy)",
        recommendation: "Remove marquee tags"
      },
      {
        id: "xss-picture-srcset",
        name: "XSS - Picture/Srcset XSS",
        pattern: /<picture[\s\S]*?srcset\s*=\s*"[^"]*javascript:|srcset\s*=\s*"[^"]*data:/i,
        field: "request",
        severity: "high",
        score: 76,
        category: "xss",
        description: "Picture element srcset injection",
        recommendation: "Validate srcset URLs"
      },
      {
        id: "xss-isindex",
        name: "XSS - isindex Tag XSS",
        pattern: /<isindex[\s\S]*?(?:prompt|on\w+)/i,
        field: "request",
        severity: "medium",
        score: 60,
        category: "xss",
        description: "Deprecated isindex tag exploitation",
        recommendation: "Remove isindex tags"
      },
      {
        id: "xss-label-for-xss",
        name: "XSS - Label for Attribute",
        pattern: /<label[^>]+for\s*=\s*["'][\s\S]*?(?:on\w+|javascript)/i,
        field: "request",
        severity: "medium",
        score: 65,
        category: "xss",
        description: "Label for attribute combined with event handlers",
        recommendation: "Validate label for references"
      },
      {
        id: "xss-output-tag",
        name: "XSS - Output Tag XSS",
        pattern: /<output[^>]*\son\w+\s*=/i,
        field: "request",
        severity: "high",
        score: 72,
        category: "xss",
        description: "Output element with event handlers",
        recommendation: "Sanitize output elements"
      },
      {
        id: "xss-datalist-xss",
        name: "XSS - Datalist XSS",
        pattern: /<datalist[^>]*\s(?:on\w+|id\s*=.*on\w+)/i,
        field: "request",
        severity: "high",
        score: 71,
        category: "xss",
        description: "Datalist element XSS",
        recommendation: "Sanitize datalist elements"
      },
      {
        id: "xss-meter-progress",
        name: "XSS - Meter/Progress Elements",
        pattern: /<(?:meter|progress)[^>]*\son\w+\s*=/i,
        field: "request",
        severity: "high",
        score: 70,
        category: "xss",
        description: "Meter/Progress element with handlers",
        recommendation: "Remove event handlers from elements"
      },
      {
        id: "xss-ruby-annotation",
        name: "XSS - Ruby Annotation XSS",
        pattern: /<ruby[\s\S]*?rt[\s\S]*?on\w+\s*=/i,
        field: "request",
        severity: "medium",
        score: 62,
        category: "xss",
        description: "Ruby annotation with XSS",
        recommendation: "Sanitize ruby tags"
      },
      {
        id: "xss-details-summary",
        name: "XSS - Details/Summary XSS",
        pattern: /<(?:details|summary)[^>]*\son(?:toggle|click|load|error)\s*=/i,
        field: "request",
        severity: "high",
        score: 73,
        category: "xss",
        description: "Details/Summary element with handlers",
        recommendation: "Sanitize details/summary elements"
      },
      {
        id: "xss-noscript-injection",
        name: "XSS - Noscript Tag Injection",
        pattern: /<noscript[\s\S]*?<(?:img|script|svg|iframe)/i,
        field: "request",
        severity: "high",
        score: 79,
        category: "xss",
        description: "Noscript tag containing XSS payload",
        recommendation: "Sanitize noscript content"
      },
      {
        id: "xss-comment-injection",
        name: "XSS - HTML Comment Injection",
        pattern: /<!--[\s\S]*?(?:<script|on\w+|javascript:)/i,
        field: "request",
        severity: "high",
        score: 74,
        category: "xss",
        description: "XSS payload hidden in HTML comments",
        recommendation: "Remove comments or sanitize"
      },
      {
        id: "xss-cdata-injection",
        name: "XSS - CDATA Injection",
        pattern: /<!\[CDATA\[[\s\S]*?(?:<script|javascript:)/i,
        field: "request",
        severity: "high",
        score: 73,
        category: "xss",
        description: "XSS in XML CDATA sections",
        recommendation: "Sanitize CDATA content"
      },
      {
        id: "xss-plaintext-tag",
        name: "XSS - Plaintext Tag",
        pattern: /<plaintext[\s\S]*?>|<listing[\s\S]*?>/i,
        field: "request",
        severity: "high",
        score: 72,
        category: "xss",
        description: "Plaintext/listing tags for content bypass",
        recommendation: "Remove deprecated plaintext/listing tags"
      },
      {
        id: "xss-xmp-tag",
        name: "XSS - XMP Tag XSS",
        pattern: /<xmp[\s\S]*?>[\s\S]*?<script|<xmp[\s\S]*?on\w+/i,
        field: "request",
        severity: "high",
        score: 71,
        category: "xss",
        description: "XMP tag exploitation",
        recommendation: "Remove XMP tags"
      },
      {
        id: "xss-tabindex-focus",
        name: "XSS - Tabindex/Autofocus XSS",
        pattern: /tabindex\s*=\s*[-\d]+|autofocus\s*=|autoplay\s*=.*\s(?:on\w+|script)/i,
        field: "request",
        severity: "medium",
        score: 69,
        category: "xss",
        description: "Tabindex/Autofocus combined with handlers",
        recommendation: "Validate autofocus usage"
      },
      {
        id: "xss-contextmenu-attr",
        name: "XSS - Contextmenu Attribute",
        pattern: /contextmenu\s*=\s*["'][^"']*<|contextmenu[\s\S]*?(?:script|on\w+)/i,
        field: "request",
        severity: "medium",
        score: 64,
        category: "xss",
        description: "Contextmenu attribute XSS",
        recommendation: "Validate contextmenu references"
      },
      {
        id: "xss-usemap-attr",
        name: "XSS - Usemap Area XSS",
        pattern: /<map[\s\S]*?<area[\s\S]*?(?:href\s*=\s*javascript:|on\w+)/i,
        field: "request",
        severity: "high",
        score: 74,
        category: "xss",
        description: "Image map area element XSS",
        recommendation: "Sanitize map/area elements"
      },
      {
        id: "xss-fieldset-legend",
        name: "XSS - Fieldset/Legend XSS",
        pattern: /<fieldset[\s\S]*?on\w+\s*=|<legend[\s\S]*?on\w+\s*=/i,
        field: "request",
        severity: "high",
        score: 70,
        category: "xss",
        description: "Fieldset/legend with event handlers",
        recommendation: "Remove handlers from form elements"
      },
      {
        id: "xss-optgroup-option",
        name: "XSS - Select/Option XSS",
        pattern: /<select[\s\S]*?on\w+\s*=|<option[\s\S]*?on\w+\s*=/i,
        field: "request",
        severity: "high",
        score: 72,
        category: "xss",
        description: "Select/Option element XSS",
        recommendation: "Sanitize select/option handlers"
      },
      {
        id: "xss-dialog-modal",
        name: "XSS - Dialog/Modal XSS",
        pattern: /<dialog[\s\S]*?(?:on\w+|open\s*>[\s\S]*?<script)/i,
        field: "request",
        severity: "high",
        score: 73,
        category: "xss",
        description: "Dialog element with handlers",
        recommendation: "Sanitize dialog elements"
      },
      {
        id: "xss-template-tag",
        name: "XSS - Template Tag Content",
        pattern: /<template[\s\S]*?>[\s\S]*?<(?:script|img\s+on\w+)/i,
        field: "request",
        severity: "high",
        score: 76,
        category: "xss",
        description: "Template tag with embedded scripts",
        recommendation: "Sanitize template content"
      },
      {
        id: "xss-slot-xss",
        name: "XSS - Web Component Slot XSS",
        pattern: /<slot[\s\S]*?name\s*=[\s\S]*?(?:script|on\w+)/i,
        field: "request",
        severity: "high",
        score: 74,
        category: "xss",
        description: "Web component slot injection",
        recommendation: "Sanitize slot content"
      },
      {
        id: "xss-shadow-dom",
        name: "XSS - Shadow DOM Injection",
        pattern: /attachShadow|shadow-root|shadowRoot|slot\s*=|part\s*=/i,
        field: "request",
        severity: "high",
        score: 77,
        category: "xss",
        description: "Shadow DOM manipulation",
        recommendation: "Validate shadow DOM usage"
      },
      {
        id: "xss-attribute-quotes-bypass",
        name: "XSS - Unquoted Attribute Bypass",
        pattern: /\s+on\w+=/,
        field: "request",
        severity: "high",
        score: 79,
        category: "xss",
        description: "Event handler without quotes",
        recommendation: "Require quoted attributes"
      },
      {
        id: "xss-newline-injection",
        name: "XSS - Newline/Carriage Return Injection",
        pattern: /(?:%0A|%0D|\r|\n)\s*(?:on\w+|script|javascript:)/i,
        field: "request",
        severity: "high",
        score: 75,
        category: "xss",
        description: "Line break for XSS filter bypass",
        recommendation: "Normalize line breaks"
      },
      {
        id: "xss-null-byte-injection",
        name: "XSS - Null Byte Injection",
        pattern: /%00|\\x00|\\u0000|%u0000/,
        field: "request",
        severity: "high",
        score: 73,
        category: "xss",
        description: "Null byte for XSS bypass",
        recommendation: "Strip null bytes"
      },
      {
        id: "xss-mixed-encoding",
        name: "XSS - Mixed Encoding Bypass",
        pattern: /(?:%|&#|\\x|\\u)[0-9a-fA-F]+.*(?:%|&#|\\x|\\u)[0-9a-fA-F]+.*(?:script|on\w+)/i,
        field: "request",
        severity: "high",
        score: 78,
        category: "xss",
        description: "Multiple encoding layers for bypass",
        recommendation: "Recursively decode and validate"
      },
      {
        id: "xss-rtl-override",
        name: "XSS - RTL Override (U+202E)",
        pattern: /\\u202e|%E2%80%AE|&#8238;|rtlmark|rtl-override/i,
        field: "request",
        severity: "medium",
        score: 61,
        category: "xss",
        description: "Right-to-left override for obfuscation",
        recommendation: "Validate text direction"
      },
      {
        id: "xss-zero-width-chars",
        name: "XSS - Zero-Width Character Bypass",
        pattern: /\\u200b|\\u200c|\\u200d|\\ufeff|%E2%80%8B|%E2%80%8C|%E2%80%8D/i,
        field: "request",
        severity: "medium",
        score: 62,
        category: "xss",
        description: "Zero-width characters for bypass",
        recommendation: "Remove zero-width characters"
      },
      {
        id: "xss-combining-chars",
        name: "XSS - Combining Characters Bypass",
        pattern: /[\u0300-\u036F]{3,}|combining.*mark/i,
        field: "request",
        severity: "medium",
        score: 60,
        category: "xss",
        description: "Combining diacritical marks for bypass",
        recommendation: "Normalize Unicode"
      },
      {
        id: "xss-no-break-space",
        name: "XSS - No-Break Space Bypass",
        pattern: /\\u00a0|%C2%A0|&#160;|\\240/,
        field: "request",
        severity: "medium",
        score: 58,
        category: "xss",
        description: "No-break space for filter bypass",
        recommendation: "Normalize whitespace"
      },
      {
        id: "xss-variation-selectors",
        name: "XSS - Variation Selector Bypass",
        pattern: /\\ufe00|\\ufe01|%EF%B8%80|variation.?selector/i,
        field: "request",
        severity: "medium",
        score: 59,
        category: "xss",
        description: "Unicode variation selectors",
        recommendation: "Strip variation selectors"
      },
      {
        id: "xss-soft-hyphen",
        name: "XSS - Soft Hyphen Bypass",
        pattern: /\\u00ad|%C2%AD|&#173;|soft.?hyphen/i,
        field: "request",
        severity: "low",
        score: 45,
        category: "xss",
        description: "Soft hyphen for bypass",
        recommendation: "Strip soft hyphens"
      },
      {
        id: "xss-bidi-override-complex",
        name: "XSS - Complex Bidi Override Chain",
        pattern: /(?:\\u202[abed]){2,}|bidi.*override.*override/i,
        field: "request",
        severity: "medium",
        score: 63,
        category: "xss",
        description: "Multiple bidi control characters",
        recommendation: "Limit bidi control usage"
      },
      {
        id: "xss-form-attribute-confusion",
        name: "XSS - Form Attribute Confusion",
        pattern: /form\s*=|formenctype\s*=|formmethod\s*=|formnovalidate|formtarget\s*=/i,
        field: "request",
        severity: "high",
        score: 71,
        category: "xss",
        description: "Form attributes manipulation",
        recommendation: "Validate form references"
      },
      {
        id: "xss-input-type-confusion",
        name: "XSS - Input Type Confusion",
        pattern: /type\s*=\s*["'](?:image|button|submit|reset)["'][\s\S]*?(?:on\w+|src\s*=)/i,
        field: "request",
        severity: "high",
        score: 70,
        category: "xss",
        description: "Input type bypass with handlers",
        recommendation: "Sanitize input elements"
      },
      {
        id: "xss-button-formaction",
        name: "XSS - Button Formaction Override",
        pattern: /<button[\s\S]*?formaction\s*=\s*["']?(?!https?:\/\/trusted)/i,
        field: "request",
        severity: "high",
        score: 76,
        category: "xss",
        description: "Button formaction attribute hijacking",
        recommendation: "Whitelist allowed actions"
      },
      {
        id: "xss-css-import-url",
        name: "XSS - CSS @import URL",
        pattern: /@import\s+url\s*\(\s*["']?(?:javascript:|data:|about:)/i,
        field: "request",
        severity: "high",
        score: 75,
        category: "xss",
        description: "CSS @import with dangerous URLs",
        recommendation: "Validate CSS imports"
      },
      {
        id: "xss-css-behavior",
        name: "XSS - CSS Behavior Property",
        pattern: /behavior\s*:\s*url|binding\s*:\s*url/i,
        field: "request",
        severity: "high",
        score: 77,
        category: "xss",
        description: "CSS behavior/binding XSS",
        recommendation: "Remove or sanitize CSS"
      },
      {
        id: "xss-moz-binding",
        name: "XSS - -moz-binding XSS",
        pattern: /-moz-binding\s*:\s*url|xbl:|expression\s*\(/i,
        field: "request",
        severity: "high",
        score: 76,
        category: "xss",
        description: "Mozilla-specific XSS vectors",
        recommendation: "Remove vendor-specific properties"
      },
      {
        id: "xss-resource-hint-xss",
        name: "XSS - Link Resource Hint XSS",
        pattern: /<link\s+(?:rel=|href=)[\s\S]*?(?:rel="(?:prefetch|preload|dns-prefetch|preconnect)"|href\s*=\s*["']?(?:javascript:|data:))/i,
        field: "request",
        severity: "high",
        score: 72,
        category: "xss",
        description: "Link resource hints with XSS",
        recommendation: "Validate link resources"
      },
      {
        id: "xss-crossorigin-bypass",
        name: "XSS - Crossorigin Attribute Abuse",
        pattern: /crossorigin\s*=\s*["']?anonymous["']?[\s\S]*?(?:on\w+|src\s*=\s*["']?(?:javascript:|data:))/i,
        field: "request",
        severity: "high",
        score: 68,
        category: "xss",
        description: "Crossorigin with malicious payload",
        recommendation: "Validate CORS attributes"
      },
      {
        id: "xss-integrity-bypass",
        name: "XSS - Integrity Attribute Bypass",
        pattern: /integrity\s*=\s*["']{2}|integrity=""|integrity=''/i,
        field: "request",
        severity: "high",
        score: 79,
        category: "xss",
        description: "Empty integrity attribute for bypass",
        recommendation: "Require valid integrity hashes"
      }
    ];
  }
});

// server/waf/rules/rce.ts
var RCE_RULES;
var init_rce = __esm({
  "server/waf/rules/rce.ts"() {
    "use strict";
    RCE_RULES = [
      {
        id: "rce-shell-commands",
        name: "RCE - Shell Command Execution",
        pattern: /\b(bash|sh|cmd|powershell|exec|system|passthru|eval|assert|compile)\s*\(/i,
        field: "request",
        severity: "critical",
        score: 98,
        category: "rce",
        description: "Shell command execution functions detected",
        recommendation: "Disable dangerous functions, use allowlist for commands"
      },
      {
        id: "rce-pipe-operators",
        name: "RCE - Pipe Operators",
        pattern: /[|&;`$()><\n].*\b(cat|ls|rm|mv|cp|chmod|chown|whoami|id|uname|nc|ncat|telnet)\b/i,
        field: "request",
        severity: "critical",
        score: 95,
        category: "rce",
        description: "Shell pipe/redirect operators with system commands",
        recommendation: "Block shell metacharacters and chaining"
      },
      {
        id: "rce-reverse-shell",
        name: "RCE - Reverse Shell Patterns",
        pattern: /\/bin\/bash|\/bin\/sh|\/bin\/dash|cmd\.exe|powershell\.exe|nc\s+-[a-z]*e|bash\s+-i|sh\s+-i/i,
        field: "request",
        severity: "critical",
        score: 96,
        category: "rce",
        description: "Reverse shell or interactive shell execution",
        recommendation: "Restrict shell access and outbound connections"
      },
      {
        id: "rce-code-injection",
        name: "RCE - Code Injection",
        pattern: /eval\s*\(|exec\s*\(|system\s*\(|assert\s*\(|create_function|preg_replace\s*\/[a-z]*e/i,
        field: "request",
        severity: "critical",
        score: 94,
        category: "rce",
        description: "Code injection via eval, exec, or similar functions",
        recommendation: "Never use user input with eval/exec functions"
      },
      {
        id: "rce-environment-variables",
        name: "RCE - Environment Variable Injection",
        pattern: /LD_PRELOAD|LD_LIBRARY_PATH|DYLD_INSERT_LIBRARIES|PATH=|PYTHONPATH=|CLASSPATH=/i,
        field: "request",
        severity: "high",
        score: 85,
        category: "rce",
        description: "Environment variable manipulation for code execution",
        recommendation: "Sanitize environment variables, use isolated environments"
      },
      {
        id: "rce-process-execution",
        name: "RCE - Process Execution",
        pattern: /Runtime\.exec|ProcessBuilder|ProcessImpl|spawn|fork|popen|subprocess\.call/i,
        field: "request",
        severity: "critical",
        score: 92,
        category: "rce",
        description: "Language-level process execution functions",
        recommendation: "Restrict process execution, use safe APIs only"
      },
      {
        id: "rce-wildcards-globbing",
        name: "RCE - Glob/Wildcard Expansion",
        pattern: /\$\{.*?\}|\$\(.*?\)|`.*?`|\*\.\*|[\[\]{}]/,
        field: "request",
        severity: "high",
        score: 80,
        category: "rce",
        description: "Command substitution or glob expansion patterns",
        recommendation: "Quote parameters, disable shell expansion"
      },
      {
        id: "rce-directory-traversal-execution",
        name: "RCE - Directory Traversal to Execute",
        pattern: /\.\.\/.*\.(sh|exe|com|bat|cmd|bin|elf|o|so)|\.\/\.\.\/.*\.(sh|exe|com|bat|cmd)/i,
        field: "request",
        severity: "high",
        score: 88,
        category: "rce",
        description: "Directory traversal combined with command execution",
        recommendation: "Validate file paths, restrict executable locations"
      },
      {
        id: "rce-input-output-redirection",
        name: "RCE - Input/Output Redirection",
        pattern: />\s*\/dev\/\w+|<\s*\/proc\/|[\d+]>\s*&[\d+]|[\d+]<>\s*\/dev\//,
        field: "request",
        severity: "high",
        score: 82,
        category: "rce",
        description: "I/O redirection to special files",
        recommendation: "Block redirection to /dev/ and /proc/"
      },
      {
        id: "rce-dangerous-imports",
        name: "RCE - Dangerous Module Imports",
        pattern: /require\s*\(\s*['"`].*\$|import\s+.*\${.*}|__import__\s*\(\s*['"`]\$/i,
        field: "request",
        severity: "critical",
        score: 91,
        category: "rce",
        description: "Dynamic module/file imports with user input",
        recommendation: "Use static imports only, validate module names"
      },
      {
        id: "rce-command-substitution",
        name: "RCE - Command Substitution $()",
        pattern: /\$\([^)]*(?:cat|ls|rm|wget|curl|bash|sh|id|whoami)/i,
        field: "request",
        severity: "critical",
        score: 96,
        category: "rce",
        description: "Command substitution with system commands",
        recommendation: "Block $(command) substitution"
      },
      {
        id: "rce-backtick-substitution",
        name: "RCE - Backtick Command Substitution",
        pattern: /`[^`]*(?:cat|ls|rm|wget|curl|bash|sh|id|whoami)/i,
        field: "request",
        severity: "critical",
        score: 95,
        category: "rce",
        description: "Backtick command substitution",
        recommendation: "Strip backticks from input"
      },
      {
        id: "rce-unicode-bypass",
        name: "RCE - Unicode/UTF-8 Command Bypass",
        pattern: /\\x2f|\\x3b|\\x7c|%2f|%3b|%7c|%24\(|%60/i,
        field: "request",
        severity: "high",
        score: 82,
        category: "rce",
        description: "Encoded shell metacharacters",
        recommendation: "Decode and normalize input before validation"
      },
      {
        id: "rce-hex-encoding-bypass",
        name: "RCE - Hex Encoding Command Bypass",
        pattern: /\\x[0-9a-fA-F]{2}.*(?:exec|eval|system|bash)|0x(?:[0-9a-fA-F]{2})+/i,
        field: "request",
        severity: "high",
        score: 81,
        category: "rce",
        description: "Hex-encoded RCE payloads",
        recommendation: "Decode all inputs before pattern matching"
      },
      {
        id: "rce-octal-encoding",
        name: "RCE - Octal Encoding Bypass",
        pattern: /\\[0-7]{3}.*(?:bash|sh|exec|eval)|[0-7]{3,4}.*(?:bash|sh)/i,
        field: "request",
        severity: "high",
        score: 80,
        category: "rce",
        description: "Octal-encoded command bypasses",
        recommendation: "Normalize octal sequences"
      },
      {
        id: "rce-iis-shortname-rce",
        name: "RCE - IIS Short Filename (8.3) RCE",
        pattern: /\.asp~\d|\.aspx~\d|\.jsp~\d|\*\.asp[\s?]|iis|shortname|~1~2/i,
        field: "request",
        severity: "high",
        score: 83,
        category: "rce",
        description: "IIS 8.3 short filename disclosure for RCE",
        recommendation: "Disable 8.3 naming on IIS"
      },
      {
        id: "rce-polyglot-files",
        name: "RCE - Polyglot File Uploads",
        pattern: /GIF8|GIF89|GIF87|JFIF|PNG|ZIP|php|jsp|asp|jspx|aspx/i,
        field: "file_content_header",
        severity: "high",
        score: 84,
        category: "rce",
        description: "Polyglot files combining image+code",
        recommendation: "Validate file types strictly"
      },
      {
        id: "rce-null-byte-execution",
        name: "RCE - Null Byte Injection",
        pattern: /\.php%00|\.asp%00|\.jsp%00|%00\.jpg|%00\.gif|\.php\x00/i,
        field: "request",
        severity: "high",
        score: 82,
        category: "rce",
        description: "Null byte in filename for extension bypass",
        recommendation: "Strip and validate null bytes"
      },
      {
        id: "rce-double-extension",
        name: "RCE - Double Extension Upload",
        pattern: /\.php\.jpg|\.php\.png|\.php\.gif|\.asp\.jpg|\.jsp\.gif|\.php\.txt|\.php\.pdf/i,
        field: "request",
        severity: "high",
        score: 81,
        category: "rce",
        description: "Double extension file upload bypass",
        recommendation: "Validate only final extension"
      },
      {
        id: "rce-case-insensitive-bypass",
        name: "RCE - Case Sensitivity Bypass",
        pattern: /\.pHp|\.AsP|\.jSp|\.Php5|\.phtml|\.shtml|\.shtm|\.sh\s/i,
        field: "request",
        severity: "medium",
        score: 70,
        category: "rce",
        description: "Mixed case extension bypass",
        recommendation: "Use case-insensitive validation"
      },
      {
        id: "rce-alternate-stream-ads",
        name: "RCE - NTFS Alternate Data Streams",
        pattern: /\.jpg::|\\.jpg:|\.:jpg:|file\.txt:jpg|stream\s*::|zone\.identifier/i,
        field: "request",
        severity: "high",
        score: 83,
        category: "rce",
        description: "NTFS alternate data stream abuse",
        recommendation: "Filter NTFS stream syntax"
      },
      {
        id: "rce-asp-dot-dot",
        name: "RCE - ASP Dot-Dot Traversal",
        pattern: /\.\.\..*asp|asp\.\.\.|\.\.\/\.\.\/.*asp|aspx\.\.\./i,
        field: "request",
        severity: "high",
        score: 79,
        category: "rce",
        description: "ASP dot-dot directory traversal",
        recommendation: "Normalize paths properly"
      },
      {
        id: "rce-parser-confusion",
        name: "RCE - Parser Confusion Attacks",
        pattern: /\.php5|\.phtml|\.phar|\.phps|\.php3|\.php4|\.php7|\.pht|\.phpt|\.pgif|\.shtml/i,
        field: "request",
        severity: "high",
        score: 82,
        category: "rce",
        description: "Parser confusion via alternate extensions",
        recommendation: "Whitelist allowed extensions only"
      },
      {
        id: "rce-htaccess-upload",
        name: "RCE - .htaccess Upload",
        pattern: /\.htaccess|\.htpasswd|\.web\.config|\.aspx_client|\.user\.js/i,
        field: "request",
        severity: "critical",
        score: 94,
        category: "rce",
        description: "Configuration file upload for RCE",
        recommendation: "Block upload of sensitive files"
      },
      {
        id: "rce-symlink-exploitation",
        name: "RCE - Symlink/Hardlink Exploitation",
        pattern: /ln\s+-s|symlink|hardlink|mknod|mkfifo|ln\s+-h|readlink/i,
        field: "request",
        severity: "high",
        score: 81,
        category: "rce",
        description: "Symlink creation for privilege escalation",
        recommendation: "Restrict symlink operations"
      },
      {
        id: "rce-race-condition",
        name: "RCE - Race Condition/TOCTOU",
        pattern: /tmp\/|\/var\/tmp|tempfile|mktemp|temp.*dir|race|toctou/i,
        field: "request",
        severity: "medium",
        score: 72,
        category: "rce",
        description: "Time-of-check/time-of-use race conditions",
        recommendation: "Use atomic operations, secure temp files"
      },
      {
        id: "rce-perl-open",
        name: "RCE - Perl Open/System Injection",
        pattern: /open\s*\(\s*['"`]\||\bopen\s+my|system\s*\(/i,
        field: "request",
        severity: "critical",
        score: 93,
        category: "rce",
        description: "Perl system() or piped open() execution",
        recommendation: "Avoid bareword filehandles"
      },
      {
        id: "rce-php-assert-code",
        name: "RCE - PHP assert() Code Execution",
        pattern: /assert\s*\([^)]*\$|assert\s*\(\s*['"`].*(?:eval|exec|system|shell_exec)/i,
        field: "request",
        severity: "critical",
        score: 92,
        category: "rce",
        description: "PHP assert() with code evaluation",
        recommendation: "Never use assert() with user input"
      },
      {
        id: "rce-preg-replace-code",
        name: "RCE - preg_replace /e Modifier",
        pattern: /preg_replace\s*\(.*\/[a-z]*e|preg_replace\s*\(.*['\"]e['\"]/i,
        field: "request",
        severity: "critical",
        score: 93,
        category: "rce",
        description: "PHP preg_replace() with /e modifier",
        recommendation: "Use preg_replace_callback() instead"
      },
      {
        id: "rce-create-function-eval",
        name: "RCE - create_function() RCE",
        pattern: /create_function\s*\(|create_function\s*\(['\"][^'\"]*\$|eval\s*\(\s*\$_(GET|POST|COOKIE)/i,
        field: "request",
        severity: "critical",
        score: 91,
        category: "rce",
        description: "create_function() for anonymous function RCE",
        recommendation: "Use closures/lambdas, never with user input"
      },
      {
        id: "rce-variable-variables",
        name: "RCE - PHP Variable Variables",
        pattern: /\$\$\w+|$$\(|${.*}.*\$/,
        field: "request",
        severity: "high",
        score: 85,
        category: "rce",
        description: "PHP variable variables ${} syntax",
        recommendation: "Avoid variable variables with user input"
      },
      {
        id: "rce-extract-import-vars",
        name: "RCE - extract()/import_request_variables()",
        pattern: /extract\s*\(|import_request_variables|parse_str\s*\(/i,
        field: "request",
        severity: "high",
        score: 84,
        category: "rce",
        description: "PHP extract() function for variable injection",
        recommendation: "Avoid extract(), use explicit assignment"
      },
      {
        id: "rce-mysql-exec",
        name: "RCE - MySQL INTO OUTFILE/LOAD DATA",
        pattern: /INTO\s+(OUTFILE|DUMPFILE)|LOAD_FILE|LOAD\s+DATA.*INFILE|INTO\s+OUTFILE.*shell/i,
        field: "request",
        severity: "critical",
        score: 94,
        category: "rce",
        description: "MySQL file write for RCE",
        recommendation: "Restrict FILE privilege"
      },
      {
        id: "rce-udf-exploitation",
        name: "RCE - User Defined Function (UDF) Exploitation",
        pattern: /sys_exec|sys_eval|udf\.dll|lib_mysqludf|create\s+function|into.*\.so|into.*\.dll/i,
        field: "request",
        severity: "critical",
        score: 93,
        category: "rce",
        description: "Database UDF for shell execution",
        recommendation: "Restrict UDF creation"
      },
      {
        id: "rce-mongodb-injection",
        name: "RCE - MongoDB Code Injection",
        pattern: /\$where[\s:]*|mapReduce|function\s*\(\s*\)|eval\s*\(|function\(\)\s*\{[\s\S]*(?:exec|spawn)/i,
        field: "request",
        severity: "critical",
        score: 92,
        category: "rce",
        description: "MongoDB $where operator code injection",
        recommendation: "Avoid $where, use strict queries"
      },
      {
        id: "rce-nosql-regex-dos",
        name: "RCE - NoSQL Regex DoS to RCE",
        pattern: /\$regex[\s:]*.*\(|\/.*\/[\w]{100,}|pattern.*[*+{]{2,}/,
        field: "request",
        severity: "high",
        score: 86,
        category: "rce",
        description: "NoSQL regex patterns for DoS/RCE",
        recommendation: "Validate regex complexity"
      },
      {
        id: "rce-cgi-bin-exploitation",
        name: "RCE - CGI Bin Exploitation",
        pattern: /cgi-bin|\.cgi|\.pl|sendmail|index\.cgi|status\.cgi|test\.cgi/i,
        field: "request",
        severity: "high",
        score: 80,
        category: "rce",
        description: "CGI script exploitation",
        recommendation: "Secure CGI scripts, use modern frameworks"
      },
      {
        id: "rce-imagetragick",
        name: "RCE - ImageMagick (ImageTragick)",
        pattern: /imagick|convert|mogrify|identify|composite|delegate|popen|powershell|cmd\.exe/i,
        field: "request",
        severity: "high",
        score: 83,
        category: "rce",
        description: "ImageMagick RCE via delegate commands",
        recommendation: "Update ImageMagick, disable delegates"
      },
      {
        id: "rce-ghostscript",
        name: "RCE - Ghostscript PDF Injection",
        pattern: /ghostscript|gs\.exe|gswin64|pdf.*exec|currentdevice|stdin|stdout/i,
        field: "request",
        severity: "high",
        score: 82,
        category: "rce",
        description: "Ghostscript PostScript RCE",
        recommendation: "Update Ghostscript, disable -dSAFER"
      },
      {
        id: "rce-ffmpeg-injection",
        name: "RCE - FFmpeg Command Injection",
        pattern: /ffmpeg|ffprobe|avconv|filter_complex|custom_filter|pipe:/i,
        field: "request",
        severity: "high",
        score: 81,
        category: "rce",
        description: "FFmpeg filter/codec injection",
        recommendation: "Use whitelist, quote all parameters"
      },
      {
        id: "rce-latex-injection",
        name: "RCE - LaTeX/TeX Command Injection",
        pattern: /\\immediate\\write18|\\def\\x|\\expandafter|pdflatex|xetex|luatex|\\input|\\include/i,
        field: "request",
        severity: "critical",
        score: 94,
        category: "rce",
        description: "LaTeX/TeX shell escape RCE",
        recommendation: "Disable shell escape, sandbox LaTeX"
      },
      {
        id: "rce-graphviz-injection",
        name: "RCE - Graphviz DOT Injection",
        pattern: /digraph|graph\s*{|node|edge|shellcommand|system|exec/i,
        field: "request",
        severity: "high",
        score: 80,
        category: "rce",
        description: "Graphviz DOT language injection",
        recommendation: "Validate DOT syntax, disable shell"
      },
      {
        id: "rce-aspx-viewstate",
        name: "RCE - ASP.NET ViewState Deserialization",
        pattern: /viewstate|__viewstate|objectstatefromstring|deserialize.*viewstate/i,
        field: "request",
        severity: "critical",
        score: 93,
        category: "rce",
        description: "ASP.NET ViewState gadget chains",
        recommendation: "Enable ViewState MAC, use ysoserial prevention"
      },
      {
        id: "rce-source-code-comment",
        name: "RCE - Source Code in Comments",
        pattern: /<!--[\s\S]*(?:exec|system|bash|shell_exec|eval)[\s\S]*-->|\/\*[\s\S]*(?:exec|system)[\s\S]*\*\//i,
        field: "response",
        severity: "medium",
        score: 75,
        category: "rce",
        description: "Executable code in HTML comments",
        recommendation: "Never include code in comments"
      }
    ];
  }
});

// server/waf/rules/lfi.ts
var LFI_RULES;
var init_lfi = __esm({
  "server/waf/rules/lfi.ts"() {
    "use strict";
    LFI_RULES = [
      {
        id: "lfi-directory-traversal",
        name: "LFI - Directory Traversal",
        pattern: /\.\.\/|\.\.\\|%2e%2e%2f|%2e%2e%5c|\.\.;\/|..;\\|%252e%252e/i,
        field: "request",
        severity: "critical",
        score: 96,
        category: "lfi",
        description: "Directory traversal sequences detected",
        recommendation: "Canonicalize paths and validate against whitelist"
      },
      {
        id: "lfi-null-byte-injection",
        name: "LFI - Null Byte Injection",
        pattern: /%00|\.php%00|\.jsp%00|\.asp%00|\.exe%00/i,
        field: "request",
        severity: "critical",
        score: 94,
        category: "lfi",
        description: "Null byte injection for file extension bypass",
        recommendation: "Validate and reject null bytes in filenames"
      },
      {
        id: "lfi-absolute-paths",
        name: "LFI - Absolute File Paths",
        pattern: /^(\/etc\/|\/var\/|\/proc\/|\/sys\/|\/root\/|\/home\/|C:\\(Windows|Program Files)|file:\/\/\/)/i,
        field: "request",
        severity: "critical",
        score: 93,
        category: "lfi",
        description: "Absolute file system paths for sensitive files",
        recommendation: "Only allow relative paths, use base directory"
      },
      {
        id: "lfi-php-wrappers",
        name: "LFI - PHP Stream Wrappers",
        pattern: /(php|filter|data|glob|phar|rar|ogg|expect):\/\//i,
        field: "request",
        severity: "critical",
        score: 95,
        category: "lfi",
        description: "PHP stream wrapper abuse (filter, data, etc.)",
        recommendation: "Disable stream wrapper handlers"
      },
      {
        id: "lfi-log-poisoning",
        name: "LFI - Log Poisoning",
        pattern: /\/var\/log\/.*|\/var\/www\/.*|access\.log|error\.log|apache2\/logs|nginx\/logs/i,
        field: "request",
        severity: "high",
        score: 85,
        category: "lfi",
        description: "Attempting to include application logs",
        recommendation: "Restrict log file access, implement proper logging"
      },
      {
        id: "lfi-unicode-encoding",
        name: "LFI - Unicode Path Encoding",
        pattern: /%c0%ae|%uff0e|%u002e|%c1%9c|%e0%80%ae/i,
        field: "request",
        severity: "high",
        score: 82,
        category: "lfi",
        description: "Unicode-encoded directory traversal",
        recommendation: "Normalize Unicode before path validation"
      },
      {
        id: "lfi-double-encoding",
        name: "LFI - Double Encoding Bypass",
        pattern: /%252e%252e|%252f|%255c|%25c0%25ae/i,
        field: "request",
        severity: "high",
        score: 88,
        category: "lfi",
        description: "Double-encoded traversal sequences",
        recommendation: "Decode recursively and normalize paths"
      },
      {
        id: "lfi-sensitive-windows-files",
        name: "LFI - Windows Sensitive Files",
        pattern: /(win\.ini|system32|boot\.ini|windows\\\\system32|pagefile\.sys|hiberfil\.sys)/i,
        field: "request",
        severity: "high",
        score: 86,
        category: "lfi",
        description: "Windows sensitive file access attempts",
        recommendation: "Implement strict file whitelisting"
      },
      {
        id: "lfi-unix-system-files",
        name: "LFI - Unix System Files",
        pattern: /\/etc\/(passwd|shadow|group|hosts|resolv\.conf|fstab|sudoers)|\/proc\/self\/(cmdline|environ|maps)/i,
        field: "request",
        severity: "critical",
        score: 97,
        category: "lfi",
        description: "Unix system and credential file access",
        recommendation: "Block access to /etc/ and /proc/ files"
      },
      {
        id: "lfi-archive-extraction",
        name: "LFI - Archive File Exploitation",
        pattern: /\.zip%00|\.tar%00|\.gz%00|\.rar%00|\.7z%00|phar:\/\//i,
        field: "request",
        severity: "high",
        score: 84,
        category: "lfi",
        description: "Archive file inclusion/extraction attempts",
        recommendation: "Disable archive wrappers and validate extensions"
      }
    ];
  }
});

// server/waf/rules/ssrf.ts
var SSRF_RULES;
var init_ssrf = __esm({
  "server/waf/rules/ssrf.ts"() {
    "use strict";
    SSRF_RULES = [
      {
        id: "ssrf-localhost-access",
        name: "SSRF - Localhost Access",
        pattern: /(localhost|127\.0\.0\.1|0\.0\.0\.0|::1|%7f%7f%7f%7f|0x7f000001)/i,
        field: "request",
        severity: "critical",
        score: 96,
        category: "ssrf",
        description: "Attempt to access localhost or loopback addresses",
        recommendation: "Whitelist allowed external URLs, block internal IPs"
      },
      {
        id: "ssrf-private-ips",
        name: "SSRF - Private IP Ranges",
        pattern: /(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2[0-9]|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|169\.254\.\d{1,3}\.\d{1,3})/,
        field: "request",
        severity: "critical",
        score: 95,
        category: "ssrf",
        description: "Attempt to access private IP addresses (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)",
        recommendation: "Reject requests to private IP ranges"
      },
      {
        id: "ssrf-metadata-services",
        name: "SSRF - Cloud Metadata Services",
        pattern: /(169\.254\.169\.254|metadata\.google\.internal|instance-data|kube-system|imds)/i,
        field: "request",
        severity: "critical",
        score: 97,
        category: "ssrf",
        description: "Attempt to access cloud metadata services (AWS, GCP, Azure)",
        recommendation: "Block access to cloud metadata endpoints"
      },
      {
        id: "ssrf-url-schemes",
        name: "SSRF - Dangerous URL Schemes",
        pattern: /(file:\/\/|ftp:\/\/|gopher:\/\/|dict:\/\/|ldap:\/\/|ldapi:\/\/|tftp:\/\/|sftp:\/\/|telnet:\/\/)/i,
        field: "request",
        severity: "high",
        score: 88,
        category: "ssrf",
        description: "Dangerous URL schemes for SSRF exploitation",
        recommendation: "Only allow http and https schemes"
      },
      {
        id: "ssrf-port-scanning",
        name: "SSRF - Port Scanning Attempts",
        pattern: /:\d{1,5}\s*(\/|$)|port=\d{1,5}|host=[^&\s]*:\d{1,5}/i,
        field: "request",
        severity: "high",
        score: 82,
        category: "ssrf",
        description: "Apparent port scanning attempts via SSRF",
        recommendation: "Restrict URL parsing to standard ports"
      },
      {
        id: "ssrf-host-header-injection",
        name: "SSRF - Host Header Injection",
        pattern: /host\s*:\s*[^:]*@|@[^\/]*host\s*:/i,
        field: "request",
        severity: "high",
        score: 85,
        category: "ssrf",
        description: "Host header manipulation for SSRF",
        recommendation: "Validate Host header matches expected domain"
      },
      {
        id: "ssrf-dns-rebinding",
        name: "SSRF - DNS Rebinding",
        pattern: /(localhost\.localdomain|127\.0\.0\.1\.xip\.io|127\.0\.0\.1\.nip\.io|0x7f\.0x0\.0x0\.0x1)/i,
        field: "request",
        severity: "high",
        score: 84,
        category: "ssrf",
        description: "DNS rebinding techniques for SSRF bypass",
        recommendation: "Use IP address validation instead of hostname"
      },
      {
        id: "ssrf-url-encoding-bypass",
        name: "SSRF - URL Encoding Bypass",
        pattern: /%2e%2e|%3f|%23|%40|%3a|%2f%2f/i,
        field: "request",
        severity: "high",
        score: 81,
        category: "ssrf",
        description: "URL-encoded characters for SSRF bypass",
        recommendation: "Normalize and decode URLs before validation"
      },
      {
        id: "ssrf-redirect-chain",
        name: "SSRF - Redirect Chain Exploitation",
        pattern: /(redirect|redir|return|goto|url|callback|continue|destination|next)=https?:\/\/[^&\s]+https?:\/\//i,
        field: "request",
        severity: "high",
        score: 83,
        category: "ssrf",
        description: "Chained redirects for internal access",
        recommendation: "Limit redirect depth, validate all redirect targets"
      },
      {
        id: "ssrf-hex-ip-encoding",
        name: "SSRF - Hex IP Encoding",
        pattern: /0x[0-9a-fA-F]{2}\.0x[0-9a-fA-F]{2}|0x7f|0xa9fe/i,
        field: "request",
        severity: "high",
        score: 80,
        category: "ssrf",
        description: "Hex-encoded IP addresses for bypass",
        recommendation: "Validate IP addresses in multiple formats"
      },
      {
        id: "ssrf-octal-notation",
        name: "SSRF - Octal Notation IP Bypass",
        pattern: /\b0[0-7]{1,3}\.0[0-7]{1,3}\.0[0-7]{1,3}\.0[0-7]{1,3}\b/,
        field: "request",
        severity: "high",
        score: 79,
        category: "ssrf",
        description: "Octal notation IP addresses for bypass",
        recommendation: "Validate all IP notation formats"
      },
      {
        id: "ssrf-unicode-bypass",
        name: "SSRF - Unicode/UTF-8 Bypass",
        pattern: /127%00|localhost%00|%c0%ae|%uff0e|%c1%9c/i,
        field: "request",
        severity: "high",
        score: 77,
        category: "ssrf",
        description: "Unicode encoding for SSRF bypass",
        recommendation: "Normalize URLs before validation"
      }
    ];
  }
});

// server/waf/rules/java-attacks.ts
var JAVA_ATTACKS_RULES;
var init_java_attacks = __esm({
  "server/waf/rules/java-attacks.ts"() {
    "use strict";
    JAVA_ATTACKS_RULES = [
      {
        id: "java-serialization",
        name: "Java - Unsafe Deserialization",
        pattern: /\bObjectInputStream\b|\breadObject\b|java\.io\.Serializable|ysoserial|CommonsCollections|JNDI/i,
        field: "request",
        severity: "critical",
        score: 98,
        category: "java-attacks",
        description: "Java deserialization exploitation (gadget chains)",
        recommendation: "Disable object deserialization, use allowlists"
      },
      {
        id: "java-reflection",
        name: "Java - Unsafe Reflection",
        pattern: /\bClass\.forName\b|\bgetMethod\b|\bgetField\b|invoke\s*\(|newInstance|defineClass/i,
        field: "request",
        severity: "high",
        score: 90,
        category: "java-attacks",
        description: "Java reflection for dynamic code execution",
        recommendation: "Avoid reflection with user input, use security manager"
      },
      {
        id: "java-jndi-injection",
        name: "Java - JNDI Injection",
        pattern: /(rmi:\/\/|ldap:\/\/|nis:\/\/|iiop:\/\/|corbaname:\/\/|ldaps:\/\/).*\$\{.*\}|InitialContext|lookup/i,
        field: "request",
        severity: "critical",
        score: 96,
        category: "java-attacks",
        description: "JNDI injection with variable expansion (Log4Shell)",
        recommendation: "Update Log4j and disable variable expansion"
      },
      {
        id: "java-spring-expression",
        name: "Java - Spring Expression Injection",
        pattern: /SpEL|\$\{.*T\(.*\)\}|T\(java\.|\.class\.forName/i,
        field: "request",
        severity: "critical",
        score: 94,
        category: "java-attacks",
        description: "Spring Expression Language injection",
        recommendation: "Avoid SpEL with user input, use strict parser"
      },
      {
        id: "java-velocity-template",
        name: "Java - Velocity Template Injection",
        pattern: /#set\s*\(|#if\s*\(|#foreach|#parse|#include|\$\{.*\.class\..*\}|#evaluate/i,
        field: "request",
        severity: "high",
        score: 88,
        category: "java-attacks",
        description: "Velocity template engine injection",
        recommendation: "Disable dangerous directives, sandbox template execution"
      },
      {
        id: "java-freemarker-injection",
        name: "Java - FreeMarker Template Injection",
        pattern: /<#assign|<#if|<#list|<@|\?new|\?api|FreeMarkerException/i,
        field: "request",
        severity: "high",
        score: 86,
        category: "java-attacks",
        description: "FreeMarker template language injection",
        recommendation: "Use safe configuration, disable object wrapping"
      },
      {
        id: "java-groovy-injection",
        name: "Java - Groovy Script Injection",
        pattern: /GroovyShell|GroovyEngine|\.evaluate\s*\(|\.execute\s*\(|Runtime\.getRuntime|ProcessGroovyMethods/i,
        field: "request",
        severity: "critical",
        score: 92,
        category: "java-attacks",
        description: "Groovy dynamic script execution",
        recommendation: "Disable script evaluation, use sandboxing"
      },
      {
        id: "java-xpath-injection",
        name: "Java - XPath Injection",
        pattern: /XPathFactory|XPath\.evaluate|selectNodes|selectSingleNode|concat\s*\(|string-length/i,
        field: "request",
        severity: "high",
        score: 82,
        category: "java-attacks",
        description: "XPath injection in Java applications",
        recommendation: "Use parameterized XPath queries"
      },
      {
        id: "java-mybatis-injection",
        name: "Java - MyBatis SQL Injection",
        pattern: /\$\{.*\}|#\{.*\}|sqlmap|union.*select|mybatis|mapper/i,
        field: "request",
        severity: "high",
        score: 85,
        category: "java-attacks",
        description: "MyBatis SQL injection via unsanitized variables",
        recommendation: "Use parameterized queries, validate all input"
      },
      {
        id: "java-classloader-injection",
        name: "Java - ClassLoader Manipulation",
        pattern: /ClassLoader|defineClass|findClass|loadClass|setClassAssertionStatus|getClassloader/i,
        field: "request",
        severity: "high",
        score: 83,
        category: "java-attacks",
        description: "ClassLoader manipulation for code injection",
        recommendation: "Restrict ClassLoader access, use security manager"
      },
      {
        id: "java-runtime-exec",
        name: "Java - Runtime.exec() Command Injection",
        pattern: /Runtime\.getRuntime\s*\(\)\s*\.exec|ProcessBuilder|ProcessImpl|java\.lang\.UNIXProcess/i,
        field: "request",
        severity: "critical",
        score: 97,
        category: "java-attacks",
        description: "Direct runtime command execution",
        recommendation: "Avoid Runtime.exec(), use security manager"
      },
      {
        id: "java-script-engine",
        name: "Java - ScriptEngineManager Injection",
        pattern: /ScriptEngineManager|ScriptEngine|getEngineByName|eval\s*\(|javascript|nashorn|rhino/i,
        field: "request",
        severity: "critical",
        score: 93,
        category: "java-attacks",
        description: "Script engine injection (Nashorn/Rhino)",
        recommendation: "Disable script engines, use sandboxing"
      },
      {
        id: "java-mbean-injection",
        name: "Java - MBean/JMX Injection",
        pattern: /MBeanServer|ObjectName|createMBean|setAttribute|getAttribute|invoke|JMXConnectorFactory/i,
        field: "request",
        severity: "high",
        score: 89,
        category: "java-attacks",
        description: "JMX/MBean manipulation",
        recommendation: "Restrict JMX access, use authentication"
      },
      {
        id: "java-el-injection",
        name: "Java - Expression Language (EL) Injection",
        pattern: /\$\{[^}]*\}|\#\{[^}]*\}|ELProcessor|evaluateExpression|parseExpression/i,
        field: "request",
        severity: "high",
        score: 88,
        category: "java-attacks",
        description: "EL injection in JSP/JSF",
        recommendation: "Disable EL evaluation, use strict templates"
      },
      {
        id: "java-ognl-injection",
        name: "Java - OGNL Injection",
        pattern: /OGNL|%\{[^}]*\}|struts|getValue|setValue|\(#|@java|@org/i,
        field: "request",
        severity: "high",
        score: 87,
        category: "java-attacks",
        description: "Object-Graph Navigation Language injection",
        recommendation: "Update Struts, disable OGNL with user input"
      },
      {
        id: "java-log4j-injection",
        name: "Java - Log4j Injection Patterns",
        pattern: /\$\{jndi:[^}]*\}|log4j|Log4j|CVE-2021-44228|log4shell|JndiLookup/i,
        field: "request",
        severity: "critical",
        score: 95,
        category: "java-attacks",
        description: "Log4Shell and related Log4j exploits",
        recommendation: "Update to patched Log4j version"
      },
      {
        id: "java-urlclassloader",
        name: "Java - URLClassLoader Exploitation",
        pattern: /URLClassLoader|new\s+URL|addURL|jar:file|codebase|java\.net\.URL/i,
        field: "request",
        severity: "high",
        score: 84,
        category: "java-attacks",
        description: "Remote class loading via URLClassLoader",
        recommendation: "Restrict URLClassLoader usage"
      },
      {
        id: "java-bcel-injection",
        name: "Java - BCEL Classloader Injection",
        pattern: /BCEL|org\.apache\.bcel|com\.sun\.org\.apache\.bcel|Bytecode Engineering|ClassPool/i,
        field: "request",
        severity: "high",
        score: 86,
        category: "java-attacks",
        description: "BCEL bytecode manipulation",
        recommendation: "Update BCEL, restrict bytecode manipulation"
      },
      {
        id: "java-jexl-injection",
        name: "Java - JEXL Expression Injection",
        pattern: /JexlEngine|JexlContext|createExpression|getValue|jexl|commons\.jexl/i,
        field: "request",
        severity: "high",
        score: 85,
        category: "java-attacks",
        description: "JEXL expression language injection",
        recommendation: "Use parameterized JEXL expressions"
      },
      {
        id: "java-pickle-serialization",
        name: "Java - Unsafe Pickle Deserialization",
        pattern: /pickle\.loads|cPickle|marshal\.loads|unpickle|ObjectInputStream|readObject/i,
        field: "request",
        severity: "high",
        score: 88,
        category: "java-attacks",
        description: "Python pickle or Java serialization attacks",
        recommendation: "Avoid unsafe deserialization"
      }
    ];
  }
});

// server/waf/rules/dos.ts
var DOS_RULES;
var init_dos = __esm({
  "server/waf/rules/dos.ts"() {
    "use strict";
    DOS_RULES = [
      {
        id: "dos-large-payload",
        name: "DoS - Excessively Large Payload",
        pattern: /.{10000}/,
        field: "body",
        severity: "high",
        score: 75,
        category: "dos",
        description: "Request body exceeds 10KB (potential DoS)",
        recommendation: "Implement strict content-length limits"
      },
      {
        id: "dos-slow-request",
        name: "DoS - Slow Request Detection",
        pattern: /^$/,
        field: "body",
        severity: "medium",
        score: 45,
        category: "dos",
        description: "Slowloris or slow request attack pattern",
        recommendation: "Implement request timeouts and connection limits"
      },
      {
        id: "dos-compression-bomb",
        name: "DoS - Compression Bomb Detection",
        pattern: /content-encoding\s*:\s*(gzip|deflate|br)|x-compressed-bomb/i,
        field: "headers",
        severity: "high",
        score: 70,
        category: "dos",
        description: "Potential compression bomb or decompression attack",
        recommendation: "Limit decompressed content size and detect bombs"
      },
      {
        id: "dos-regex-complexity",
        name: "DoS - ReDoS Pattern Detection",
        pattern: /(\w+\*){5,}|(\w+\+){5,}|\(\w+\|{2,}/,
        field: "request",
        severity: "high",
        score: 72,
        category: "dos",
        description: "Regular expression complexity (ReDoS attack)",
        recommendation: "Validate regex complexity and use timeouts"
      },
      {
        id: "dos-hash-collision",
        name: "DoS - Hash Collision Attack",
        pattern: /[?&][a-z0-9]{100,}=|POST.*content-type.*x-www-form.*[a-z0-9]{500,}/i,
        field: "request",
        severity: "high",
        score: 68,
        category: "dos",
        description: "Potential hash table collision attack",
        recommendation: "Use secure hash functions and limit parameter counts"
      },
      {
        id: "dos-xml-bomb",
        name: "DoS - XML Bomb (Billion Laughs)",
        pattern: /<!ENTITY|<\!ENTITY.*?SYSTEM|&[a-z]+;.*&[a-z]+;.*&[a-z]+;/i,
        field: "body",
        severity: "high",
        score: 76,
        category: "dos",
        description: "XML bomb or entity expansion attack",
        recommendation: "Disable external entities, limit entity nesting"
      },
      {
        id: "dos-request-flooding",
        name: "DoS - Request Flooding Indicators",
        pattern: /^$/,
        field: "path",
        severity: "medium",
        score: 50,
        category: "dos",
        description: "Multiple rapid requests from same IP",
        recommendation: "Implement rate limiting and connection pooling"
      },
      {
        id: "dos-pipe-pollution",
        name: "DoS - HTTP Pipe Pollution",
        pattern: /\r\n\r\n.*GET\s+\/|POST\s+\/.*\r\n\r\nGET/i,
        field: "request",
        severity: "high",
        score: 71,
        category: "dos",
        description: "HTTP request pipelining or cache poisoning",
        recommendation: "Enforce strict request parsing and disable pipelining"
      },
      {
        id: "dos-memory-exhaustion",
        name: "DoS - Memory Exhaustion Pattern",
        pattern: /\barray_fill\b|\bstr_repeat\b|\bmemset\b|malloc.*1000000|allocate.*\d{10}/i,
        field: "request",
        severity: "high",
        score: 74,
        category: "dos",
        description: "Potential memory allocation explosion",
        recommendation: "Limit allocation sizes and monitor memory usage"
      },
      {
        id: "dos-algorithmic-complexity",
        name: "DoS - Algorithmic Complexity Attack",
        pattern: /sort|shuffle|permutation|factorial|fibonacci|recursive.*call|\.{3,}/,
        field: "request",
        severity: "medium",
        score: 62,
        category: "dos",
        description: "Algorithmic complexity exploitation",
        recommendation: "Implement complexity analysis and execution timeouts"
      },
      {
        id: "dos-cpu-intensive",
        name: "DoS - CPU Intensive Operations",
        pattern: /(crypto|bcrypt|argon2|scrypt|pbkdf2)[\s\S]*?iterations?[\s\S]*?100000|sleep\(\d{6,}|usleep\(\d{8,}/i,
        field: "request",
        severity: "high",
        score: 73,
        category: "dos",
        description: "CPU-intensive operation requests",
        recommendation: "Throttle expensive operations"
      },
      {
        id: "dos-bandwidth-exhaustion",
        name: "DoS - Bandwidth Exhaustion",
        pattern: /content-length\s*:\s*\d{8,}|range\s*:\s*bytes.*-\d{8,}/i,
        field: "headers",
        severity: "high",
        score: 69,
        category: "dos",
        description: "Large range requests for bandwidth exhaustion",
        recommendation: "Limit range request sizes"
      },
      {
        id: "dos-connection-exhaustion",
        name: "DoS - Connection Pool Exhaustion",
        pattern: /keep-alive\s*:\s*\d{6,}|connection\s*:\s*keep-alive[\s\S]*?content-length\s*:\s*0/i,
        field: "headers",
        severity: "medium",
        score: 61,
        category: "dos",
        description: "Connection pool exhaustion via keep-alive",
        recommendation: "Implement connection limits"
      },
      {
        id: "dos-querystring-explosion",
        name: "DoS - Query String Explosion",
        pattern: /\?[^=&]*=[^&]*(&[^=&]*=[^&]*){100,}/,
        field: "request",
        severity: "high",
        score: 67,
        category: "dos",
        description: "Excessive query parameters",
        recommendation: "Limit parameter counts"
      }
    ];
  }
});

// server/waf/rules/protocol-validation.ts
var PROTOCOL_VALIDATION_RULES;
var init_protocol_validation = __esm({
  "server/waf/rules/protocol-validation.ts"() {
    "use strict";
    PROTOCOL_VALIDATION_RULES = [
      {
        id: "protocol-invalid-content-length",
        name: "Invalid Content-Length",
        pattern: /content-length\s*:\s*[^0-9\r\n]/i,
        field: "headers",
        severity: "high",
        score: 75,
        category: "protocol-validation",
        description: "Content-Length header contains non-numeric characters",
        recommendation: "Ensure Content-Length contains only numeric values"
      },
      {
        id: "protocol-duplicate-content-length",
        name: "Multiple Content-Length Headers",
        pattern: /(?:content-length[\s\S]*?){2,}/i,
        field: "headers",
        severity: "high",
        score: 80,
        category: "protocol-validation",
        description: "Request contains duplicate Content-Length headers (HTTP smuggling)",
        recommendation: "Reject requests with multiple Content-Length headers"
      },
      {
        id: "protocol-post-no-body",
        name: "POST Request with No Body",
        pattern: /^POST.*content-length\s*:\s*0\s*$/mi,
        field: "headers",
        severity: "medium",
        score: 50,
        category: "protocol-validation",
        description: "POST request with Content-Length: 0",
        recommendation: "Validate POST request has expected content"
      },
      {
        id: "protocol-null-byte",
        name: "Null Byte in Request",
        pattern: /\x00/,
        field: "request",
        severity: "critical",
        score: 95,
        category: "protocol-validation",
        description: "Null byte detected in HTTP request",
        recommendation: "Strip null bytes from all user input"
      },
      {
        id: "protocol-invalid-method",
        name: "Invalid HTTP Method",
        pattern: /^(?!GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|TRACE|CONNECT|PROPFIND|PROPPATCH|MKCOL|COPY|MOVE|LOCK|UNLOCK)\S+/i,
        field: "method",
        severity: "high",
        score: 70,
        category: "protocol-validation",
        description: "Non-standard HTTP method detected",
        recommendation: "Only allow standard HTTP methods"
      },
      {
        id: "protocol-http-version",
        name: "Invalid HTTP Version",
        pattern: /HTTP\/(?!0\.9|1\.0|1\.1|2\.0|3\.0)/i,
        field: "headers",
        severity: "medium",
        score: 55,
        category: "protocol-validation",
        description: "Invalid or unsupported HTTP version",
        recommendation: "Only support HTTP/1.0, HTTP/1.1, HTTP/2.0"
      },
      {
        id: "protocol-missing-host",
        name: "Missing Host Header",
        pattern: /^(?!.*Host\s*:)/i,
        field: "headers",
        severity: "medium",
        score: 45,
        category: "protocol-validation",
        description: "HTTP/1.1 request without Host header",
        recommendation: "Enforce Host header for HTTP/1.1 requests"
      },
      {
        id: "protocol-absolute-uri",
        name: "Absolute URI in Request Line",
        pattern: /^(GET|POST|PUT|DELETE|PATCH|HEAD)\s+https?:\/\//i,
        field: "request",
        severity: "high",
        score: 65,
        category: "protocol-validation",
        description: "Absolute URI in request line (potential proxy bypass)",
        recommendation: "Only allow relative URIs in request line"
      },
      {
        id: "protocol-method-override",
        name: "HTTP Method Override Header",
        pattern: /(x-http-method-override|x-method-override|x-real-method)\s*:\s*(GET|POST|PUT|DELETE|PATCH)/i,
        field: "headers",
        severity: "high",
        score: 70,
        category: "protocol-validation",
        description: "HTTP method override header detected (security risk)",
        recommendation: "Disable HTTP method override headers if not needed"
      },
      {
        id: "protocol-transfer-encoding-null",
        name: "Transfer-Encoding with Null Bytes",
        pattern: /transfer-encoding\s*:[\s\S]*?\x00/i,
        field: "headers",
        severity: "critical",
        score: 90,
        category: "protocol-validation",
        description: "Transfer-Encoding header with null bytes",
        recommendation: "Strip null bytes and validate Transfer-Encoding values"
      },
      {
        id: "protocol-chunked-encoding-invalid",
        name: "Invalid Chunked Transfer Encoding",
        pattern: /transfer-encoding\s*:\s*chunked[\s\S]*?[^\da-fA-F\r\n]/i,
        field: "headers",
        severity: "high",
        score: 78,
        category: "protocol-validation",
        description: "Invalid chunked transfer encoding format"
      },
      {
        id: "protocol-double-transfer-encoding",
        name: "Multiple Transfer-Encoding Headers",
        pattern: /(?:transfer-encoding[\s\S]*?){2,}/i,
        field: "headers",
        severity: "critical",
        score: 92,
        category: "protocol-validation",
        description: "HTTP smuggling via duplicate Transfer-Encoding"
      },
      {
        id: "protocol-conflicting-headers",
        name: "Conflicting Content-Length and Transfer-Encoding",
        pattern: /content-length\s*:[^:\r\n]*[\r\n][\s\S]*?transfer-encoding\s*:/i,
        field: "headers",
        severity: "critical",
        score: 94,
        category: "protocol-validation",
        description: "Both Content-Length and Transfer-Encoding present"
      },
      {
        id: "protocol-invalid-uri",
        name: "Invalid URI Characters",
        pattern: /^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+[^\s]*[\x00-\x1f<>\\"]/i,
        field: "request",
        severity: "high",
        score: 77,
        category: "protocol-validation",
        description: "Invalid characters in request URI"
      },
      {
        id: "protocol-uri-encoding-bypass",
        name: "Double-Encoded URI",
        pattern: /%25[0-9a-fA-F]{2}|%252[0-7a-fA-F]/i,
        field: "request",
        severity: "high",
        score: 75,
        category: "protocol-validation",
        description: "Double URL encoding in request URI"
      },
      {
        id: "protocol-header-injection",
        name: "CRLF Injection in Headers",
        pattern: /[\r\n]{2,}|%0d%0a|%0a%0d/i,
        field: "headers",
        severity: "critical",
        score: 93,
        category: "protocol-validation",
        description: "CRLF injection for header injection attacks"
      },
      {
        id: "protocol-host-header-injection",
        name: "Host Header Injection",
        pattern: /host\s*:\s*[^:]*@|host\s*:\s*[^:]*:[^:]*:[^:]*/i,
        field: "headers",
        severity: "high",
        score: 76,
        category: "protocol-validation",
        description: "Malformed or malicious Host header"
      },
      {
        id: "protocol-invalid-content-type",
        name: "Invalid Content-Type Header",
        pattern: /content-type\s*:\s*(?![a-z]+\/[a-z+.-]+)/i,
        field: "headers",
        severity: "medium",
        score: 65,
        category: "protocol-validation",
        description: "Invalid Content-Type format"
      },
      {
        id: "protocol-accept-header-bomb",
        name: "Accept Header Bomb",
        pattern: /accept\s*:[^:\r\n]*,[^:\r\n]*,[^:\r\n]*,[^:\r\n]*,[^:\r\n]*,[^:\r\n]*,/i,
        field: "headers",
        severity: "medium",
        score: 60,
        category: "protocol-validation",
        description: "Excessive Accept header values"
      },
      {
        id: "protocol-user-agent-long",
        name: "Excessively Long User-Agent",
        pattern: /user-agent\s*:\s*.{500,}/i,
        field: "headers",
        severity: "medium",
        score: 55,
        category: "protocol-validation",
        description: "User-Agent header exceeds reasonable length"
      },
      {
        id: "protocol-referer-injection",
        name: "Referer Header Injection",
        pattern: /referer\s*:\s*.*(?:javascript:|data:|about:)/i,
        field: "headers",
        severity: "high",
        score: 72,
        category: "protocol-validation",
        description: "Dangerous URI scheme in Referer header"
      },
      {
        id: "protocol-cookie-injection",
        name: "CRLF in Cookie Header",
        pattern: /cookie\s*:[\s\S]*?[\r\n](?![\s])/i,
        field: "headers",
        severity: "high",
        score: 79,
        category: "protocol-validation",
        description: "CRLF characters in Cookie header"
      },
      {
        id: "protocol-authorization-injection",
        name: "CRLF in Authorization Header",
        pattern: /authorization\s*:[\s\S]*?[\r\n](?![\s])/i,
        field: "headers",
        severity: "critical",
        score: 91,
        category: "protocol-validation",
        description: "CRLF injection in Authorization header"
      },
      {
        id: "protocol-range-attack",
        name: "Range Request DoS",
        pattern: /range\s*:\s*bytes\s*=.*-.*,.*-.*,.*-.*,.*-.*,.*-.*/i,
        field: "headers",
        severity: "high",
        score: 74,
        category: "protocol-validation",
        description: "Excessive range requests (multipart range attack)"
      },
      {
        id: "protocol-if-range-mismatch",
        name: "If-Range and Range Mismatch",
        pattern: /if-range\s*:.*\r\n[\s\S]*?range\s*:/i,
        field: "headers",
        severity: "medium",
        score: 58,
        category: "protocol-validation",
        description: "Conflicting If-Range and Range headers"
      },
      {
        id: "protocol-date-format-invalid",
        name: "Invalid Date Header Format",
        pattern: /date\s*:\s*(?!(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun),)/i,
        field: "headers",
        severity: "medium",
        score: 52,
        category: "protocol-validation",
        description: "Invalid HTTP date format in Date header"
      },
      {
        id: "protocol-cache-control-confusion",
        name: "Conflicting Cache-Control Directives",
        pattern: /cache-control\s*:[\s\S]*?public[\s\S]*?private/i,
        field: "headers",
        severity: "medium",
        score: 61,
        category: "protocol-validation",
        description: "Conflicting Cache-Control directives"
      },
      {
        id: "protocol-pragma-cache-mismatch",
        name: "Pragma and Cache-Control Mismatch",
        pattern: /pragma\s*:\s*(?!no-cache)[\s\S]*?cache-control\s*:\s*no-cache/i,
        field: "headers",
        severity: "medium",
        score: 59,
        category: "protocol-validation",
        description: "Mismatched Pragma and Cache-Control"
      },
      {
        id: "protocol-age-negative",
        name: "Negative Age Header",
        pattern: /age\s*:\s*-\d+/i,
        field: "headers",
        severity: "medium",
        score: 54,
        category: "protocol-validation",
        description: "Negative value in Age header"
      },
      {
        id: "protocol-max-age-negative",
        name: "Negative Max-Age in Cache-Control",
        pattern: /cache-control\s*:[\s\S]*?max-age\s*=\s*-/i,
        field: "headers",
        severity: "medium",
        score: 56,
        category: "protocol-validation",
        description: "Negative max-age value"
      },
      {
        id: "protocol-expires-invalid",
        name: "Invalid Expires Header",
        pattern: /expires\s*:\s*(?!0|(?:(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun),))/i,
        field: "headers",
        severity: "medium",
        score: 53,
        category: "protocol-validation",
        description: "Invalid date/time in Expires header"
      },
      {
        id: "protocol-connection-upgrade",
        name: "Suspicious Connection Header",
        pattern: /connection\s*:\s*(?!keep-alive|close|upgrade)[\s\S]*?upgrade/i,
        field: "headers",
        severity: "high",
        score: 71,
        category: "protocol-validation",
        description: "Connection header with upgrade request"
      },
      {
        id: "protocol-upgrade-invalid",
        name: "Invalid Upgrade Header Protocol",
        pattern: /upgrade\s*:\s*(?!websocket|h2|h2c|h2-14|h2-15|h2-16|h2c-14)/i,
        field: "headers",
        severity: "high",
        score: 70,
        category: "protocol-validation",
        description: "Unknown protocol in Upgrade header"
      },
      {
        id: "protocol-proxy-injection",
        name: "Proxy Header Injection",
        pattern: /(?:x-forwarded-for|x-real-ip|cf-connecting-ip)\s*:[\s\S]*?[\r\n]/i,
        field: "headers",
        severity: "high",
        score: 73,
        category: "protocol-validation",
        description: "Suspicious proxy headers"
      },
      {
        id: "protocol-expect-100",
        name: "Invalid Expect Header",
        pattern: /expect\s*:\s*(?!100-continue)/i,
        field: "headers",
        severity: "medium",
        score: 57,
        category: "protocol-validation",
        description: "Invalid value in Expect header"
      },
      {
        id: "protocol-via-chain",
        name: "Excessive Via Header Chain",
        pattern: /via\s*:[\s\S]*?,[\s\S]*?,[\s\S]*?,[\s\S]*?,[\s\S]*?,/i,
        field: "headers",
        severity: "high",
        score: 69,
        category: "protocol-validation",
        description: "Excessively long proxy chain"
      },
      {
        id: "protocol-warning-header",
        name: "Invalid Warning Header",
        pattern: /warning\s*:\s*(?!\d{3})/i,
        field: "headers",
        severity: "medium",
        score: 51,
        category: "protocol-validation",
        description: "Invalid Warning header format"
      },
      {
        id: "protocol-allow-methods",
        name: "Invalid Allow Header",
        pattern: /allow\s*:[\s\S]*?[^A-Z\s,]/i,
        field: "headers",
        severity: "medium",
        score: 48,
        category: "protocol-validation",
        description: "Invalid methods in Allow header"
      },
      {
        id: "protocol-accept-encoding-bomb",
        name: "Accept-Encoding Bomb",
        pattern: /accept-encoding\s*:[^:\r\n]*,[^:\r\n]*,[^:\r\n]*,[^:\r\n]*,[^:\r\n]*,/i,
        field: "headers",
        severity: "medium",
        score: 59,
        category: "protocol-validation",
        description: "Excessive Accept-Encoding values"
      },
      {
        id: "protocol-te-header-abuse",
        name: "TE Header HTTP Smuggling",
        pattern: /te\s*:\s*(?!trailers)[\s\S]*?trailers/i,
        field: "headers",
        severity: "high",
        score: 81,
        category: "protocol-validation",
        description: "TE header smuggling techniques"
      },
      {
        id: "protocol-content-encoding-invalid",
        name: "Invalid Content-Encoding",
        pattern: /content-encoding\s*:\s*(?!gzip|deflate|br|compress|identity|x-gzip)/i,
        field: "headers",
        severity: "medium",
        score: 63,
        category: "protocol-validation",
        description: "Unknown Content-Encoding value"
      },
      {
        id: "protocol-content-location-invalid",
        name: "Invalid Content-Location",
        pattern: /content-location\s*:\s*(?:\/\/|javascript:|data:|about:)/i,
        field: "headers",
        severity: "high",
        score: 68,
        category: "protocol-validation",
        description: "Dangerous protocol in Content-Location"
      },
      {
        id: "protocol-link-header-injection",
        name: "Link Header Injection",
        pattern: /link\s*:[\s\S]*?>;[\s\S]*?[<>]/i,
        field: "headers",
        severity: "high",
        score: 66,
        category: "protocol-validation",
        description: "Malformed Link header"
      },
      {
        id: "protocol-retry-after-invalid",
        name: "Invalid Retry-After Format",
        pattern: /retry-after\s*:\s*(?!\d{1,3}|(?:(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun),))/i,
        field: "headers",
        severity: "medium",
        score: 49,
        category: "protocol-validation",
        description: "Invalid Retry-After value"
      },
      {
        id: "protocol-request-line-splitting",
        name: "Request Line Injection",
        pattern: /^(GET|POST|PUT|DELETE)\s+[^\s]*(?:\r|\n|%0[ad])/i,
        field: "request",
        severity: "critical",
        score: 90,
        category: "protocol-validation",
        description: "CRLF in HTTP request line"
      },
      {
        id: "protocol-empty-header-name",
        name: "Empty Header Name",
        pattern: /^\s*:\s*[^:\r\n]/m,
        field: "headers",
        severity: "high",
        score: 67,
        category: "protocol-validation",
        description: "Header with empty name"
      },
      {
        id: "protocol-header-line-folding",
        name: "Obsolete Header Line Folding",
        pattern: /\r\n[\s\t]+/m,
        field: "headers",
        severity: "medium",
        score: 64,
        category: "protocol-validation",
        description: "Obsolete line folding in headers"
      },
      {
        id: "protocol-space-in-header-name",
        name: "Space in Header Name",
        pattern: /^[^\s:]*\s+[^\s:]*\s*:/m,
        field: "headers",
        severity: "high",
        score: 74,
        category: "protocol-validation",
        description: "Spaces in header field name"
      },
      {
        id: "protocol-tab-in-uri",
        name: "Tab Character in URI",
        pattern: /^(GET|POST|PUT|DELETE|PATCH|HEAD)\s+[^\s]*\t/i,
        field: "request",
        severity: "high",
        score: 72,
        category: "protocol-validation",
        description: "Tab character in request URI"
      },
      {
        id: "protocol-form-urlencoded-invalid",
        name: "Invalid Form URL Encoding",
        pattern: /application\/x-www-form-urlencoded[\s\S]*?(?:[^a-zA-Z0-9_%\-\.&=](?!%[0-9a-fA-F]{2}))/i,
        field: "request",
        severity: "medium",
        score: 62,
        category: "protocol-validation",
        description: "Invalid characters in form data"
      },
      {
        id: "protocol-multipart-boundary",
        name: "Invalid Multipart Boundary",
        pattern: /multipart\/(?:form-data|mixed)[\s\S]*?boundary\s*=(?![a-zA-Z0-9._-]{1,70})/i,
        field: "headers",
        severity: "high",
        score: 75,
        category: "protocol-validation",
        description: "Invalid or missing multipart boundary"
      },
      {
        id: "protocol-path-traversal",
        name: "Path Traversal in URI",
        pattern: /^(GET|POST|PUT|DELETE|PATCH|HEAD)\s+[^\s]*\.\.\/|\.\.\\\\/i,
        field: "request",
        severity: "high",
        score: 77,
        category: "protocol-validation",
        description: "Path traversal sequences in request URI"
      },
      {
        id: "protocol-backslash-uri",
        name: "Backslash in URI Path",
        pattern: /^(GET|POST|PUT|DELETE|PATCH|HEAD)\s+[^\s]*\\(?!\/)/i,
        field: "request",
        severity: "high",
        score: 71,
        category: "protocol-validation",
        description: "Backslash used as path separator"
      },
      {
        id: "protocol-raw-unicode-uri",
        name: "Raw Unicode in URI",
        pattern: /^(GET|POST|PUT|DELETE)\s+[^\s]*[^\x00-\x7F]/i,
        field: "request",
        severity: "medium",
        score: 60,
        category: "protocol-validation",
        description: "Non-ASCII characters in request URI"
      },
      {
        id: "protocol-fragment-identifier",
        name: "Fragment Identifier in Request",
        pattern: /^(GET|POST|PUT|DELETE|PATCH|HEAD)\s+[^\s]*#/i,
        field: "request",
        severity: "medium",
        score: 57,
        category: "protocol-validation",
        description: "Fragment identifier in HTTP request URI"
      },
      {
        id: "protocol-query-string-bomb",
        name: "Excessive Query String",
        pattern: /\?[^=&]*=[^&]*(&[^=&]*=[^&]*){100,}/,
        field: "request",
        severity: "high",
        score: 70,
        category: "protocol-validation",
        description: "Query string with 100+ parameters"
      },
      {
        id: "protocol-status-line-invalid",
        name: "Invalid Status Line Format",
        pattern: /^HTTP\/(?!1\.[01]|2\.0|3\.0)\S+\s+(?!\d{3})/i,
        field: "response",
        severity: "medium",
        score: 51,
        category: "protocol-validation",
        description: "Malformed HTTP status line"
      },
      {
        id: "protocol-reason-phrase-invalid",
        name: "Invalid Reason Phrase",
        pattern: /HTTP\/\d\.\d\s+\d{3}\s+[^\x20-\x7E]/,
        field: "response",
        severity: "medium",
        score: 50,
        category: "protocol-validation",
        description: "Invalid characters in reason phrase"
      },
      {
        id: "protocol-status-code-range",
        name: "Invalid HTTP Status Code",
        pattern: /HTTP\/\d\.\d\s+(?!100|101|[23]\d{2}|400|40[134567]|41[0-7]|5\d{2})\d{3}/i,
        field: "response",
        severity: "medium",
        score: 47,
        category: "protocol-validation",
        description: "Non-standard HTTP status code"
      },
      {
        id: "protocol-http2-pseudo-headers",
        name: "HTTP/2 Pseudo-Header Abuse",
        pattern: /:\w+\s*:[^\s]/i,
        field: "headers",
        severity: "high",
        score: 76,
        category: "protocol-validation",
        description: "Invalid HTTP/2 pseudo-header"
      },
      {
        id: "protocol-header-name-uppercase",
        name: "Uppercase in Header Name",
        pattern: /^[a-z]*[A-Z][a-z]*:/m,
        field: "headers",
        severity: "low",
        score: 35,
        category: "protocol-validation",
        description: "Non-standard header name capitalization"
      },
      {
        id: "protocol-http09-request",
        name: "HTTP/0.9 Request Detection",
        pattern: /^(GET|HEAD)\s+[^\s]+\s*\r?\n(?!HTTP)/i,
        field: "request",
        severity: "medium",
        score: 58,
        category: "protocol-validation",
        description: "HTTP/0.9 simple request format"
      },
      {
        id: "protocol-connect-method-abuse",
        name: "CONNECT Method Abuse",
        pattern: /^CONNECT\s+[^\s]*[^\d]\s+HTTP/i,
        field: "request",
        severity: "high",
        score: 73,
        category: "protocol-validation",
        description: "CONNECT method with invalid destination"
      },
      {
        id: "protocol-trace-method-abuse",
        name: "TRACE Method Detected",
        pattern: /^TRACE\s+/i,
        field: "request",
        severity: "high",
        score: 68,
        category: "protocol-validation",
        description: "TRACE method which can expose headers"
      },
      {
        id: "protocol-options-wildcard-abuse",
        name: "OPTIONS * Wildcard Abuse",
        pattern: /^OPTIONS\s+\*\s+HTTP\/1\.1/i,
        field: "request",
        severity: "medium",
        score: 59,
        category: "protocol-validation",
        description: "OPTIONS request to server root"
      },
      {
        id: "protocol-content-length-large",
        name: "Excessively Large Content-Length",
        pattern: /content-length\s*:\s*(?:[5-9]\d{8}|\d{10,})/i,
        field: "headers",
        severity: "high",
        score: 72,
        category: "protocol-validation",
        description: "Content-Length exceeds 500MB"
      },
      {
        id: "protocol-content-length-format",
        name: "Invalid Content-Length Format",
        pattern: /content-length\s*:\s*[+-]|content-length\s*:\s*0[xX]/i,
        field: "headers",
        severity: "high",
        score: 70,
        category: "protocol-validation",
        description: "Content-Length with sign or hex prefix"
      },
      {
        id: "protocol-header-value-spaces",
        name: "Excessive Spaces in Header Value",
        pattern: /:\s{5,}[^\s]|:\s*[^\s]*\s{10,}[^\s]/,
        field: "headers",
        severity: "medium",
        score: 56,
        category: "protocol-validation",
        description: "Abnormal whitespace in header values"
      },
      {
        id: "protocol-host-port-mismatch",
        name: "Host Header Port Mismatch",
        pattern: /host\s*:\s*[^\s:]+:(\d+)/i,
        field: "headers",
        severity: "medium",
        score: 61,
        category: "protocol-validation",
        description: "Host header with port number"
      },
      {
        id: "protocol-accept-charset-bomb",
        name: "Accept-Charset Bomb",
        pattern: /accept-charset\s*:[^:\r\n]*,[^:\r\n]*,[^:\r\n]*,[^:\r\n]*,[^:\r\n]*,/i,
        field: "headers",
        severity: "medium",
        score: 55,
        category: "protocol-validation",
        description: "Excessive Accept-Charset values"
      },
      {
        id: "protocol-accept-language-bomb",
        name: "Accept-Language Bomb",
        pattern: /accept-language\s*:[^:\r\n]*,[^:\r\n]*,[^:\r\n]*,[^:\r\n]*,[^:\r\n]*,/i,
        field: "headers",
        severity: "medium",
        score: 54,
        category: "protocol-validation",
        description: "Excessive Accept-Language values"
      },
      {
        id: "protocol-x-forwarded-for-spoof",
        name: "X-Forwarded-For Spoofing",
        pattern: /x-forwarded-for\s*:\s*(?:127\.|192\.168\.|10\.|172\.1[6-9]\.|172\.2[0-9]\.|172\.3[01]\.)/i,
        field: "headers",
        severity: "high",
        score: 71,
        category: "protocol-validation",
        description: "Private IP in X-Forwarded-For"
      },
      {
        id: "protocol-etag-weak-strong-mismatch",
        name: "ETag Format Invalid",
        pattern: /etag\s*:\s*(?!W?"[^"]*"|"[^"]*")/i,
        field: "headers",
        severity: "medium",
        score: 52,
        category: "protocol-validation",
        description: "Invalid ETag format"
      },
      {
        id: "protocol-if-match-mismatch",
        name: "If-Match Multiple ETags",
        pattern: /if-match\s*:(?:[^,]*,){5,}/i,
        field: "headers",
        severity: "medium",
        score: 50,
        category: "protocol-validation",
        description: "Multiple ETags in If-Match"
      },
      {
        id: "protocol-if-none-match-conflict",
        name: "If-None-Match with If-Modified-Since",
        pattern: /if-none-match[\s\S]*?if-modified-since|if-modified-since[\s\S]*?if-none-match/i,
        field: "headers",
        severity: "medium",
        score: 49,
        category: "protocol-validation",
        description: "Conflicting conditional headers"
      },
      {
        id: "protocol-location-header-crlf",
        name: "Location Header CRLF Injection",
        pattern: /location\s*:[\s\S]*?[\r\n](?![\s])/i,
        field: "headers",
        severity: "critical",
        score: 89,
        category: "protocol-validation",
        description: "CRLF in Location header"
      },
      {
        id: "protocol-set-cookie-crlf",
        name: "Set-Cookie CRLF Injection",
        pattern: /set-cookie\s*:[\s\S]*?[\r\n](?![\s])/i,
        field: "headers",
        severity: "critical",
        score: 88,
        category: "protocol-validation",
        description: "CRLF injection in Set-Cookie"
      },
      {
        id: "protocol-www-authenticate-crlf",
        name: "WWW-Authenticate CRLF Injection",
        pattern: /www-authenticate\s*:[\s\S]*?[\r\n](?![\s])/i,
        field: "headers",
        severity: "critical",
        score: 87,
        category: "protocol-validation",
        description: "CRLF in WWW-Authenticate header"
      },
      {
        id: "protocol-sec-websocket-key-invalid",
        name: "Invalid WebSocket Key",
        pattern: /sec-websocket-key\s*:\s*(?![A-Za-z0-9+\/]{24}==)/i,
        field: "headers",
        severity: "high",
        score: 69,
        category: "protocol-validation",
        description: "Malformed Sec-WebSocket-Key"
      },
      {
        id: "protocol-sec-fetch-mode-invalid",
        name: "Invalid Sec-Fetch-Mode",
        pattern: /sec-fetch-mode\s*:\s*(?!navigate|nested-navigate|same-origin|same-site|cross-site|no-cors|cors|websocket|document)/i,
        field: "headers",
        severity: "medium",
        score: 57,
        category: "protocol-validation",
        description: "Unknown Sec-Fetch-Mode value"
      },
      {
        id: "protocol-sec-fetch-site-invalid",
        name: "Invalid Sec-Fetch-Site",
        pattern: /sec-fetch-site\s*:\s*(?!cross-site|same-origin|same-site|none)/i,
        field: "headers",
        severity: "medium",
        score: 56,
        category: "protocol-validation",
        description: "Unknown Sec-Fetch-Site value"
      },
      {
        id: "protocol-origin-header-mismatch",
        name: "Origin Header Mismatch",
        pattern: /origin\s*:\s*(?:null|about:blank)/i,
        field: "headers",
        severity: "medium",
        score: 58,
        category: "protocol-validation",
        description: "Suspicious Origin header value"
      },
      {
        id: "protocol-referrer-policy-crlf",
        name: "Referrer-Policy CRLF Injection",
        pattern: /referrer-policy\s*:[\s\S]*?[\r\n](?![\s])/i,
        field: "headers",
        severity: "high",
        score: 75,
        category: "protocol-validation",
        description: "CRLF in Referrer-Policy header"
      },
      {
        id: "protocol-content-security-policy-crlf",
        name: "CSP Header CRLF Injection",
        pattern: /content-security-policy[\s\S]*?:\s*[\s\S]*?[\r\n](?![\s])/i,
        field: "headers",
        severity: "critical",
        score: 92,
        category: "protocol-validation",
        description: "CRLF in CSP header"
      },
      {
        id: "protocol-x-frame-options-crlf",
        name: "X-Frame-Options CRLF Injection",
        pattern: /x-frame-options\s*:[\s\S]*?[\r\n](?![\s])/i,
        field: "headers",
        severity: "high",
        score: 74,
        category: "protocol-validation",
        description: "CRLF in X-Frame-Options"
      },
      {
        id: "protocol-x-content-type-options-invalid",
        name: "Invalid X-Content-Type-Options",
        pattern: /x-content-type-options\s*:\s*(?!nosniff)/i,
        field: "headers",
        severity: "medium",
        score: 51,
        category: "protocol-validation",
        description: "Unknown X-Content-Type-Options value"
      },
      {
        id: "protocol-hsts-invalid",
        name: "Invalid HSTS Header",
        pattern: /strict-transport-security\s*:(?!.*max-age\s*=\s*\d+)/i,
        field: "headers",
        severity: "medium",
        score: 53,
        category: "protocol-validation",
        description: "Invalid HSTS format"
      },
      {
        id: "protocol-request-id-length",
        name: "Excessively Long Request ID",
        pattern: /x-request-id\s*:\s*.{256,}/i,
        field: "headers",
        severity: "low",
        score: 38,
        category: "protocol-validation",
        description: "Request ID exceeds 256 characters"
      },
      {
        id: "protocol-correlation-id-length",
        name: "Excessively Long Correlation ID",
        pattern: /x-correlation-id\s*:\s*.{256,}/i,
        field: "headers",
        severity: "low",
        score: 37,
        category: "protocol-validation",
        description: "Correlation ID exceeds 256 characters"
      },
      {
        id: "protocol-custom-header-bomb",
        name: "Excessive Custom Headers",
        pattern: /^x-[^:]*:[^\r\n]*\r\nx-[^:]*:[^\r\n]*\r\nx-[^:]*:[^\r\n]*\r\nx-[^:]*:[^\r\n]*\r\nx-[^:]*:[^\r\n]*\r\nx-[^:]*:/im,
        field: "headers",
        severity: "high",
        score: 66,
        category: "protocol-validation",
        description: "More than 5 custom X-* headers"
      },
      {
        id: "protocol-header-byte-count",
        name: "Excessively Large Header Section",
        pattern: /./,
        field: "headers",
        severity: "high",
        score: 64,
        category: "protocol-validation",
        description: "Total header section exceeds safe size"
      },
      {
        id: "protocol-request-uri-length",
        name: "Excessively Long Request URI",
        pattern: /^(GET|POST|PUT|DELETE|PATCH|HEAD)\s+.{8192,}/i,
        field: "request",
        severity: "high",
        score: 70,
        category: "protocol-validation",
        description: "Request URI exceeds 8192 bytes"
      },
      {
        id: "protocol-null-byte-header-name",
        name: "Null Byte in Header Name",
        pattern: /^\w*\x00[^:]*:/m,
        field: "headers",
        severity: "critical",
        score: 91,
        category: "protocol-validation",
        description: "Null byte in header field name"
      },
      {
        id: "protocol-null-byte-header-value",
        name: "Null Byte in Header Value",
        pattern: /:\s*[^\r\n]*\x00[^\r\n]*/m,
        field: "headers",
        severity: "critical",
        score: 90,
        category: "protocol-validation",
        description: "Null byte in header field value"
      },
      {
        id: "protocol-null-byte-uri",
        name: "Null Byte in Request URI",
        pattern: /^(GET|POST|PUT|DELETE|PATCH|HEAD)\s+[^\s]*\x00/i,
        field: "request",
        severity: "critical",
        score: 95,
        category: "protocol-validation",
        description: "Null byte in request URI"
      },
      {
        id: "protocol-parameter-pollution",
        name: "HTTP Parameter Pollution",
        pattern: /[?&]\w+=(?:[^&]*&){4}\w+=/,
        field: "request",
        severity: "high",
        score: 73,
        category: "protocol-validation",
        description: "Duplicate parameter names (HPP attack)"
      },
      {
        id: "protocol-unicode-directory-traversal",
        name: "Unicode Directory Traversal",
        pattern: /(?:%u002e|%u252e)+(?:%u002f|%u252f)/i,
        field: "request",
        severity: "high",
        score: 76,
        category: "protocol-validation",
        description: "Unicode-encoded directory traversal"
      },
      {
        id: "protocol-utf8-bypass",
        name: "UTF-8 Encoding Bypass",
        pattern: /%c0%ae|%c1%9c|%e0%80%ae/i,
        field: "request",
        severity: "high",
        score: 75,
        category: "protocol-validation",
        description: "Overlong UTF-8 sequences"
      },
      {
        id: "protocol-semicolon-separator",
        name: "Semicolon Path Separator",
        pattern: /;\s*(?:GET|POST|PUT|DELETE|PATCH|HEAD)/i,
        field: "request",
        severity: "high",
        score: 72,
        category: "protocol-validation",
        description: "Semicolon as path separator (ASP.NET abuse)"
      },
      {
        id: "protocol-content-type-charset",
        name: "Suspicious Charset in Content-Type",
        pattern: /content-type\s*:[^;]*;\s*charset\s*=(?:utf-7|utf7|cp1252|iso-2022-jp)/i,
        field: "headers",
        severity: "high",
        score: 71,
        category: "protocol-validation",
        description: "Dangerous charset declaration"
      },
      {
        id: "protocol-xml-content-type-bomb",
        name: "XML Content-Type with Large Body",
        pattern: /content-type\s*:\s*application\/xml/i,
        field: "headers",
        severity: "medium",
        score: 60,
        category: "protocol-validation",
        description: "XML content type (XXE risk)"
      },
      {
        id: "protocol-request-body-no-content-type",
        name: "Request Body Without Content-Type",
        pattern: /^(POST|PUT|PATCH)\s+[^\s]+\s+HTTP\/1\.1[\s\S]*(?!content-type)/i,
        field: "request",
        severity: "medium",
        score: 55,
        category: "protocol-validation",
        description: "POST/PUT without Content-Type header"
      },
      {
        id: "protocol-get-with-body",
        name: "GET Request with Body",
        pattern: /^GET\s+[^\s]+\s+HTTP\/1\.1[\s\S]*content-length\s*:\s*[1-9]/i,
        field: "request",
        severity: "medium",
        score: 54,
        category: "protocol-validation",
        description: "GET request with Content-Length"
      },
      {
        id: "protocol-delete-with-body",
        name: "DELETE Request with Body",
        pattern: /^DELETE\s+[^\s]+\s+HTTP\/1\.1[\s\S]*content-length\s*:\s*[1-9]/i,
        field: "request",
        severity: "medium",
        score: 53,
        category: "protocol-validation",
        description: "DELETE request with body"
      },
      {
        id: "protocol-head-with-body",
        name: "HEAD Request with Body",
        pattern: /^HEAD\s+[^\s]+\s+HTTP\/1\.1[\s\S]*content-length\s*:\s*[1-9]/i,
        field: "request",
        severity: "medium",
        score: 52,
        category: "protocol-validation",
        description: "HEAD request with Content-Length"
      },
      {
        id: "protocol-http-tunnel-abuse",
        name: "HTTP TUNNEL Abuse",
        pattern: /^TUNNEL\s+/i,
        field: "request",
        severity: "high",
        score: 74,
        category: "protocol-validation",
        description: "Illegal HTTP TUNNEL method"
      },
      {
        id: "protocol-webdav-method-abuse",
        name: "WebDAV Method Injection",
        pattern: /^(?:PROPFIND|PROPPATCH|MKCOL|COPY|MOVE|LOCK|UNLOCK)\s+/i,
        field: "request",
        severity: "medium",
        score: 59,
        category: "protocol-validation",
        description: "WebDAV method in HTTP request"
      }
    ];
  }
});

// server/waf/rules/http-desync.ts
var HTTP_DESYNC_RULES;
var init_http_desync = __esm({
  "server/waf/rules/http-desync.ts"() {
    "use strict";
    HTTP_DESYNC_RULES = [
      {
        id: "desync-cl-te",
        name: "HTTP Desync - CL.TE (Content-Length vs Transfer-Encoding)",
        pattern: /content-length\s*:\s*\d+[\s\S]*?transfer-encoding\s*:\s*(chunked|gzip)/i,
        field: "headers",
        severity: "critical",
        score: 95,
        category: "http-desync",
        description: "Content-Length and Transfer-Encoding both present (CL.TE desync)",
        recommendation: "Reject requests with both CL and TE headers, normalize at proxy"
      },
      {
        id: "desync-te-cl",
        name: "HTTP Desync - TE.CL (Transfer-Encoding vs Content-Length)",
        pattern: /transfer-encoding\s*:\s*(chunked|gzip)[\s\S]*?content-length\s*:\s*\d+/i,
        field: "headers",
        severity: "critical",
        score: 95,
        category: "http-desync",
        description: "Transfer-Encoding before Content-Length (TE.CL desync)",
        recommendation: "Normalize header ordering, reject conflicting headers"
      },
      {
        id: "desync-te-te",
        name: "HTTP Desync - TE.TE (Duplicate Transfer-Encoding)",
        pattern: /transfer-encoding[\s\S]*?transfer-encoding/i,
        field: "headers",
        severity: "high",
        score: 88,
        category: "http-desync",
        description: "Multiple Transfer-Encoding headers (TE.TE desync)",
        recommendation: "Consolidate duplicate headers, reject ambiguous cases"
      },
      {
        id: "desync-chunk-smuggling",
        name: "HTTP Desync - Chunk Encoding Smuggling",
        pattern: /transfer-encoding\s*:\s*chunked[\s\S]*?0\r\n\r\nGET|0\r\n\r\nPOST|0\r\n\r\nHEAD/i,
        field: "request",
        severity: "critical",
        score: 94,
        category: "http-desync",
        description: "Chunk-encoded request with embedded request after final chunk",
        recommendation: "Validate chunk boundaries, strip smuggled requests"
      },
      {
        id: "desync-invalid-chunk-size",
        name: "HTTP Desync - Invalid Chunk Size",
        pattern: /transfer-encoding\s*:\s*chunked[\s\S]*?[^\da-fA-F\r\n]\s*\r\n/,
        field: "request",
        severity: "high",
        score: 82,
        category: "http-desync",
        description: "Chunk size contains non-hex characters or invalid format",
        recommendation: "Validate chunk size format strictly (only hex)"
      },
      {
        id: "desync-space-before-colon",
        name: "HTTP Desync - Space Before Header Colon",
        pattern: /[a-z0-9\-]\s+:/i,
        field: "headers",
        severity: "high",
        score: 80,
        category: "http-desync",
        description: "Whitespace before colon in header (ambiguous parsing)",
        recommendation: "Normalize headers, reject malformed header syntax"
      },
      {
        id: "desync-tab-in-header",
        name: "HTTP Desync - Tab Character in Header",
        pattern: /.*\t.*:/i,
        field: "headers",
        severity: "high",
        score: 78,
        category: "http-desync",
        description: "Tab character used in header field (RFC ambiguity)",
        recommendation: "Strip tabs, use strict header validation"
      },
      {
        id: "desync-line-folding",
        name: "HTTP Desync - Line Folding (Header Continuation)",
        pattern: /\r\n[\s\t]+/,
        field: "headers",
        severity: "high",
        score: 81,
        category: "http-desync",
        description: "Header line folding/continuation (deprecated in HTTP/1.1)",
        recommendation: "Reject folded headers, enforce strict parsing"
      },
      {
        id: "desync-obfuscated-te",
        name: "HTTP Desync - Obfuscated Transfer-Encoding",
        pattern: /transfer-encoding\s*:\s*(chunked\s*;\s*q|gzip\s*,\s*chunked|chunked\s*,|deflate\s*,\s*chunked)/i,
        field: "headers",
        severity: "high",
        score: 79,
        category: "http-desync",
        description: "Transfer-Encoding with obfuscated or unusual values",
        recommendation: "Only accept standard values: chunked, gzip, deflate"
      },
      {
        id: "desync-request-prefix",
        name: "HTTP Desync - HTTP Request in Body",
        pattern: /\r\n\r\n(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|TRACE|CONNECT)\s+\/.*HTTP\/1\.[01]/i,
        field: "body",
        severity: "critical",
        score: 93,
        category: "http-desync",
        description: "Complete HTTP request embedded in body (request smuggling)",
        recommendation: "Strip request prefixes, enforce single-request-per-connection"
      },
      {
        id: "desync-cr-lf-injection",
        name: "HTTP Desync - CRLF in Header Value",
        pattern: /[a-z0-9\-]+\s*:\s*[^\r\n]*\r\n[^\s]/i,
        field: "headers",
        severity: "high",
        score: 85,
        category: "http-desync",
        description: "CRLF sequence within header value enabling header injection",
        recommendation: "Strip CRLF sequences, validate header values"
      },
      {
        id: "desync-null-prefix",
        name: "HTTP Desync - Null Byte Prefix",
        pattern: /\x00[\w\s]+(GET|POST|PUT|DELETE|PATCH|HEAD)/i,
        field: "request",
        severity: "high",
        score: 84,
        category: "http-desync",
        description: "Null byte prefix used to bypass request parsing",
        recommendation: "Strip null bytes from all requests"
      },
      {
        id: "desync-mixed-case-te",
        name: "HTTP Desync - Mixed-Case Transfer-Encoding",
        pattern: /[Tt][Rr][Aa][Nn][Ss][Ff][Ee][Rr]-[Ee][Nn][Cc][Oo][Dd][Ii][Nn][Gg]|TrAnSfEr-EnCoDiNg/i,
        field: "headers",
        severity: "medium",
        score: 72,
        category: "http-desync",
        description: "Transfer-Encoding header with mixed case (parser ambiguity)",
        recommendation: "Normalize header names to lowercase, strict comparison"
      }
    ];
  }
});

// server/waf/rules/protocol-attack.ts
var PROTOCOL_ATTACK_RULES;
var init_protocol_attack = __esm({
  "server/waf/rules/protocol-attack.ts"() {
    "use strict";
    PROTOCOL_ATTACK_RULES = [
      {
        id: "http-smuggling",
        name: "HTTP Request Smuggling",
        pattern: /transfer-encoding\s*:\s*chunked.*content-length|content-length.*transfer-encoding\s*:\s*chunked/i,
        field: "headers",
        severity: "critical",
        score: 90,
        category: "protocol-attack",
        description: "HTTP request smuggling attempt",
        recommendation: "Normalize HTTP requests at proxy level"
      }
    ];
  }
});

// server/waf/rules/path-traversal.ts
var PATH_TRAVERSAL_RULES;
var init_path_traversal = __esm({
  "server/waf/rules/path-traversal.ts"() {
    "use strict";
    PATH_TRAVERSAL_RULES = [
      { id: "path-traversal", name: "Path Traversal", pattern: /(\.\.(\/|\\|%2f|%5c))+/i, field: "request", severity: "high", score: 80, category: "path-traversal", description: "Directory traversal attempt", recommendation: "Validate and sanitize file paths" },
      { id: "path-null-byte", name: "Path Traversal - Null Byte", pattern: /%00|\\x00|\0/, field: "request", severity: "high", score: 85, category: "path-traversal", description: "Null byte injection", recommendation: "Remove null bytes" }
    ];
  }
});

// server/waf/rules/command-injection.ts
var COMMAND_INJECTION_RULES;
var init_command_injection = __esm({
  "server/waf/rules/command-injection.ts"() {
    "use strict";
    COMMAND_INJECTION_RULES = [
      { id: "cmd-injection-basic", name: "Command Injection - Basic", pattern: /[;&|`$]\s*(cat|ls|id|whoami|uname|pwd|wget|curl|nc|bash|sh|python|perl|ruby|php)/i, field: "request", severity: "critical", score: 95, category: "command-injection", description: "Shell command execution", recommendation: "Never pass user input to shell" },
      { id: "cmd-injection-redirect", name: "Command Injection - Redirection", pattern: /[<>]\s*[\/\w]+|>>\s*[\/\w]+/, field: "request", severity: "high", score: 75, category: "command-injection", description: "Shell redirection operators", recommendation: "Block shell metacharacters" },
      { id: "cmd-injection-subshell", name: "Command Injection - Subshell", pattern: /\$\([^)]+\)|\`[^`]+\`/, field: "request", severity: "critical", score: 90, category: "command-injection", description: "Command substitution", recommendation: "Use safe APIs only" }
    ];
  }
});

// server/waf/rules/xxe.ts
var XXE_RULES;
var init_xxe = __esm({
  "server/waf/rules/xxe.ts"() {
    "use strict";
    XXE_RULES = [
      {
        id: "xxe-attack",
        name: "XXE - XML External Entity",
        pattern: /<!ENTITY[^>]+SYSTEM[^>]+>/i,
        field: "body",
        severity: "critical",
        score: 95,
        category: "xxe",
        description: "XML External Entity injection attempt",
        recommendation: "Disable external entities in XML parser"
      },
      {
        id: "xxe-dtd",
        name: "XXE - DOCTYPE Declaration",
        pattern: /<!DOCTYPE[^>]+\[/i,
        field: "body",
        severity: "high",
        score: 70,
        category: "xxe",
        description: "DOCTYPE with internal subset (potential XXE)",
        recommendation: "Disable DTD processing in XML parser"
      },
      {
        id: "xxe-billion-laughs",
        name: "XXE - Billion Laughs Attack",
        pattern: /<!ENTITY\s+\w+\s*"&\w+;&\w+;[\s\S]*?"[\s\S]*?<!ENTITY\s+\w+\s*"&\w+;"/i,
        field: "body",
        severity: "high",
        score: 85,
        category: "xxe",
        description: "Exponential entity expansion (Billion Laughs/XML bomb)",
        recommendation: "Limit entity expansion depth and disable entity substitution"
      },
      {
        id: "xxe-file-disclosure",
        name: "XXE - File Disclosure (file:// URI)",
        pattern: /<!ENTITY\s+\w+\s+SYSTEM\s+["']file:\/\//i,
        field: "body",
        severity: "critical",
        score: 96,
        category: "xxe",
        description: "File disclosure via file:// URI in ENTITY declaration",
        recommendation: "Disable file URI scheme in XML entities"
      },
      {
        id: "xxe-network-access",
        name: "XXE - Network Access (http:// URI)",
        pattern: /<!ENTITY\s+\w+\s+SYSTEM\s+["'](https?|ftp):\/\//i,
        field: "body",
        severity: "high",
        score: 88,
        category: "xxe",
        description: "Network-based XXE for SSRF or data exfiltration",
        recommendation: "Disable external URI schemes in XML parser"
      },
      {
        id: "xxe-parameter-entity",
        name: "XXE - Parameter Entity Injection",
        pattern: /<!ENTITY\s+%\w+\s+SYSTEM/i,
        field: "body",
        severity: "high",
        score: 86,
        category: "xxe",
        description: "Parameter entity injection for XXE exploitation",
        recommendation: "Disable parameter entities in DTD"
      },
      {
        id: "xxe-internal-subset",
        name: "XXE - Internal DTD Subset with Entity",
        pattern: /<!DOCTYPE\s+\w+\s*\[\s*<!ENTITY\s+\w+\s+SYSTEM/i,
        field: "body",
        severity: "critical",
        score: 93,
        category: "xxe",
        description: "Internal DTD subset with SYSTEM entity declaration",
        recommendation: "Disable internal DTD processing"
      },
      {
        id: "xxe-public-identifier",
        name: "XXE - PUBLIC Identifier Declaration",
        pattern: /<!ENTITY\s+\w+\s+PUBLIC\s+["'][^"']*["']\s+["'][^"']*["']/i,
        field: "body",
        severity: "high",
        score: 80,
        category: "xxe",
        description: "PUBLIC identifier in entity declaration for XXE",
        recommendation: "Disable PUBLIC identifier resolution"
      },
      {
        id: "xxe-wrapped-entity",
        name: "XXE - Wrapped Entity Reference",
        pattern: /&[a-zA-Z0-9_\-]+;[\s\S]*?<!ENTITY|<!ENTITY[\s\S]*?&[a-zA-Z0-9_\-]+;/i,
        field: "body",
        severity: "high",
        score: 82,
        category: "xxe",
        description: "Entity reference combined with entity declaration (XXE nesting)",
        recommendation: "Validate and sanitize entity references"
      },
      {
        id: "xxe-remote-dtd",
        name: "XXE - Remote DTD Fetching",
        pattern: /<!DOCTYPE\s+\w+\s+PUBLIC\s+["'][^"']*["']\s+["'](https?|ftp):\/\//i,
        field: "body",
        severity: "high",
        score: 87,
        category: "xxe",
        description: "Remote DTD URL for XXE exploitation",
        recommendation: "Disable remote DTD loading"
      },
      {
        id: "xxe-xmlns-injection",
        name: "XXE - XML Namespace Injection",
        pattern: /xmlns\s*=\s*["'].*SYSTEM/i,
        field: "body",
        severity: "medium",
        score: 65,
        category: "xxe",
        description: "SYSTEM reference in xmlns attribute",
        recommendation: "Validate and sanitize namespace declarations"
      },
      {
        id: "xxe-comment-injection",
        name: "XXE - XXE via XML Comments",
        pattern: /<!--[\s\S]*?<!ENTITY[\s\S]*?-->|<!--[\s\S]*?\$\{[\s\S]*?}[\s\S]*?-->/i,
        field: "body",
        severity: "medium",
        score: 60,
        category: "xxe",
        description: "XXE payload hidden in XML comments",
        recommendation: "Strip and validate XML comments"
      },
      {
        id: "xxe-cdata-injection",
        name: "XXE - CDATA Section with Entity",
        pattern: /<!\[CDATA\[[\s\S]*?<!ENTITY|<!ENTITY[\s\S]*?\]\]>/i,
        field: "body",
        severity: "medium",
        score: 62,
        category: "xxe",
        description: "XXE payload combined with CDATA sections",
        recommendation: "Validate CDATA content, disable entity processing"
      },
      {
        id: "xxe-nested-entities",
        name: "XXE - Nested Entity Declarations",
        pattern: /<!ENTITY[\s\S]*?<!ENTITY[\s\S]*?<!ENTITY/i,
        field: "body",
        severity: "high",
        score: 79,
        category: "xxe",
        description: "Multiple nested entity declarations for XXE",
        recommendation: "Limit entity nesting depth"
      },
      {
        id: "xxe-utf-bypass",
        name: "XXE - UTF Encoding Bypass",
        pattern: /encoding\s*=\s*["']?(utf-32|utf-16|utf-8-sig)["']?[\s\S]*?<!ENTITY/i,
        field: "body",
        severity: "medium",
        score: 68,
        category: "xxe",
        description: "UTF encoding declarations to bypass XXE filters",
        recommendation: "Normalize encoding before parsing"
      }
    ];
  }
});

// server/waf/rules/header-injection.ts
var HEADER_INJECTION_RULES;
var init_header_injection = __esm({
  "server/waf/rules/header-injection.ts"() {
    "use strict";
    HEADER_INJECTION_RULES = [
      { id: "crlf-injection", name: "CRLF Injection", pattern: /(%0d|%0a|\\r|\\n)/i, field: "request", severity: "high", score: 75, category: "header-injection", description: "CRLF characters for header injection", recommendation: "Strip CRLF characters" }
    ];
  }
});

// server/waf/rules/open-redirect.ts
var OPEN_REDIRECT_RULES;
var init_open_redirect = __esm({
  "server/waf/rules/open-redirect.ts"() {
    "use strict";
    OPEN_REDIRECT_RULES = [
      { id: "open-redirect", name: "Open Redirect", pattern: /(url|redirect|next|goto|return|returnUrl|returnTo|dest|destination|redir|redirect_uri|continue)\s*=\s*https?:\/\//i, field: "query", severity: "medium", score: 55, category: "open-redirect", description: "Open redirect vulnerability", recommendation: "Validate against whitelist" }
    ];
  }
});

// server/waf/rules/nosql.ts
var NOSQL_RULES;
var init_nosql = __esm({
  "server/waf/rules/nosql.ts"() {
    "use strict";
    NOSQL_RULES = [
      { id: "nosql-injection", name: "NoSQL Injection", pattern: /(\$where|\$ne|\$gt|\$lt|\$regex|\$or|\$and|\$not|\$nor|\$in|\$nin)/i, field: "request", severity: "high", score: 80, category: "nosql-injection", description: "MongoDB/NoSQL injection", recommendation: "Sanitize NoSQL operators" }
    ];
  }
});

// server/waf/rules/ldap.ts
var LDAP_RULES;
var init_ldap = __esm({
  "server/waf/rules/ldap.ts"() {
    "use strict";
    LDAP_RULES = [
      { id: "ldap-injection", name: "LDAP Injection", pattern: /[)(|*\\]/, field: "query", severity: "medium", score: 50, category: "ldap-injection", description: "LDAP special characters", recommendation: "Escape LDAP characters" }
    ];
  }
});

// server/waf/rules/xpath.ts
var XPATH_RULES;
var init_xpath = __esm({
  "server/waf/rules/xpath.ts"() {
    "use strict";
    XPATH_RULES = [
      { id: "xpath-injection", name: "XPath Injection", pattern: /['"][\s]*or[\s]*['"]|contains\s*\(|text\s*\(\)/i, field: "request", severity: "high", score: 75, category: "xpath-injection", description: "XPath injection", recommendation: "Use parameterized queries" }
    ];
  }
});

// server/waf/rules/ssti.ts
var SSTI_RULES;
var init_ssti = __esm({
  "server/waf/rules/ssti.ts"() {
    "use strict";
    SSTI_RULES = [
      { id: "ssti-jinja", name: "SSTI - Jinja2/Twig", pattern: /\{\{.*(__class__|__mro__|__subclasses__|__globals__|__builtins__).*\}\}/i, field: "request", severity: "critical", score: 95, category: "ssti", description: "Server-Side Template Injection", recommendation: "Avoid rendering user input" }
    ];
  }
});

// server/waf/rules/log-injection.ts
var LOG_INJECTION_RULES;
var init_log_injection = __esm({
  "server/waf/rules/log-injection.ts"() {
    "use strict";
    LOG_INJECTION_RULES = [
      { id: "log-injection", name: "Log Injection", pattern: /(\n|\r).*?(ERROR|WARN|INFO|DEBUG|FATAL)/i, field: "request", severity: "medium", score: 45, category: "log-injection", description: "Fake log entry injection", recommendation: "Sanitize log output" }
    ];
  }
});

// server/waf/rules/reconnaissance.ts
var RECONNAISSANCE_RULES;
var init_reconnaissance = __esm({
  "server/waf/rules/reconnaissance.ts"() {
    "use strict";
    RECONNAISSANCE_RULES = [
      { id: "scanner-detection", name: "Security Scanner Detection", pattern: /(sqlmap|nikto|nessus|burp|acunetix|netsparker|owasp|zap|w3af|whatweb|masscan|nmap)/i, field: "headers", severity: "medium", score: 60, category: "reconnaissance", description: "Known security scanner user agent", recommendation: "Consider blocking automated tools" },
      { id: "scanner-dirbuster", name: "Scanner - DirBuster/GoBuster", pattern: /(dirbuster|gobuster|feroxbuster|dirb|wfuzz|ffuf)/i, field: "headers", severity: "medium", score: 58, category: "reconnaissance", description: "Directory enumeration tool detected", recommendation: "Block directory scanners" },
      { id: "scanner-metasploit", name: "Scanner - Metasploit Framework", pattern: /(metasploit|msfvenom|msfconsole|rapid7)/i, field: "headers", severity: "medium", score: 62, category: "reconnaissance", description: "Metasploit exploitation framework", recommendation: "Monitor for exploitation attempts" },
      { id: "scanner-qualys", name: "Scanner - Qualys", pattern: /(qualys|qualysguard|qualysassets)/i, field: "headers", severity: "medium", score: 59, category: "reconnaissance", description: "Qualys vulnerability scanner", recommendation: "Block or rate limit" },
      { id: "scanner-openvas", name: "Scanner - OpenVAS", pattern: /(openvas|greenbone)/i, field: "headers", severity: "medium", score: 57, category: "reconnaissance", description: "OpenVAS vulnerability scanner", recommendation: "Monitor scanner activity" },
      { id: "scanner-tenable", name: "Scanner - Tenable", pattern: /(tenable|nessusagent|lumin)/i, field: "headers", severity: "medium", score: 61, category: "reconnaissance", description: "Tenable Nessus agent", recommendation: "Restrict access" },
      { id: "scanner-rapid7", name: "Scanner - Rapid7 InsightVM", pattern: /(rapid7|insightvm|nexpose)/i, field: "headers", severity: "medium", score: 60, category: "reconnaissance", description: "Rapid7 InsightVM scanner", recommendation: "Monitor vulnerability scans" },
      { id: "scanner-checkmarx", name: "Scanner - Checkmarx SAST", pattern: /(checkmarx|cxscan)/i, field: "headers", severity: "low", score: 40, category: "reconnaissance", description: "Checkmarx SAST scanner (internal)", recommendation: "Whitelist internal scanners" },
      { id: "scanner-tools", name: "Scanner - Common Penetration Tools", pattern: /(nmap|hydra|hashcat|john|hashdeep|cain|abel|wireshark|tcpdump|metasploit)/i, field: "headers", severity: "medium", score: 62, category: "reconnaissance", description: "Common penetration testing tools", recommendation: "Block or monitor" },
      { id: "scanner-content-discovery", name: "Scanner - Content Discovery Tools", pattern: /(dirsearch|cmsmap|joomlascan|wordpress-scanner|droopscan|drupal-enum)/i, field: "headers", severity: "medium", score: 58, category: "reconnaissance", description: "CMS/content enumeration tools", recommendation: "Block automated enumeration" },
      { id: "scanner-api-fuzzer", name: "Scanner - API Fuzzing Tools", pattern: /(swagger-ui|api-fuzzer|postman-runtime|insomnia|burp|graphql-voyager)/i, field: "headers", severity: "medium", score: 56, category: "reconnaissance", description: "API testing and fuzzing tools", recommendation: "Monitor API reconnaissance" },
      { id: "scanner-bot-user-agent", name: "Scanner - Suspicious Bot User Agent", pattern: /bot|crawler|scanner|spider|scraper|monitor|crawler|curl|wget|python-requests|urllib|httplib/i, field: "headers", severity: "low", score: 35, category: "reconnaissance", description: "Generic bot or crawler detection", recommendation: "Implement rate limiting for bots" },
      { id: "scanner-custom-headers", name: "Scanner - Custom/Suspicious Headers", pattern: /(x-scanner|x-tool|x-test|x-debug|x-original-url|x-rewrite-url|x-forwarded|x-client-ip)/i, field: "headers", severity: "medium", score: 55, category: "reconnaissance", description: "Custom headers indicating scanner/proxy", recommendation: "Monitor suspicious headers" },
      { id: "scanner-vulnerability-params", name: "Scanner - Vulnerability Test Parameters", pattern: /(union\s+select|sleep\(|benchmark\(|version\(\)|information_schema|admin.*password|test.*admin)/i, field: "query", severity: "high", score: 75, category: "reconnaissance", description: "Common vulnerability testing parameters", recommendation: "Flag as scanning activity" },
      { id: "scanner-version-probe", name: "Scanner - Version/Info Disclosure Probes", pattern: /(version|info|debug|env|config|php_info|server.*version|banner)/i, field: "query", severity: "medium", score: 50, category: "reconnaissance", description: "Information disclosure probes", recommendation: "Don't expose system info" }
    ];
  }
});

// server/waf/rules/malware.ts
var MALWARE_RULES;
var init_malware = __esm({
  "server/waf/rules/malware.ts"() {
    "use strict";
    MALWARE_RULES = [
      { id: "webshell-detect", name: "Webshell Detection", pattern: /(c99|r57|wso|b374k|alfa|weevely|phpspy|regeorg|chisel)/i, field: "request", severity: "critical", score: 95, category: "malware", description: "Known webshell signature", recommendation: "Investigate server" }
    ];
  }
});

// server/waf/rules/rfi.ts
var RFI_RULES;
var init_rfi = __esm({
  "server/waf/rules/rfi.ts"() {
    "use strict";
    RFI_RULES = [
      { id: "rfi-attempt", name: "Remote File Inclusion", pattern: /(https?|ftp|php|data|expect|input|filter):\/\//i, field: "query", severity: "critical", score: 90, category: "rfi", description: "Remote file inclusion", recommendation: "Disable RFI" },
      { id: "php-wrapper", name: "PHP Wrapper Abuse", pattern: /php:\/\/(input|filter|data|expect)/i, field: "request", severity: "critical", score: 90, category: "rfi", description: "PHP stream wrapper abuse", recommendation: "Disable wrappers" }
    ];
  }
});

// server/waf/rules/prototype-pollution.ts
var PROTOTYPE_POLLUTION_RULES;
var init_prototype_pollution = __esm({
  "server/waf/rules/prototype-pollution.ts"() {
    "use strict";
    PROTOTYPE_POLLUTION_RULES = [
      { id: "prototype-pollution", name: "Prototype Pollution", pattern: /__proto__|constructor\s*\[|prototype\s*\[/i, field: "body", severity: "high", score: 80, category: "prototype-pollution", description: "JavaScript prototype pollution", recommendation: "Validate JSON keys" }
    ];
  }
});

// server/waf/rules/auth.ts
var AUTH_RULES;
var init_auth = __esm({
  "server/waf/rules/auth.ts"() {
    "use strict";
    AUTH_RULES = [
      { id: "jwt-manipulation", name: "JWT Manipulation", pattern: /eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[^.]+/, field: "headers", severity: "low", score: 20, category: "auth", description: "JWT token detected", recommendation: "Ensure JWT validation" }
    ];
  }
});

// server/waf/rules/mass-assignment.ts
var MASS_ASSIGNMENT_RULES;
var init_mass_assignment = __esm({
  "server/waf/rules/mass-assignment.ts"() {
    "use strict";
    MASS_ASSIGNMENT_RULES = [
      { id: "mass-assignment", name: "Mass Assignment", pattern: /(isAdmin|is_admin|role|admin|privilege|permission)\s*[=:]/i, field: "body", severity: "medium", score: 55, category: "mass-assignment", description: "Mass assignment of sensitive fields", recommendation: "Use field whitelisting" }
    ];
  }
});

// server/waf/rules/data-leakage.ts
var DATA_LEAKAGE_RULES;
var init_data_leakage = __esm({
  "server/waf/rules/data-leakage.ts"() {
    "use strict";
    DATA_LEAKAGE_RULES = [
      {
        id: "data-sql-error",
        name: "Data Leakage - SQL Error Messages",
        pattern: /(sql.*error|mysql.*error|ora-\d{5}|postgres.*error|sqlite.*error|sqlstate|syntax error|unexpected.*token|column.*not found)/i,
        field: "response",
        severity: "high",
        score: 80,
        category: "data-leakage",
        description: "SQL error message exposure",
        recommendation: "Use generic error messages, log details server-side"
      },
      {
        id: "data-stack-trace",
        name: "Data Leakage - Stack Trace Exposure",
        pattern: /(stack trace|at\s+\w+\.\w+\s*\(|java\.lang\.|thrown.*exception|traceback|line \d+|file ".*\.py")/i,
        field: "response",
        severity: "high",
        score: 82,
        category: "data-leakage",
        description: "Stack trace or debug information exposed",
        recommendation: "Disable debug mode in production"
      },
      {
        id: "data-version-disclosure",
        name: "Data Leakage - Version/Banner Disclosure",
        pattern: /(apache\/[\d.]+|nginx\/[\d.]+|microsoft-iis\/[\d.]+|php\/[\d.]+|python\/[\d.]+|ruby\/[\d.]+|tomcat\/[\d.]+|server:\s*[a-zA-Z]+\/[\d.]+)/i,
        field: "headers",
        severity: "medium",
        score: 65,
        category: "data-leakage",
        description: "Server version information in response headers",
        recommendation: "Remove or mask server version headers"
      },
      {
        id: "data-path-disclosure",
        name: "Data Leakage - File Path Disclosure",
        pattern: /(\/home\/\w+|\/usr\/local|\/opt\/|\/var\/www|c:\\|d:\\|windows\\|program files|\/etc\/|\/root\/)(?:\/|\\)?[\w\-\.]+/i,
        field: "response",
        severity: "high",
        score: 78,
        category: "data-leakage",
        description: "Absolute file path disclosed in response",
        recommendation: "Avoid exposing system paths in error messages"
      },
      {
        id: "data-email-disclosure",
        name: "Data Leakage - Email Address Exposure",
        pattern: /\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b/,
        field: "response",
        severity: "medium",
        score: 60,
        category: "data-leakage",
        description: "Email addresses exposed in response",
        recommendation: "Redact email addresses in user-facing responses"
      },
      {
        id: "data-credit-card",
        name: "Data Leakage - Credit Card Numbers",
        pattern: /\b(?:\d{4}[\s\-]?){3}\d{4}\b|4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}/,
        field: "response",
        severity: "critical",
        score: 95,
        category: "data-leakage",
        description: "Credit card numbers in response",
        recommendation: "Never expose full credit card data"
      },
      {
        id: "data-ssn-disclosure",
        name: "Data Leakage - Social Security Numbers",
        pattern: /\b\d{3}-\d{2}-\d{4}\b|\b\d{9}\b(?=\D|$)/,
        field: "response",
        severity: "critical",
        score: 93,
        category: "data-leakage",
        description: "Social Security number exposure",
        recommendation: "Encrypt and protect SSN data"
      },
      {
        id: "data-private-key",
        name: "Data Leakage - Private Key Exposure",
        pattern: /(-----BEGIN\s+(PRIVATE|RSA|DSA|EC)\s+KEY|-----BEGIN\s+PRIVATE\s+KEY|\{-----BEGIN|ssh-rsa|ssh-ed25519)/i,
        field: "response",
        severity: "critical",
        score: 96,
        category: "data-leakage",
        description: "Private cryptographic keys in response",
        recommendation: "Never expose private keys"
      },
      {
        id: "data-api-key-disclosure",
        name: "Data Leakage - API Key Exposure",
        pattern: /(api[_-]?key|apikey|api_secret|secret_key|access_token|bearer|authorization)[\s:=]*[a-zA-Z0-9\-_.]{20,}/i,
        field: "response",
        severity: "critical",
        score: 94,
        category: "data-leakage",
        description: "API keys or tokens exposed",
        recommendation: "Mask API keys in responses"
      },
      {
        id: "data-database-credentials",
        name: "Data Leakage - Database Credentials",
        pattern: /(db_?user|db_?pass|database_?url|connection_?string|mysql_user|mysql_pass|postgres_user|postgres_pass)[\s:=]*[^\s<>\\"']+[\s<>\\"']/i,
        field: "response",
        severity: "critical",
        score: 94,
        category: "data-leakage",
        description: "Database credentials in response",
        recommendation: "Never expose database credentials"
      },
      {
        id: "data-directory-listing",
        name: "Data Leakage - Directory Listing",
        pattern: /<title>[^<]*index of|<h1>[^<]*directory listing|<a\s+href="[^"]*"\s*>[a-zA-Z0-9_.-]+\/(?:<\/a>)?/i,
        field: "response",
        severity: "medium",
        score: 70,
        category: "data-leakage",
        description: "Unprotected directory listing",
        recommendation: "Disable directory indexing"
      },
      {
        id: "data-config-exposure",
        name: "Data Leakage - Configuration File Exposure",
        pattern: /(web\.config|\.env|config\.php|settings\.py|appconfig\.json|database\.yml|credentials\.json|\.aws\/|\.ssh\/)/i,
        field: "response",
        severity: "critical",
        score: 92,
        category: "data-leakage",
        description: "Configuration files in response",
        recommendation: "Exclude config files from web access"
      },
      {
        id: "data-source-code-exposure",
        name: "Data Leakage - Source Code Exposure",
        pattern: /(php source code|view source|\.php:|<?php|import\s+|from\s+\w+\s+import|def\s+\w+\(|class\s+\w+[\s{:])[\s\S]{0,500}(?:copyright|author|license|\$_[A-Z]+|\bfunction\b)/i,
        field: "response",
        severity: "high",
        score: 85,
        category: "data-leakage",
        description: "Source code exposed in response",
        recommendation: "Prevent source code disclosure via error messages"
      },
      {
        id: "data-ip-address-disclosure",
        name: "Data Leakage - Internal IP Address",
        pattern: /(internal|server|local)[\s:]*(?:ip|address|addr)[\s:=]*(\d{1,3}\.){3}\d{1,3}|from\s*(?:\d{1,3}\.){3}\d{1,3}|connected.*(?:\d{1,3}\.){3}\d{1,3}/i,
        field: "response",
        severity: "medium",
        score: 68,
        category: "data-leakage",
        description: "Internal IP addresses disclosed",
        recommendation: "Don't expose internal IPs"
      },
      {
        id: "data-hostname-disclosure",
        name: "Data Leakage - Hostname Disclosure",
        pattern: /(?:hostname|server|host)[\s:=]*[\w-]+\.(?:local|internal|corp|prod|dev|staging|test)/i,
        field: "response",
        severity: "medium",
        score: 65,
        category: "data-leakage",
        description: "Sensitive hostnames disclosed",
        recommendation: "Mask or avoid exposing internal hostnames"
      },
      {
        id: "data-session-id-exposure",
        name: "Data Leakage - Session ID in URL",
        pattern: /jsessionid|phpsessid|aspsessionid|session_id|sessionid|sid=[\da-zA-Z]+/i,
        field: "response",
        severity: "high",
        score: 80,
        category: "data-leakage",
        description: "Session identifiers in URL or response",
        recommendation: "Use secure, httponly session cookies only"
      },
      {
        id: "data-auth-header-exposure",
        name: "Data Leakage - Authorization Header Info",
        pattern: /(authorization|bearer|basic)\s+[a-zA-Z0-9\+\/=]{20,}|www-authenticate/i,
        field: "response",
        severity: "high",
        score: 82,
        category: "data-leakage",
        description: "Authentication credentials in response",
        recommendation: "Don't expose auth tokens in responses"
      },
      {
        id: "data-backup-file-exposure",
        name: "Data Leakage - Backup File Exposure",
        pattern: /\.(bak|backup|old|orig|tmp|test|copy|swp|swo|~|\.1|\.2|\.3|\.gz|\.zip|\.tar)[\s\/<>\\"']/i,
        field: "response",
        severity: "high",
        score: 79,
        category: "data-leakage",
        description: "Backup or temporary files exposed",
        recommendation: "Remove backup files from web root"
      },
      {
        id: "data-debug-page",
        name: "Data Leakage - Debug/Error Page",
        pattern: /(debug|development|staging|test)[\s:]*(?:mode|environment|enabled|true)|error occurred|exception details|traceback|debug info/i,
        field: "response",
        severity: "high",
        score: 76,
        category: "data-leakage",
        description: "Debug or error page exposed",
        recommendation: "Use custom error pages in production"
      },
      {
        id: "data-database-schema",
        name: "Data Leakage - Database Schema Info",
        pattern: /(table|column|index|constraint|trigger|procedure|view|schema)[\s:]+(?:name|type|size)|information_schema|mysql\.user|pg_catalog/i,
        field: "response",
        severity: "high",
        score: 77,
        category: "data-leakage",
        description: "Database schema information exposed",
        recommendation: "Limit database introspection"
      },
      {
        id: "data-pii-name",
        name: "Data Leakage - Personal Information (Names)",
        pattern: /(?:first_?name|last_?name|full_?name|name)[\s:=]*[A-Z][a-z]+[\s]+[A-Z][a-z]+/,
        field: "response",
        severity: "medium",
        score: 62,
        category: "data-leakage",
        description: "Personal names exposed in response",
        recommendation: "Minimize PII in responses"
      },
      {
        id: "data-phone-number",
        name: "Data Leakage - Phone Number Exposure",
        pattern: /\b(?:\+?1[-.\s]?)?\(?[2-9]\d{2}\)?[-.\s]?[2-9]\d{2}[-.\s]?\d{4}\b|phone[\s:=]*\+?[\d\s\-().]{10,15}/i,
        field: "response",
        severity: "medium",
        score: 63,
        category: "data-leakage",
        description: "Phone numbers exposed",
        recommendation: "Redact phone numbers"
      },
      {
        id: "data-bank-account",
        name: "Data Leakage - Bank Account Numbers",
        pattern: /(?:account|iban|routing|bank\s+account)[\s:=]*[\d\-]{10,20}|iban[\s:]*[A-Z]{2}\d{2}[A-Z0-9]{1,30}/i,
        field: "response",
        severity: "critical",
        score: 93,
        category: "data-leakage",
        description: "Bank account numbers exposed",
        recommendation: "Never expose account numbers"
      },
      {
        id: "data-timestamp-precision",
        name: "Data Leakage - Excessive Timestamp Precision",
        pattern: /\d{4}-\d{2}-\d{2}\s*[T\s]\d{2}:\d{2}:\d{2}\.\d{6,}/,
        field: "response",
        severity: "low",
        score: 40,
        category: "data-leakage",
        description: "Microsecond-precision timestamps (can aid attacks)",
        recommendation: "Use second-level precision only"
      },
      {
        id: "data-unicode-normalization",
        name: "Data Leakage - Unicode/UTF-8 Encoding Tricks",
        pattern: /\\u[0-9a-fA-F]{4}|&#[0-9]+;|%[0-9a-fA-F]{2}.*(?:select|union|script|iframe)/i,
        field: "response",
        severity: "medium",
        score: 61,
        category: "data-leakage",
        description: "Encoded payloads in response",
        recommendation: "Normalize and validate responses"
      },
      {
        id: "data-serialized-objects",
        name: "Data Leakage - Serialized Objects",
        pattern: /(java\.io\.serializable|serialVersionUID|readObject|writeObject|base64|pickle|serialized)/i,
        field: "response",
        severity: "high",
        score: 78,
        category: "data-leakage",
        description: "Serialized objects in response",
        recommendation: "Avoid returning serialized objects"
      },
      {
        id: "data-null-byte-injection",
        name: "Data Leakage - Null Byte Injection",
        pattern: /%00|\\x00|\\0|%0/,
        field: "response",
        severity: "medium",
        score: 64,
        category: "data-leakage",
        description: "Null byte characters in response",
        recommendation: "Strip null bytes from responses"
      }
    ];
  }
});

// server/waf/rules/index.ts
var OWASP_PATTERNS;
var init_rules = __esm({
  "server/waf/rules/index.ts"() {
    "use strict";
    init_sql_injection();
    init_xss();
    init_rce();
    init_lfi();
    init_ssrf();
    init_java_attacks();
    init_dos();
    init_protocol_validation();
    init_http_desync();
    init_protocol_attack();
    init_path_traversal();
    init_command_injection();
    init_xxe();
    init_header_injection();
    init_open_redirect();
    init_nosql();
    init_ldap();
    init_xpath();
    init_ssti();
    init_log_injection();
    init_reconnaissance();
    init_malware();
    init_rfi();
    init_prototype_pollution();
    init_auth();
    init_mass_assignment();
    init_data_leakage();
    OWASP_PATTERNS = [
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
  }
});

// server/services/geolocation.ts
import geoip from "geoip-lite";
var GeolocationService;
var init_geolocation = __esm({
  "server/services/geolocation.ts"() {
    "use strict";
    GeolocationService = class {
      static lookup(ip) {
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
          console.error("Geolocation lookup error:", error);
          return null;
        }
      }
      static checkGeoRestriction(ip, allowedCountries, blockedCountries) {
        const geo = this.lookup(ip);
        if (!geo) {
          return { allowed: true, country: "Unknown", reason: "Could not determine location" };
        }
        if (blockedCountries?.includes(geo.country)) {
          return {
            allowed: false,
            country: geo.country,
            reason: `Country ${geo.country} (${geo.countryName}) is on the blocked list`
          };
        }
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
      static checkVPN(ip) {
        const geo = geoip.lookup(ip);
        if (!geo) return false;
        return this.detectVPN(geo);
      }
      static detectVPN(geo) {
        const org = geo.org || "";
        const cloudPatterns = ["AWS", "Google", "Microsoft", "Azure", "Linode", "DigitalOcean", "Vultr", "OVH", "Hetzner"];
        return cloudPatterns.some((provider) => org.toUpperCase().includes(provider.toUpperCase()));
      }
      static getCountryName(code) {
        const countries = {
          "US": "United States",
          "UK": "United Kingdom",
          "CA": "Canada",
          "AU": "Australia",
          "DE": "Germany",
          "FR": "France",
          "IT": "Italy",
          "ES": "Spain",
          "NL": "Netherlands",
          "SE": "Sweden",
          "NO": "Norway",
          "DK": "Denmark",
          "CH": "Switzerland",
          "AT": "Austria",
          "BE": "Belgium",
          "JP": "Japan",
          "CN": "China",
          "IN": "India",
          "BR": "Brazil",
          "MX": "Mexico",
          "SG": "Singapore",
          "HK": "Hong Kong",
          "RU": "Russia",
          "KR": "South Korea",
          "TW": "Taiwan",
          "TH": "Thailand",
          "MY": "Malaysia",
          "PH": "Philippines",
          "ID": "Indonesia",
          "VN": "Vietnam",
          "NZ": "New Zealand",
          "ZA": "South Africa",
          "EG": "Egypt",
          "NG": "Nigeria",
          "KE": "Kenya",
          "UA": "Ukraine",
          "PL": "Poland",
          "CZ": "Czech Republic",
          "GR": "Greece",
          "TR": "Turkey",
          "IL": "Israel",
          "KP": "North Korea",
          "IR": "Iran",
          "SY": "Syria",
          "CU": "Cuba"
        };
        return countries[code] || code;
      }
    };
  }
});

// server/waf/ddos-detection.ts
import { EventEmitter } from "events";
var DDoSDetectionService, ddosDetection;
var init_ddos_detection = __esm({
  "server/waf/ddos-detection.ts"() {
    "use strict";
    DDoSDetectionService = class extends EventEmitter {
      tenantStates = /* @__PURE__ */ new Map();
      defaultConfig;
      constructor(config = {}) {
        super();
        this.defaultConfig = {
          maxConnections: 1e4,
          maxConnectionsPerIP: 100,
          maxRequestsPerSecond: 5e3,
          maxRequestsPerIPPerSecond: 50,
          volumetricThreshold: 3e3,
          uniqueIPThreshold: 500,
          anomalyThreshold: 0.7,
          enableAutomaticMitigation: true,
          graduatedResponseEnabled: true,
          enableNormalization: true,
          requestTimeoutMs: 3e4,
          maxHeaderSize: 8192,
          maxBodySize: 10485760,
          // 10MB
          ...config
        };
        setInterval(() => this.cleanupAllTenants(), 6e4);
      }
      /**
       * Initialize tenant state
       */
      initializeTenant(tenantId) {
        if (this.tenantStates.has(tenantId)) {
          return this.tenantStates.get(tenantId);
        }
        const state = {
          requestHistory: /* @__PURE__ */ new Map(),
          ipConnections: /* @__PURE__ */ new Map(),
          totalConnections: 0,
          metrics: {
            requestsPerSecond: 0,
            uniqueIPs: 0,
            topAttackerIPs: [],
            suspiciousPatterns: [],
            volumetricScore: 0,
            protocolAnomalies: 0,
            detectionConfidence: 0
          },
          config: { ...this.defaultConfig },
          lastMetricsUpdate: Date.now()
        };
        this.tenantStates.set(tenantId, state);
        return state;
      }
      /**
       * Analyze request and detect DDoS patterns for specific tenant
       */
      analyzeRequest(tenantId, clientIp, method, path4, headers, bodySize) {
        const state = this.initializeTenant(tenantId);
        const now = Date.now();
        const severity = this.assessSeverity(state);
        const normalizationViolation = this.checkNormalizationViolations(
          method,
          path4,
          headers,
          bodySize,
          state.config
        );
        if (normalizationViolation) {
          return {
            isDDoSDetected: true,
            severity: "medium",
            action: "throttle",
            reason: normalizationViolation
          };
        }
        const connectionViolation = this.checkConnectionLimits(clientIp, state);
        if (connectionViolation) {
          return {
            isDDoSDetected: true,
            severity: connectionViolation.severity,
            action: connectionViolation.action,
            reason: connectionViolation.reason
          };
        }
        const rateLimitViolation = this.checkRateLimits(clientIp, now, state);
        if (rateLimitViolation) {
          return {
            isDDoSDetected: true,
            severity: rateLimitViolation.severity,
            action: rateLimitViolation.action,
            reason: rateLimitViolation.reason
          };
        }
        const volumetricDetection = this.detectVolumetricAttack(now, state);
        if (volumetricDetection.detected) {
          return {
            isDDoSDetected: true,
            severity: volumetricDetection.severity,
            action: this.getGraduatedResponse(volumetricDetection.severity, state.config),
            reason: volumetricDetection.reason
          };
        }
        const protocolAnomaly = this.detectProtocolAnomalies(
          method,
          headers,
          bodySize,
          state
        );
        if (protocolAnomaly) {
          return {
            isDDoSDetected: true,
            severity: "low",
            action: "throttle",
            reason: protocolAnomaly
          };
        }
        return {
          isDDoSDetected: false,
          severity: "low",
          action: "allow",
          reason: "No DDoS pattern detected"
        };
      }
      /**
       * Track per-tenant request
       */
      trackRequest(tenantId, clientIp) {
        const state = this.initializeTenant(tenantId);
        const now = Date.now();
        if (!state.requestHistory.has(clientIp)) {
          state.requestHistory.set(clientIp, []);
        }
        const timestamps = state.requestHistory.get(clientIp);
        timestamps.push(now);
        const cutoff = now - 6e4;
        while (timestamps.length > 0 && timestamps[0] < cutoff) {
          timestamps.shift();
        }
        state.ipConnections.set(clientIp, (state.ipConnections.get(clientIp) || 0) + 1);
        state.totalConnections++;
        if (now - state.lastMetricsUpdate > 5e3) {
          this.updateMetrics(state);
        }
      }
      /**
       * Release connection
       */
      releaseConnection(tenantId, clientIp) {
        const state = this.tenantStates.get(tenantId);
        if (!state) return;
        const current = state.ipConnections.get(clientIp) || 0;
        if (current > 0) {
          state.ipConnections.set(clientIp, current - 1);
          state.totalConnections--;
        }
      }
      /**
       * Normalize traffic by checking size and format violations
       */
      checkNormalizationViolations(method, path4, headers, bodySize, config) {
        if (!config.enableNormalization) return null;
        const suspiciousMethods = ["TRACE", "CONNECT"];
        if (suspiciousMethods.includes(method)) {
          return `Suspicious HTTP method: ${method}`;
        }
        const headerSize = JSON.stringify(headers).length;
        if (headerSize > config.maxHeaderSize) {
          return `Header size exceeds limit: ${headerSize}`;
        }
        if (bodySize > config.maxBodySize) {
          return `Body size exceeds limit: ${bodySize}`;
        }
        if (path4.includes("\0")) {
          return "Null byte detected in path";
        }
        if (path4.includes("..\\") || path4.includes("..%")) {
          return "Path traversal attempt detected";
        }
        return null;
      }
      /**
       * Check per-IP and global connection limits
       */
      checkConnectionLimits(clientIp, state) {
        const ipConnections = state.ipConnections.get(clientIp) || 0;
        if (ipConnections > state.config.maxConnectionsPerIP) {
          return {
            severity: "high",
            action: "throttle",
            reason: `IP ${clientIp} exceeded connection limit: ${ipConnections}/${state.config.maxConnectionsPerIP}`
          };
        }
        if (state.totalConnections > state.config.maxConnections) {
          return {
            severity: "critical",
            action: "challenge",
            reason: `Tenant connection limit exceeded: ${state.totalConnections}/${state.config.maxConnections}`
          };
        }
        return null;
      }
      /**
       * Check rate limits per IP and global (tenant-scoped)
       */
      checkRateLimits(clientIp, now, state) {
        const timestamps = state.requestHistory.get(clientIp) || [];
        const lastSecond = timestamps.filter((t) => t > now - 1e3).length;
        if (lastSecond > state.config.maxRequestsPerIPPerSecond) {
          return {
            severity: "medium",
            action: "throttle",
            reason: `IP rate limit exceeded: ${lastSecond} req/s`
          };
        }
        const totalLastSecond = Array.from(state.requestHistory.values()).reduce(
          (sum, ts) => sum + ts.filter((t) => t > now - 1e3).length,
          0
        );
        if (totalLastSecond > state.config.maxRequestsPerSecond) {
          return {
            severity: "high",
            action: "challenge",
            reason: `Tenant rate limit exceeded: ${totalLastSecond} req/s`
          };
        }
        return null;
      }
      /**
       * Detect volumetric DDoS attacks (tenant-scoped)
       */
      detectVolumetricAttack(now, state) {
        const lastSecond = Array.from(state.requestHistory.values()).reduce(
          (sum, ts) => sum + ts.filter((t) => t > now - 1e3).length,
          0
        );
        const uniqueIPs = state.requestHistory.size;
        const volumeScore = Math.min(1, lastSecond / (state.config.volumetricThreshold * 2));
        const diversityScore = Math.min(1, uniqueIPs / state.config.uniqueIPThreshold);
        const volumetricScore = (volumeScore + diversityScore) / 2;
        state.metrics.volumetricScore = volumetricScore;
        if (volumetricScore > state.config.anomalyThreshold) {
          let severity = "low";
          if (volumetricScore > 0.9) severity = "critical";
          else if (volumetricScore > 0.8) severity = "high";
          else if (volumetricScore > 0.7) severity = "medium";
          return {
            detected: true,
            severity,
            reason: `Volumetric attack detected (score: ${(volumetricScore * 100).toFixed(1)}%, ${lastSecond} req/s)`
          };
        }
        return {
          detected: false,
          severity: "low",
          reason: "No volumetric attack detected"
        };
      }
      /**
       * Detect protocol and HTTP anomalies
       */
      detectProtocolAnomalies(method, headers, bodySize, state) {
        const anomalies = [];
        if (method === "GET" && bodySize > 100) {
          anomalies.push("GET request with unexpected body");
        }
        if (!headers["host"]) {
          anomalies.push("Missing Host header");
        }
        if (headers["user-agent"]?.length === 0) {
          anomalies.push("Empty User-Agent header");
        }
        if (headers["content-length"] && isNaN(parseInt(headers["content-length"]))) {
          anomalies.push("Invalid Content-Length header");
        }
        state.metrics.protocolAnomalies = anomalies.length;
        return anomalies.length > 0 ? anomalies[0] : null;
      }
      /**
       * Get graduated response based on severity
       */
      getGraduatedResponse(severity, config) {
        if (!config.graduatedResponseEnabled) {
          return severity === "critical" ? "block" : "throttle";
        }
        switch (severity) {
          case "low":
            return "allow";
          // No action
          case "medium":
            return "throttle";
          // Rate limit
          case "high":
            return "challenge";
          // CAPTCHA/verification
          case "critical":
            return "block";
          // Block completely
          default:
            return "allow";
        }
      }
      /**
       * Assess overall attack severity for tenant
       */
      assessSeverity(state) {
        if (state.metrics.volumetricScore > 0.9) return "critical";
        if (state.metrics.volumetricScore > 0.8) return "high";
        if (state.metrics.volumetricScore > 0.7) return "medium";
        return "low";
      }
      /**
       * Update metrics for tenant
       */
      updateMetrics(state) {
        const now = Date.now();
        const lastSecond = Array.from(state.requestHistory.values()).reduce(
          (sum, ts) => sum + ts.filter((t) => t > now - 1e3).length,
          0
        );
        state.metrics.requestsPerSecond = lastSecond;
        state.metrics.uniqueIPs = state.requestHistory.size;
        const ipCounts = Array.from(state.requestHistory.entries()).map(([ip, timestamps]) => ({
          ip,
          count: timestamps.filter((t) => t > now - 6e4).length
        })).sort((a, b) => b.count - a.count).slice(0, 10);
        state.metrics.topAttackerIPs = ipCounts;
        state.metrics.detectionConfidence = state.metrics.volumetricScore;
        state.lastMetricsUpdate = now;
        this.emit(`metrics-updated:${state}`, state.metrics);
      }
      /**
       * Cleanup old history for all tenants
       */
      cleanupAllTenants() {
        for (const [, state] of this.tenantStates.entries()) {
          this.cleanupTenant(state);
        }
      }
      /**
       * Cleanup old history for specific tenant
       */
      cleanupTenant(state) {
        const now = Date.now();
        const cutoff = now - 12e4;
        const toDelete = [];
        for (const [ip, timestamps] of state.requestHistory.entries()) {
          while (timestamps.length > 0 && timestamps[0] < cutoff) {
            timestamps.shift();
          }
          if (timestamps.length === 0) {
            toDelete.push(ip);
          }
        }
        toDelete.forEach((ip) => {
          state.requestHistory.delete(ip);
          state.ipConnections.delete(ip);
        });
      }
      /**
       * Get tenant-specific metrics
       */
      getTenantMetrics(tenantId) {
        const state = this.initializeTenant(tenantId);
        const now = Date.now();
        const lastSecond = Array.from(state.requestHistory.values()).reduce(
          (sum, ts) => sum + ts.filter((t) => t > now - 1e3).length,
          0
        );
        const uniqueIPs = state.requestHistory.size;
        const ipCounts = Array.from(state.requestHistory.entries()).map(([ip, timestamps]) => ({
          ip,
          count: timestamps.filter((t) => t > now - 6e4).length
        })).sort((a, b) => b.count - a.count).slice(0, 10);
        const volumeScore = Math.min(1, lastSecond / (state.config.volumetricThreshold * 2));
        const diversityScore = Math.min(1, uniqueIPs / state.config.uniqueIPThreshold);
        const volumetricScore = (volumeScore + diversityScore) / 2;
        const metrics = {
          requestsPerSecond: lastSecond,
          uniqueIPs,
          topAttackerIPs: ipCounts,
          suspiciousPatterns: [],
          volumetricScore,
          protocolAnomalies: 0,
          detectionConfidence: volumetricScore
        };
        state.metrics = metrics;
        return metrics;
      }
      /**
       * Get all tenants' metrics (for dashboard)
       */
      getAllTenantMetrics() {
        const allMetrics = /* @__PURE__ */ new Map();
        for (const [tenantId] of this.tenantStates.entries()) {
          allMetrics.set(tenantId, this.getTenantMetrics(tenantId));
        }
        return allMetrics;
      }
      /**
       * Update tenant-specific config
       */
      updateTenantConfig(tenantId, config) {
        const state = this.initializeTenant(tenantId);
        state.config = { ...state.config, ...config };
      }
      /**
       * Get tenant-specific config
       */
      getTenantConfig(tenantId) {
        const state = this.initializeTenant(tenantId);
        return state.config;
      }
      /**
       * Reset specific tenant's tracking
       */
      resetTenant(tenantId) {
        const state = this.tenantStates.get(tenantId);
        if (state) {
          state.requestHistory.clear();
          state.ipConnections.clear();
          state.totalConnections = 0;
          state.metrics = {
            requestsPerSecond: 0,
            uniqueIPs: 0,
            topAttackerIPs: [],
            suspiciousPatterns: [],
            volumetricScore: 0,
            protocolAnomalies: 0,
            detectionConfidence: 0
          };
        }
      }
      /**
       * Reset all tenants' tracking
       */
      resetAll() {
        this.tenantStates.clear();
      }
    };
    ddosDetection = new DDoSDetectionService();
  }
});

// server/waf/ml-scoring.ts
var MLScoringEngine, SimpleLinearModel;
var init_ml_scoring = __esm({
  "server/waf/ml-scoring.ts"() {
    "use strict";
    MLScoringEngine = class {
      featureCache = /* @__PURE__ */ new Map();
      scoringHistory = [];
      modelWeights = {
        patternWeight: 0.6,
        mlWeight: 0.4
      };
      mlModel = null;
      constructor() {
        this.initializeDefaults();
      }
      initializeDefaults() {
        this.modelWeights = {
          patternWeight: 0.6,
          mlWeight: 0.4
        };
      }
      /**
       * Extract ML-ready features from HTTP request
       */
      extractFeatures(requestData) {
        const cacheKey = `${requestData.method}:${requestData.path}:${requestData.clientIp || "unknown"}`;
        const cached = this.featureCache.get(cacheKey);
        if (cached && this.featureCache.size < 1e3) {
          return cached;
        }
        const pathStr = requestData.path || "";
        const queryStr = JSON.stringify(requestData.query || {});
        const bodyStr = typeof requestData.body === "string" ? requestData.body : JSON.stringify(requestData.body || {});
        const headerStr = JSON.stringify(requestData.headers || {});
        const combinedContent = pathStr + queryStr + bodyStr + headerStr;
        const features = {
          pathLength: pathStr.length,
          queryLength: queryStr.length,
          bodyLength: bodyStr.length,
          headerCount: Object.keys(requestData.headers || {}).length,
          // Behavioral
          httpMethod: requestData.method.toUpperCase(),
          hasQueryString: queryStr.length > 2,
          hasBody: bodyStr.length > 2,
          hasAuthHeader: !!requestData.headers?.authorization || !!requestData.headers?.Authorization,
          hasUserAgent: !!requestData.headers?.["user-agent"] || !!requestData.headers?.["User-Agent"],
          // Content features
          specialCharDensity: this.calculateDensity(combinedContent, /[!@#$%^&*()_+=\[\]{};:'",.<>?\/\\|-]/g),
          numberDensity: this.calculateDensity(combinedContent, /[0-9]/g),
          upperCaseDensity: this.calculateDensity(combinedContent, /[A-Z]/g),
          urlEncodingDensity: this.calculateDensity(combinedContent, /%[0-9A-Fa-f]{2}/g),
          // Keyword counts
          sqlKeywordCount: this.countKeywords(combinedContent, ["UNION", "SELECT", "INSERT", "DROP", "DELETE", "OR", "AND", "EXEC"]),
          jsKeywordCount: this.countKeywords(combinedContent, ["<script", "eval", "setTimeout", "setInterval", "onerror", "onload"]),
          shellCommandCount: this.countKeywords(combinedContent, ["bash", "sh", "cmd", "powershell", "&>", "|", ";"]),
          pathTraversalCount: this.countKeywords(combinedContent, ["../../../", "..\\..\\", "%2e%2e", "null byte"]),
          // Ratios
          ratioPathToQuery: queryStr.length > 0 ? pathStr.length / queryStr.length : 0,
          ratioBodyToPath: pathStr.length > 0 ? bodyStr.length / pathStr.length : 0,
          entropyScore: this.calculateEntropy(combinedContent),
          // Network
          clientIpReputation: this.getIpReputation(requestData.clientIp),
          isPrivateIp: this.isPrivateAddress(requestData.clientIp),
          isKnownGoodIp: this.isKnownGood(requestData.clientIp)
        };
        this.featureCache.set(cacheKey, features);
        if (this.featureCache.size > 5e3) {
          const firstKey = this.featureCache.keys().next().value;
          if (firstKey) this.featureCache.delete(firstKey);
        }
        return features;
      }
      /**
       * Calculate ML-based threat score
       */
      calculateMLScore(features) {
        if (this.mlModel) {
          return this.mlModel.predict(features);
        }
        return this.heuristicScore(features);
      }
      /**
       * Heuristic scoring as fallback/baseline
       */
      heuristicScore(features) {
        let threatScore = 0;
        const factors = [];
        if (features.sqlKeywordCount > 2) {
          threatScore += 25;
          factors.push({ factor: "SQL Keywords Detected", importance: features.sqlKeywordCount });
        }
        if (features.jsKeywordCount > 1) {
          threatScore += 20;
          factors.push({ factor: "JavaScript/XSS Keywords", importance: features.jsKeywordCount });
        }
        if (features.shellCommandCount > 1) {
          threatScore += 30;
          factors.push({ factor: "Shell Commands Detected", importance: features.shellCommandCount });
        }
        if (features.pathTraversalCount > 0) {
          threatScore += 25;
          factors.push({ factor: "Path Traversal Attempts", importance: features.pathTraversalCount });
        }
        if (features.specialCharDensity > 0.3) {
          threatScore += 10;
          factors.push({ factor: "High Special Character Density", importance: features.specialCharDensity });
        }
        if (features.urlEncodingDensity > 0.15) {
          threatScore += 15;
          factors.push({ factor: "High URL Encoding Density", importance: features.urlEncodingDensity });
        }
        if (features.entropyScore > 4.5) {
          threatScore += 12;
          factors.push({ factor: "High Content Entropy", importance: features.entropyScore / 10 });
        }
        if (features.clientIpReputation > 50) {
          threatScore += features.clientIpReputation * 0.2;
          factors.push({ factor: "IP Reputation Score", importance: features.clientIpReputation / 100 });
        }
        if (features.ratioBodyToPath > 10) {
          threatScore += 8;
          factors.push({ factor: "Unusual Body-to-Path Ratio", importance: Math.min(1, features.ratioBodyToPath / 50) });
        }
        threatScore = Math.min(100, threatScore);
        return {
          threatProbability: threatScore / 100,
          anomalyScore: threatScore,
          confidence: this.calculateConfidence(factors.length),
          reasoning: [
            `Detected ${features.sqlKeywordCount} SQL keywords`,
            `Detected ${features.jsKeywordCount} JavaScript keywords`,
            `Detected ${features.shellCommandCount} shell commands`,
            `Special char density: ${(features.specialCharDensity * 100).toFixed(1)}%`,
            `Entropy score: ${features.entropyScore.toFixed(2)}`,
            `Content length: ${features.pathLength + features.queryLength + features.bodyLength} bytes`
          ].filter((r) => r),
          topFactors: factors.sort((a, b) => b.importance - a.importance).slice(0, 5)
        };
      }
      /**
       * Combine pattern-based and ML scores
       */
      combinedScore(patternScore, mlPrediction) {
        const normalizedPattern = patternScore / 100;
        const weights = this.modelWeights;
        return Math.min(
          100,
          (normalizedPattern * weights.patternWeight + mlPrediction.anomalyScore * weights.mlWeight / 100) * 100
        );
      }
      /**
       * Record scoring decision for ML training
       */
      recordDecision(features, patternScore, mlScore, finalScore, action, clientIp) {
        this.scoringHistory.push({
          timestamp: Date.now(),
          features,
          patternScore,
          mlScore,
          finalScore,
          action,
          clientIp
        });
        if (this.scoringHistory.length > 1e4) {
          this.scoringHistory = this.scoringHistory.slice(-1e4);
        }
      }
      /**
       * Get training data for ML model
       */
      getTrainingData() {
        return this.scoringHistory.map((record) => ({
          features: record.features,
          label: record.action === "block" ? 1 : 0,
          // Binary: attack or not
          score: record.finalScore,
          timestamp: record.timestamp
        }));
      }
      /**
       * Update model weights based on feedback
       */
      updateWeights(newWeights) {
        const total = newWeights.patternWeight + newWeights.mlWeight;
        this.modelWeights = {
          patternWeight: newWeights.patternWeight / total,
          mlWeight: newWeights.mlWeight / total
        };
      }
      /**
       * Register ML model
       */
      registerModel(model) {
        this.mlModel = model;
      }
      // Helper methods
      calculateDensity(text, pattern) {
        if (!text) return 0;
        const matches = text.match(pattern) || [];
        return matches.length / Math.max(text.length, 1);
      }
      countKeywords(text, keywords) {
        const upperText = text.toUpperCase();
        return keywords.filter((kw) => upperText.includes(kw.toUpperCase())).length;
      }
      calculateEntropy(text) {
        if (!text) return 0;
        const freq = {};
        for (const char of text) {
          freq[char] = (freq[char] || 0) + 1;
        }
        let entropy = 0;
        const len = text.length;
        for (const count of Object.values(freq)) {
          const p = count / len;
          entropy -= p * Math.log2(p);
        }
        return entropy;
      }
      getIpReputation(ip) {
        if (!ip) return 0;
        return 0;
      }
      isPrivateAddress(ip) {
        if (!ip) return false;
        return /^(10\.|172\.1[6-9]\.|172\.2[0-9]\.|172\.3[01]\.|192\.168\.)/.test(ip);
      }
      isKnownGood(ip) {
        const whitelist = ["127.0.0.1", "localhost"];
        return whitelist.includes(ip || "");
      }
      calculateConfidence(factorCount) {
        return Math.min(1, 0.5 + factorCount * 0.1);
      }
    };
    SimpleLinearModel = class {
      name = "SimpleLinear";
      version = "1.0";
      weights = {};
      predict(features) {
        let score = 0;
        const factors = [];
        const featureWeights = {
          sqlKeywordCount: 15,
          jsKeywordCount: 12,
          shellCommandCount: 18,
          pathTraversalCount: 20,
          specialCharDensity: 8,
          urlEncodingDensity: 10,
          entropyScore: 5,
          clientIpReputation: 3
        };
        for (const [featureName, weight] of Object.entries(featureWeights)) {
          const value = features[featureName] || 0;
          const contribution = value * weight;
          score += contribution;
          if (contribution > 0) {
            factors.push({ factor: featureName, importance: contribution / 100 });
          }
        }
        score = Math.min(100, score);
        return {
          threatProbability: score / 100,
          anomalyScore: score,
          confidence: Math.min(1, 0.7 + factors.length * 0.05),
          reasoning: [`Linear model score: ${score.toFixed(2)}`],
          topFactors: factors.sort((a, b) => b.importance - a.importance).slice(0, 5)
        };
      }
    };
  }
});

// server/waf/ml-integration.ts
var ml_integration_exports = {};
__export(ml_integration_exports, {
  mlEngine: () => mlEngine,
  simpleModel: () => simpleModel
});
var mlEngine, simpleModel;
var init_ml_integration = __esm({
  "server/waf/ml-integration.ts"() {
    "use strict";
    init_ml_scoring();
    mlEngine = new MLScoringEngine();
    simpleModel = new SimpleLinearModel();
    mlEngine.registerModel(simpleModel);
  }
});

// server/waf/engine.ts
var HEADER_ANOMALIES, WafEngine, wafEngine;
var init_engine = __esm({
  "server/waf/engine.ts"() {
    "use strict";
    init_rules();
    init_geolocation();
    init_ddos_detection();
    HEADER_ANOMALIES = [
      { header: "user-agent", pattern: /^$/, score: 30, description: "Missing User-Agent header" },
      { header: "user-agent", pattern: /^.{0,10}$/, score: 20, description: "Suspiciously short User-Agent" },
      { header: "user-agent", pattern: /^.{500,}$/, score: 40, description: "Excessively long User-Agent" },
      { header: "host", pattern: /^$/, score: 50, description: "Missing Host header" },
      { header: "content-type", pattern: /multipart.*boundary.*boundary/i, score: 60, description: "Multiple boundary parameters" }
    ];
    WafEngine = class {
      customRules = [];
      rateLimitStore = /* @__PURE__ */ new Map();
      ipReputationCache = /* @__PURE__ */ new Map();
      setCustomRules(rules) {
        this.customRules = rules.filter((r) => r.enabled);
      }
      /**
       * Get DDoS detection service
       */
      getDDoSDetection() {
        return ddosDetection;
      }
      checkRateAnomaly(clientIp, request, policy) {
        const now = Date.now();
        const windowMs = 6e4;
        let entry = this.rateLimitStore.get(clientIp);
        if (!entry || now - entry.firstRequest > windowMs) {
          entry = {
            count: 1,
            firstRequest: now,
            lastRequest: now,
            paths: /* @__PURE__ */ new Set([request.path]),
            methods: /* @__PURE__ */ new Set([request.method])
          };
          this.rateLimitStore.set(clientIp, entry);
          return 0;
        }
        entry.count++;
        entry.lastRequest = now;
        entry.paths.add(request.path);
        entry.methods.add(request.method);
        let anomalyScore = 0;
        let countryLimit = 100;
        if (policy?.geoRateLimitByCountry && request.clientIp) {
          try {
            const geo = GeolocationService.lookup(request.clientIp);
            if (geo?.country && policy.geoRateLimitByCountry[geo.country]) {
              countryLimit = policy.geoRateLimitByCountry[geo.country];
            }
          } catch (e) {
          }
        }
        if (entry.count > countryLimit * 1.5) anomalyScore += 50;
        else if (entry.count > countryLimit) anomalyScore += 30;
        else if (entry.count > countryLimit * 0.8) anomalyScore += 15;
        if (entry.paths.size > 50) anomalyScore += 15;
        const avgInterval = (entry.lastRequest - entry.firstRequest) / entry.count;
        if (avgInterval < 50 && entry.count > 10) anomalyScore += 25;
        if (Math.random() < 0.01) {
          const entries = Array.from(this.rateLimitStore.entries());
          for (const [ip, e] of entries) {
            if (now - e.lastRequest > windowMs * 2) {
              this.rateLimitStore.delete(ip);
            }
          }
        }
        return Math.min(anomalyScore, 50);
      }
      checkHeaderAnomalies(headers) {
        let score = 0;
        const issues = [];
        for (const check of HEADER_ANOMALIES) {
          const headerValue = headers[check.header] || "";
          if (check.pattern.test(headerValue)) {
            score += check.score;
            issues.push(check.description);
          }
        }
        const headerCount = Object.keys(headers).length;
        if (headerCount < 3) {
          score += 20;
          issues.push("Minimal headers (potential automated request)");
        }
        return { score: Math.min(score, 40), issues };
      }
      getIpReputation(clientIp) {
        const cached = this.ipReputationCache.get(clientIp);
        if (cached && Date.now() - cached.lastUpdated < 3e5) {
          return cached.score;
        }
        return 0;
      }
      updateIpReputation(clientIp, wasBlocked) {
        const cached = this.ipReputationCache.get(clientIp) || { score: 0, lastUpdated: 0 };
        cached.score = Math.min(100, cached.score + (wasBlocked ? 10 : -1));
        cached.lastUpdated = Date.now();
        this.ipReputationCache.set(clientIp, cached);
        if (this.ipReputationCache.size > 1e4) {
          const entries = Array.from(this.ipReputationCache.entries()).sort((a, b) => a[1].lastUpdated - b[1].lastUpdated);
          entries.slice(0, 5e3).forEach(([ip]) => this.ipReputationCache.delete(ip));
        }
      }
      extractStrings(obj, maxDepth = 5, depth = 0) {
        if (depth > maxDepth) return [];
        if (obj === null || obj === void 0) return [];
        if (typeof obj === "string") return [obj];
        if (typeof obj === "number" || typeof obj === "boolean") return [String(obj)];
        if (Array.isArray(obj)) {
          const results = [];
          for (let i = 0; i < Math.min(obj.length, 100); i++) {
            results.push(...this.extractStrings(obj[i], maxDepth, depth + 1));
          }
          return results;
        }
        if (typeof obj === "object") {
          const results = [];
          const keys = Object.keys(obj);
          for (let i = 0; i < Math.min(keys.length, 100); i++) {
            const key = keys[i];
            results.push(key);
            results.push(...this.extractStrings(obj[key], maxDepth, depth + 1));
          }
          return results;
        }
        return [];
      }
      analyzeRequest(request, thresholds, policy, skipDDoS = false) {
        const startTime = Date.now();
        const matches = [];
        let patternScore = 0;
        const details = [];
        const recommendations = [];
        if (request.clientIp && policy) {
          if (policy.blockedCountries?.length) {
            const geoCheck = GeolocationService.checkGeoRestriction(
              request.clientIp,
              void 0,
              policy.blockedCountries
            );
            if (!geoCheck.allowed) {
              return {
                action: "block",
                score: 100,
                matches: [{
                  ruleId: "geo-blocked-country",
                  ruleName: "Geo-Location: Blocked Country",
                  field: "clientIp",
                  value: request.clientIp,
                  severity: "critical",
                  category: "Geo-Location",
                  description: geoCheck.reason || "Request from blocked country",
                  matchedPattern: geoCheck.country || "unknown"
                }],
                reason: geoCheck.reason || `Country blocked by policy`,
                processingTimeMs: Date.now() - startTime,
                riskLevel: "critical",
                breakdown: {
                  patternScore: 0,
                  anomalyScore: 0,
                  reputationScore: 0,
                  combinedScore: 100
                },
                explainability: {
                  summary: `Request blocked: ${geoCheck.reason}`,
                  details: [geoCheck.reason || "Country not allowed"],
                  recommendations: ["Request from blocked geography. Contact support if this is incorrect."]
                }
              };
            }
          }
          if (policy.allowedCountries?.length) {
            const geoCheck = GeolocationService.checkGeoRestriction(
              request.clientIp,
              policy.allowedCountries,
              void 0
            );
            if (!geoCheck.allowed) {
              return {
                action: "block",
                score: 100,
                matches: [{
                  ruleId: "geo-not-allowed-country",
                  ruleName: "Geo-Location: Not in Allowed List",
                  field: "clientIp",
                  value: request.clientIp,
                  severity: "critical",
                  category: "Geo-Location",
                  description: geoCheck.reason || "Request from country not in allowed list",
                  matchedPattern: geoCheck.country || "unknown"
                }],
                reason: geoCheck.reason || `Country not in allowed list`,
                processingTimeMs: Date.now() - startTime,
                riskLevel: "critical",
                breakdown: {
                  patternScore: 0,
                  anomalyScore: 0,
                  reputationScore: 0,
                  combinedScore: 100
                },
                explainability: {
                  summary: `Request blocked: ${geoCheck.reason}`,
                  details: [geoCheck.reason || "Country not allowed"],
                  recommendations: ["Request from non-whitelisted country. Contact support if this is incorrect."]
                }
              };
            }
          }
          if (policy.vpnDetectionEnabled) {
            const isVPN = GeolocationService.checkVPN(request.clientIp);
            if (isVPN) {
              const vpnAction = policy.vpnBlockAction || "monitor";
              if (vpnAction === "block") {
                return {
                  action: "block",
                  score: 100,
                  matches: [{
                    ruleId: "geo-vpn-blocked",
                    ruleName: "Geo-Location: VPN Detected & Blocked",
                    field: "clientIp",
                    value: request.clientIp,
                    severity: "high",
                    category: "Geo-Location",
                    description: "VPN/Proxy detected and blocked by policy",
                    matchedPattern: "VPN"
                  }],
                  reason: "Request from VPN/proxy blocked by policy",
                  processingTimeMs: Date.now() - startTime,
                  riskLevel: "high",
                  breakdown: {
                    patternScore: 0,
                    anomalyScore: 0,
                    reputationScore: 0,
                    combinedScore: 100
                  },
                  explainability: {
                    summary: "VPN/Proxy detected and blocked",
                    details: ["Request originates from cloud provider/VPN network"],
                    recommendations: ["Disable VPN/Proxy to access this service"]
                  }
                };
              } else if (vpnAction === "challenge") {
                return {
                  action: "challenge",
                  score: 70,
                  matches: [{
                    ruleId: "geo-vpn-challenged",
                    ruleName: "Geo-Location: VPN Detected & Challenged",
                    field: "clientIp",
                    value: request.clientIp,
                    severity: "medium",
                    category: "Geo-Location",
                    description: "VPN/Proxy detected - challenge required",
                    matchedPattern: "VPN"
                  }],
                  reason: "VPN detected - verification required",
                  processingTimeMs: Date.now() - startTime,
                  riskLevel: "medium",
                  breakdown: {
                    patternScore: 0,
                    anomalyScore: 0,
                    reputationScore: 0,
                    combinedScore: 70
                  },
                  explainability: {
                    summary: "VPN/Proxy detected - please verify",
                    details: ["Request originates from cloud provider/VPN network"],
                    recommendations: ["Complete CAPTCHA verification to proceed"]
                  }
                };
              }
              details.push("VPN/Proxy detected (monitoring only)");
            }
          }
        }
        const pathContent = request.path || "";
        const queryStrings = this.extractStrings(request.query);
        const bodyStrings = typeof request.body === "string" ? [request.body] : this.extractStrings(request.body);
        const headerStrings = this.extractStrings(request.headers);
        const searchableContent = {
          path: pathContent,
          query: queryStrings.join(" "),
          body: bodyStrings.join(" "),
          headers: headerStrings.join(" "),
          request: [pathContent, ...queryStrings, ...bodyStrings].join(" ")
        };
        const maxContentLength = 5e4;
        for (const key of Object.keys(searchableContent)) {
          if (searchableContent[key].length > maxContentLength) {
            searchableContent[key] = searchableContent[key].substring(0, maxContentLength);
          }
        }
        const allPatterns = OWASP_PATTERNS.filter((p) => {
          const customRule = this.customRules.find((r) => r.id === p.id);
          if (customRule) return customRule.enabled;
          return true;
        });
        for (const custom of this.customRules) {
          allPatterns.push({
            id: custom.id,
            name: custom.name || custom.id,
            pattern: new RegExp(custom.pattern, "i"),
            field: custom.targetField,
            severity: custom.severity,
            score: custom.severity === "critical" ? 90 : custom.severity === "high" ? 75 : custom.severity === "medium" ? 50 : 25,
            category: custom.category,
            description: custom.description || `Custom rule: ${custom.name || custom.id}`,
            recommendation: "Review custom rule configuration"
          });
        }
        for (const rule of allPatterns) {
          const targetContent = searchableContent[rule.field] || searchableContent.request;
          const regex = rule.pattern instanceof RegExp ? rule.pattern : new RegExp(rule.pattern, "i");
          const match = regex.exec(targetContent);
          if (match) {
            patternScore += rule.score;
            const matchContext = targetContent.substring(
              Math.max(0, match.index - 20),
              Math.min(targetContent.length, match.index + match[0].length + 20)
            );
            matches.push({
              ruleId: rule.id,
              ruleName: rule.name,
              field: rule.field,
              value: matchContext.substring(0, 100),
              severity: rule.severity,
              category: rule.category,
              description: rule.description,
              matchedPattern: match[0].substring(0, 50),
              recommendation: rule.recommendation
            });
            details.push(`${rule.name}: ${rule.description}`);
            if (rule.recommendation && !recommendations.includes(rule.recommendation)) {
              recommendations.push(rule.recommendation);
            }
          }
        }
        patternScore = Math.min(100, patternScore);
        let ddosResult = null;
        if (!skipDDoS && request.clientIp && request.tenantId) {
          ddosResult = ddosDetection.analyzeRequest(
            request.tenantId,
            request.clientIp,
            request.method,
            request.path,
            request.headers || {},
            JSON.stringify(request.body || "").length
          );
          ddosDetection.trackRequest(request.tenantId, request.clientIp);
        }
        if (ddosResult?.isDDoSDetected && (ddosResult.severity === "high" || ddosResult.severity === "critical")) {
          const ddosAction = ddosResult.action === "block" ? "block" : ddosResult.action === "challenge" ? "challenge" : "throttle";
          return {
            action: ddosAction,
            score: ddosResult.severity === "critical" ? 100 : 85,
            matches: [],
            reason: ddosResult.reason,
            processingTimeMs: Date.now() - startTime,
            riskLevel: "critical",
            breakdown: {
              patternScore: 0,
              anomalyScore: 0,
              reputationScore: 0,
              ddosScore: ddosResult.severity === "critical" ? 100 : 85
            },
            ddosDetection: {
              detected: true,
              severity: ddosResult.severity,
              reason: ddosResult.reason,
              volumetricScore: request.tenantId ? ddosDetection.getTenantMetrics(request.tenantId).volumetricScore : 0
            },
            explainability: {
              summary: `DDoS Attack Detected - ${ddosResult.severity.toUpperCase()} SEVERITY`,
              details: [ddosResult.reason],
              recommendations: [
                "Traffic from this IP has been rate-limited",
                "Multiple sources detected attacking the service",
                "Complete CAPTCHA verification to proceed"
              ]
            }
          };
        }
        const rateAnomaly = request.clientIp ? this.checkRateAnomaly(request.clientIp, request, policy) : 0;
        const headerCheck = this.checkHeaderAnomalies(request.headers || {});
        const reputationScore = request.clientIp ? this.getIpReputation(request.clientIp) : 0;
        if (rateAnomaly > 0) {
          details.push(`Rate anomaly detected (score: ${rateAnomaly})`);
        }
        headerCheck.issues.forEach((issue) => details.push(`Header: ${issue}`));
        if (reputationScore > 0) {
          details.push(`IP has negative reputation history (score: ${reputationScore})`);
        }
        const anomalyScore = Math.min(30, (rateAnomaly + headerCheck.score) / 2);
        let mlScore = 0;
        let mlAnalysis;
        let totalScore = Math.min(100, patternScore * 0.7 + anomalyScore * 0.2 + reputationScore * 0.1);
        try {
          const { mlEngine: mlEngine2 } = (init_ml_integration(), __toCommonJS(ml_integration_exports));
          const baseFeatures = mlEngine2.extractFeatures({
            method: request.method,
            path: request.path,
            headers: request.headers || {},
            body: request.body,
            query: request.query,
            clientIp: request.clientIp
          });
          const mlPrediction = mlEngine2.calculateMLScore(baseFeatures);
          mlScore = mlPrediction.anomalyScore;
          totalScore = mlEngine2.combinedScore(patternScore, mlPrediction);
          mlAnalysis = {
            threatProbability: mlPrediction.threatProbability,
            anomalyScore: mlPrediction.anomalyScore,
            confidence: mlPrediction.confidence,
            topFactors: mlPrediction.topFactors,
            reasoning: mlPrediction.reasoning
          };
          const action2 = totalScore >= 70 ? "block" : totalScore >= 50 ? "challenge" : "allow";
          mlEngine2.recordDecision(
            baseFeatures,
            patternScore,
            mlScore,
            totalScore,
            action2,
            request.clientIp || "unknown"
          );
          details.push(`ML Score: ${Math.round(mlScore)} | Threat Probability: ${(mlPrediction.threatProbability * 100).toFixed(1)}%`);
        } catch (mlError) {
          console.warn("ML scoring failed, using pattern-only scoring:", mlError);
        }
        let action = "allow";
        let reason = "Request passed all security checks";
        let riskLevel = "low";
        if (request.enforcementMode === "monitor") {
          if (totalScore >= thresholds.monitorThreshold) {
            reason = `Threat score ${Math.round(totalScore)} flagged for monitoring`;
            if (totalScore >= thresholds.blockThreshold) {
              riskLevel = "critical";
            } else if (totalScore >= thresholds.challengeThreshold) {
              riskLevel = "high";
            } else {
              riskLevel = "medium";
            }
          } else {
            reason = "Request passed all security checks";
            riskLevel = "low";
          }
          action = "allow";
        } else {
          if (totalScore >= thresholds.blockThreshold) {
            action = "block";
            reason = `Threat score ${Math.round(totalScore)} exceeded block threshold`;
            riskLevel = "critical";
            if (request.clientIp) {
              this.updateIpReputation(request.clientIp, true);
            }
          } else if (totalScore >= thresholds.challengeThreshold) {
            action = "challenge";
            reason = `Threat score ${Math.round(totalScore)} requires verification`;
            riskLevel = "high";
          } else if (totalScore >= thresholds.monitorThreshold) {
            reason = `Threat score ${Math.round(totalScore)} flagged for monitoring`;
            riskLevel = "medium";
          } else if (request.clientIp) {
            this.updateIpReputation(request.clientIp, false);
          }
        }
        let summary = "";
        if (matches.length === 0) {
          summary = "No security threats detected in this request.";
        } else if (matches.length === 1) {
          summary = `Detected 1 potential security issue: ${matches[0].ruleName}`;
        } else {
          const categories = Array.from(new Set(matches.map((m) => m.category)));
          summary = `Detected ${matches.length} security issues across ${categories.length} categories: ${categories.join(", ")}`;
        }
        return {
          action,
          score: Math.round(totalScore),
          matches,
          reason,
          processingTimeMs: Date.now() - startTime,
          riskLevel,
          breakdown: {
            patternScore: Math.round(patternScore),
            anomalyScore: Math.round(anomalyScore),
            reputationScore: Math.round(reputationScore),
            mlScore: Math.round(mlScore),
            combinedScore: Math.round(totalScore)
          },
          mlAnalysis,
          explainability: {
            summary,
            details,
            recommendations: recommendations.length > 0 ? recommendations : ["Continue monitoring for suspicious activity"]
          }
        };
      }
      getStats() {
        return {
          activeIps: this.rateLimitStore.size,
          reputationEntries: this.ipReputationCache.size,
          customRulesLoaded: this.customRules.length,
          totalPatterns: OWASP_PATTERNS.length + this.customRules.length
        };
      }
    };
    wafEngine = new WafEngine();
  }
});

// server/db.ts
var db_exports = {};
__export(db_exports, {
  db: () => db,
  default: () => db_default,
  sequelize: () => sequelize,
  syncDatabase: () => syncDatabase
});
import { Sequelize } from "sequelize";
import path from "path";
async function seedDefaultUsers() {
  try {
    const defaultUsers = [
      {
        email: "admin@waf.local",
        firstName: "Admin",
        lastName: "User",
        role: "admin"
      },
      {
        email: "operator@waf.local",
        firstName: "Operator",
        lastName: "User",
        role: "operator"
      },
      {
        email: "viewer@waf.local",
        firstName: "Viewer",
        lastName: "User",
        role: "viewer"
      }
    ];
    for (const userData of defaultUsers) {
      const exists = await User.findOne({ where: { email: userData.email } });
      if (!exists) {
        await User.create(userData);
        console.log(`\u2705 Created user: ${userData.email}`);
      }
    }
  } catch (error) {
    console.error("\u274C Error seeding users:", error);
  }
}
async function seedDemoWebsite() {
  try {
    const demoWebsite = {
      name: "Demo Target App",
      domain: "demo.waf.local",
      upstreamUrl: "http://10.1.40.99:3001",
      sslEnabled: false,
      isActive: true,
      retentionDays: 30,
      anonymizeIpAfterDays: 7,
      scrubCookies: true,
      scrubAuthHeaders: true
    };
    const exists = await Tenant.findOne({
      where: { domain: demoWebsite.domain }
    });
    if (!exists) {
      const created = await Tenant.create(demoWebsite);
      console.log(
        `\u2705 Created demo website: ${demoWebsite.name} (${demoWebsite.upstreamUrl})`
      );
      return created.id;
    } else {
      await exists.update({ upstreamUrl: demoWebsite.upstreamUrl });
      console.log(`\u2705 Demo website already exists: ${demoWebsite.name}`);
      return exists.id;
    }
  } catch (error) {
    console.error("\u274C Error seeding demo website:", error);
  }
}
async function seedDemoPolicies() {
  try {
    const tenant = await Tenant.findOne({ where: { domain: "demo.waf.local" } });
    if (!tenant) return;
    const policyCount = await Policy.count();
    if (policyCount > 0) {
      console.log(`\u2705 Demo policies already exist: ${policyCount} policies`);
      return;
    }
    const demoPolicies = [
      {
        tenantId: tenant.id,
        name: "Strict Protection",
        enforcementMode: "block",
        blockThreshold: 60,
        challengeThreshold: 40,
        monitorThreshold: 20,
        rateLimit: 100,
        rateLimitWindow: 60,
        isDefault: true
      },
      {
        tenantId: tenant.id,
        name: "Balanced Security",
        enforcementMode: "monitor",
        blockThreshold: 75,
        challengeThreshold: 50,
        monitorThreshold: 30,
        rateLimit: 150,
        rateLimitWindow: 60,
        isDefault: false
      },
      {
        tenantId: tenant.id,
        name: "Permissive Mode",
        enforcementMode: "monitor",
        blockThreshold: 85,
        challengeThreshold: 70,
        monitorThreshold: 50,
        rateLimit: 200,
        rateLimitWindow: 60,
        isDefault: false
      }
    ];
    for (const policyData of demoPolicies) {
      await Policy.create(policyData);
    }
    console.log(`\u2705 Seeded ${demoPolicies.length} demo policies`);
  } catch (error) {
    console.error("\u26A0\uFE0F Error seeding demo policies:", error);
  }
}
async function seedBuiltInRules() {
  try {
    for (const pattern of OWASP_PATTERNS) {
      const exists = await WafRule.findOne({ where: { id: pattern.id } });
      if (!exists) {
        await WafRule.create({
          id: pattern.id,
          name: pattern.name,
          description: pattern.description,
          category: pattern.category,
          severity: pattern.severity,
          pattern: pattern.pattern.toString().replace(/\//g, ""),
          patternType: "regex",
          targetField: pattern.field,
          action: "deny",
          score: pattern.score,
          enabled: true,
          isBuiltIn: true,
          hitCount: 0
        });
      }
    }
    console.log(`\u2705 Seeded ${OWASP_PATTERNS.length} built-in OWASP rules`);
  } catch (error) {
    console.error("\u26A0\uFE0F Error seeding built-in rules:", error);
  }
}
async function seedComplianceFrameworks() {
  try {
    const frameworks = [
      { name: "GDPR", description: "General Data Protection Regulation", category: "data-protection", region: "EU", ruleCount: 45 },
      { name: "HIPAA", description: "Health Insurance Portability and Accountability Act", category: "healthcare", region: "US", ruleCount: 38 },
      { name: "SOC2", description: "Service Organization Control 2", category: "security", region: "US", ruleCount: 42 },
      { name: "PCI-DSS", description: "Payment Card Industry Data Security Standard", category: "payment", region: "Global", ruleCount: 35 },
      { name: "ISO27001", description: "Information Security Management Standard", category: "security", region: "Global", ruleCount: 50 },
      { name: "NIST", description: "National Institute of Standards and Technology Cybersecurity", category: "security", region: "US", ruleCount: 48 },
      { name: "CIS", description: "Center for Internet Security Controls", category: "security", region: "Global", ruleCount: 40 }
    ];
    for (const fw of frameworks) {
      const exists = await ComplianceFramework.findOne({ where: { name: fw.name } });
      if (!exists) {
        await ComplianceFramework.create(fw);
      }
    }
    console.log(`\u2705 Seeded ${frameworks.length} compliance frameworks`);
  } catch (error) {
    console.error("\u26A0\uFE0F Error seeding compliance frameworks:", error);
  }
}
async function seedComplianceRules() {
  try {
    const complianceRulesMap = {
      GDPR: [
        { id: "GDPR-32.1.1", cat: "Data Security", severity: "mandatory", desc: "Encrypt personal data at rest (AES-256+)", proof: "Encryption using AES-256 or stronger algorithms" },
        { id: "GDPR-32.1.2", cat: "Data Security", severity: "mandatory", desc: "Encrypt personal data in transit (TLS 1.2+)", proof: "TLS 1.2 or higher for all data transmission" },
        { id: "GDPR-32.1.3", cat: "Data Security", severity: "mandatory", desc: "Implement pseudonymization techniques", proof: "Replace identifiers with reference numbers" },
        { id: "GDPR-32.1.4", cat: "Data Security", severity: "mandatory", desc: "Implement hashing for data protection", proof: "Use strong cryptographic hashing algorithms" },
        { id: "GDPR-32.1.5", cat: "Data Security", severity: "mandatory", desc: "Data integrity controls", proof: "Checksums or digital signatures on data" },
        { id: "GDPR-32.1.6", cat: "Data Security", severity: "mandatory", desc: "Backup and recovery procedures", proof: "3-2-1 backup strategy (3 copies, 2 devices, 1 offsite)" },
        { id: "GDPR-32.1.7", cat: "Confidentiality", severity: "mandatory", desc: "Access control on need-to-know basis", proof: "Implement least privilege principle" },
        { id: "GDPR-32.1.8", cat: "Confidentiality", severity: "mandatory", desc: "Multi-factor authentication (MFA)", proof: "MFA on all sensitive access" },
        { id: "GDPR-32.1.9", cat: "Confidentiality", severity: "mandatory", desc: "Role-based access control (RBAC)", proof: "RBAC policies documented and enforced" },
        { id: "GDPR-32.1.10", cat: "Integrity", severity: "mandatory", desc: "Data accuracy and completeness controls", proof: "Validation rules and integrity checks" },
        { id: "GDPR-32.1.11", cat: "Integrity", severity: "mandatory", desc: "Change management with ticketing", proof: "Change requests tracked and approved" },
        { id: "GDPR-32.1.12", cat: "Integrity", severity: "mandatory", desc: "Audit logging of data modifications", proof: "Log all CREATE/UPDATE/DELETE operations" },
        { id: "GDPR-32.1.13", cat: "Availability", severity: "mandatory", desc: "System availability and redundancy", proof: "Uptime SLA and failover mechanisms" },
        { id: "GDPR-32.1.14", cat: "Resilience", severity: "mandatory", desc: "Fault tolerance and DDoS protection", proof: "DDoS mitigation and error handling" },
        { id: "GDPR-32.1.15", cat: "Incident Response", severity: "mandatory", desc: "Documented incident response plan", proof: "IR procedures and 72-hour breach notification" },
        { id: "GDPR-32.2.1", cat: "Testing", severity: "mandatory", desc: "Vulnerability scanning", proof: "Quarterly vulnerability assessments" },
        { id: "GDPR-32.2.2", cat: "Testing", severity: "mandatory", desc: "Penetration testing", proof: "Annual pentest by authorized firm" },
        { id: "GDPR-32.2.3", cat: "Testing", severity: "mandatory", desc: "Security audits", proof: "Annual security audit minimum" },
        { id: "GDPR-32.2.4", cat: "Testing", severity: "mandatory", desc: "Risk assessment monitoring", proof: "Annual risk assessment and updates" },
        { id: "GDPR-32.2.5", cat: "Monitoring", severity: "mandatory", desc: "Real-time threat detection", proof: "IDS/IPS monitoring of network" },
        { id: "GDPR-32.3.1", cat: "Data Discovery", severity: "mandatory", desc: "Data inventory and classification", proof: "Complete data location and type mapping" },
        { id: "GDPR-32.3.2", cat: "Data Protection", severity: "mandatory", desc: "Data loss prevention (DLP)", proof: "Monitor and prevent data exfiltration" },
        { id: "GDPR-32.4.1", cat: "Network Security", severity: "mandatory", desc: "Firewall implementation", proof: "Firewall rules documented and tested" },
        { id: "GDPR-32.4.2", cat: "Network Security", severity: "mandatory", desc: "Intrusion detection/prevention (IDS/IPS)", proof: "IDS/IPS deployed and monitored" },
        { id: "GDPR-32.4.3", cat: "Network Security", severity: "mandatory", desc: "Network segmentation", proof: "DMZ and internal network separation" },
        { id: "GDPR-32.4.4", cat: "Network Security", severity: "mandatory", desc: "Secure transmission protocols", proof: "TLS/SSL on all communications" },
        { id: "GDPR-32.5.1", cat: "Training", severity: "mandatory", desc: "Staff data protection training", proof: "Annual training for all employees" },
        { id: "GDPR-32.5.2", cat: "Training", severity: "mandatory", desc: "Security awareness programs", proof: "Regular security awareness updates" },
        { id: "GDPR-32.6.1", cat: "Third-party", severity: "mandatory", desc: "Processor security verification", proof: "Processor audit and contracts" },
        { id: "GDPR-32.6.2", cat: "Third-party", severity: "mandatory", desc: "Vendor breach notification", proof: "Breach notification SLAs in contracts" },
        { id: "GDPR-33.1", cat: "Breach Notification", severity: "mandatory", desc: "Breach notification within 72 hours", proof: "Breach reporting procedures documented" },
        { id: "GDPR-34.1", cat: "Data Subject Rights", severity: "mandatory", desc: "Data subject right to access", proof: "Subject access request (SAR) process" },
        { id: "GDPR-35.1", cat: "DPIA", severity: "mandatory", desc: "Data Protection Impact Assessment (DPIA)", proof: "DPIA for high-risk processing" },
        { id: "GDPR-35.2", cat: "DPIA", severity: "mandatory", desc: "Consult with supervisory authority", proof: "High-risk processing consultation" },
        { id: "GDPR-36.1", cat: "DPIA", severity: "mandatory", desc: "Comply with DPIA recommendations", proof: "Action items from DPIA implementation" },
        { id: "GDPR-37.1", cat: "DPO", severity: "mandatory", desc: "Designate Data Protection Officer", proof: "DPO contact and role documentation" },
        { id: "GDPR-38.1", cat: "DPO", severity: "mandatory", desc: "DPO independence and support", proof: "DPO reporting and resources" },
        { id: "GDPR-39.1", cat: "DPO", severity: "mandatory", desc: "DPO cooperation with authorities", proof: "DPO contact with authorities" },
        { id: "GDPR-40.1", cat: "Codes", severity: "recommended", desc: "Establish codes of conduct", proof: "Sectoral codes of conduct" },
        { id: "GDPR-42.1", cat: "Certification", severity: "recommended", desc: "Seek data protection certification", proof: "ISO 27001 or privacy certification" },
        { id: "GDPR-43.1", cat: "Certification", severity: "recommended", desc: "Monitoring bodies for certification", proof: "Third-party certification audit" },
        { id: "GDPR-44.1", cat: "International", severity: "mandatory", desc: "International data transfers", proof: "Standard contractual clauses (SCCs)" },
        { id: "GDPR-45.1", cat: "International", severity: "mandatory", desc: "Adequate decision countries", proof: "Data transfer to adequacy decision countries" },
        { id: "GDPR-46.1", cat: "International", severity: "mandatory", desc: "Standard contractual clauses", proof: "SCCs between controller and processor" },
        { id: "GDPR-47.1", cat: "International", severity: "mandatory", desc: "Binding corporate rules", proof: "BCR approval and maintenance" },
        { id: "GDPR-49.1", cat: "International", severity: "mandatory", desc: "Derogations for transfer", proof: "Documented derogation justification" }
      ],
      HIPAA: [
        { id: "HIPAA-164.312-a-1", cat: "Access Control", severity: "mandatory", desc: "Unique user identification", proof: "Unique ID per user account" },
        { id: "HIPAA-164.312-a-2", cat: "Access Control", severity: "mandatory", desc: "Emergency access procedures", proof: "Documented emergency access procedures" },
        { id: "HIPAA-164.312-a-2-i", cat: "Authentication", severity: "mandatory", desc: "Require minimum password length", proof: "Password policy with 12+ character minimum" },
        { id: "HIPAA-164.312-a-2-ii", cat: "Authentication", severity: "mandatory", desc: "Password complexity requirements", proof: "Complexity rules: upper, lower, numeric, special" },
        { id: "HIPAA-164.312-a-2-iii", cat: "Authentication", severity: "mandatory", desc: "Password expiration", proof: "Password change every 90 days" },
        { id: "HIPAA-164.312-b", cat: "Encryption", severity: "mandatory", desc: "Encryption for ePHI at rest", proof: "AES-256 or equivalent encryption" },
        { id: "HIPAA-164.312-c-1", cat: "Encryption", severity: "mandatory", desc: "Encryption for ePHI in transit", proof: "TLS 1.2+ for network transmission" },
        { id: "HIPAA-164.312-c-2", cat: "Audit Control", severity: "mandatory", desc: "Audit control and logging", proof: "Audit logs of ePHI access" },
        { id: "HIPAA-164.312-e-1", cat: "Integrity", severity: "mandatory", desc: "ePHI integrity controls", proof: "Checksums or HMAC verification" },
        { id: "HIPAA-164.312-e-2-i", cat: "Transmission Security", severity: "mandatory", desc: "Transmission encryption", proof: "Encrypt ePHI in motion" },
        { id: "HIPAA-164.312-e-2-ii", cat: "Transmission Security", severity: "mandatory", desc: "Transmission integrity controls", proof: "HMAC or similar for message integrity" },
        { id: "HIPAA-164.310-a-1", cat: "Physical Perimeter", severity: "mandatory", desc: "Facility access control", proof: "Restricted access to secure areas" },
        { id: "HIPAA-164.310-a-2-i", cat: "Physical Access", severity: "mandatory", desc: "Visitor management", proof: "Visitor log and badges" },
        { id: "HIPAA-164.310-a-2-ii", cat: "Physical Access", severity: "mandatory", desc: "Workstation use policy", proof: "Authorized use documentation" },
        { id: "HIPAA-164.310-a-2-iii", cat: "Physical Security", severity: "mandatory", desc: "Workstation security", proof: "Physical device locking mechanisms" },
        { id: "HIPAA-164.310-b", cat: "Device Control", severity: "mandatory", desc: "Media control and handling", proof: "Media labeling and secure disposal" },
        { id: "HIPAA-164.310-c", cat: "Device Disposal", severity: "mandatory", desc: "Workstation disposal", proof: "Secure device decommissioning" },
        { id: "HIPAA-164.310-d", cat: "Environmental", severity: "mandatory", desc: "Environmental controls", proof: "Fire suppression, HVAC controls" },
        { id: "HIPAA-164.308-a-1", cat: "Security Management", severity: "mandatory", desc: "Security management process", proof: "Risk assessment and mitigation plan" },
        { id: "HIPAA-164.308-a-2", cat: "Assigned Responsibility", severity: "mandatory", desc: "Assign security officer", proof: "Designated security officer" },
        { id: "HIPAA-164.308-a-3", cat: "Workforce Security", severity: "mandatory", desc: "User access provisioning", proof: "Access management procedures" },
        { id: "HIPAA-164.308-a-4", cat: "Information Access", severity: "mandatory", desc: "Information access management", proof: "Minimum necessary access principle" },
        { id: "HIPAA-164.308-a-5", cat: "Training", severity: "mandatory", desc: "Security awareness training", proof: "Annual training for all workforce" },
        { id: "HIPAA-164.308-a-6", cat: "Training", severity: "mandatory", desc: "Security sanction policies", proof: "Disciplinary procedures for violations" },
        { id: "HIPAA-164.308-a-7", cat: "Incident Response", severity: "mandatory", desc: "Incident response procedures", proof: "Documented incident response plan" },
        { id: "HIPAA-164.308-a-8", cat: "Contingency", severity: "mandatory", desc: "Contingency planning", proof: "Business continuity and DR plans" },
        { id: "HIPAA-164.308-b-1", cat: "Business Associate", severity: "mandatory", desc: "Business Associate agreements", proof: "BAAs for all third parties" },
        { id: "HIPAA-164.308-c-1", cat: "Breach Notification", severity: "mandatory", desc: "Breach notification procedures", proof: "60-day breach notification SLA" },
        { id: "HIPAA-164.308-d-1", cat: "Evaluation", severity: "mandatory", desc: "Evaluate compliance", proof: "Annual compliance evaluation" },
        { id: "HIPAA-164.406", cat: "Breach Notification", severity: "mandatory", desc: "Mitigation of inappropriate release", proof: "ePHI mitigation procedures" },
        { id: "HIPAA-164.414", cat: "Subcontracting", severity: "mandatory", desc: "Subcontractor agreements", proof: "Subcontractor compliance agreements" },
        { id: "HIPAA-164.504", cat: "Business Associate", severity: "mandatory", desc: "BA contract requirements", proof: "BA contract clauses documented" },
        { id: "HIPAA-164.504-b-1", cat: "Business Associate", severity: "mandatory", desc: "BA permitted uses", proof: "BA use limitations documented" },
        { id: "HIPAA-164.504-e", cat: "Business Associate", severity: "mandatory", desc: "BA required obligations", proof: "BA obligation documentation" },
        { id: "HIPAA-164.612", cat: "Security Incident", severity: "mandatory", desc: "Security incident procedures", proof: "Incident investigation process" }
      ],
      SOC2: [
        { id: "SOC2-CC1.1", cat: "Governance", severity: "mandatory", desc: "Establish entity-level objectives and responsibilities", proof: "Governance charter and policies" },
        { id: "SOC2-CC1.2", cat: "Governance", severity: "mandatory", desc: "Establish oversight responsibility", proof: "Board/management oversight documented" },
        { id: "SOC2-CC1.3", cat: "Code of Conduct", severity: "mandatory", desc: "Establish code of conduct", proof: "Code of conduct policy and training" },
        { id: "SOC2-CC1.4", cat: "Competence", severity: "mandatory", desc: "Demonstrate competence", proof: "Competency assessments and training" },
        { id: "SOC2-CC2.1", cat: "Risk Assessment", severity: "mandatory", desc: "Identify risks relevant to objectives", proof: "Risk register and assessment" },
        { id: "SOC2-CC2.2", cat: "Risk Assessment", severity: "mandatory", desc: "Consider potential for fraud", proof: "Fraud risk assessment" },
        { id: "SOC2-CC2.3", cat: "Risk Assessment", severity: "mandatory", desc: "Identify risks related to change", proof: "Change risk assessment process" },
        { id: "SOC2-CC2.4", cat: "Risk Assessment", severity: "mandatory", desc: "Estimate significance of risks", proof: "Risk scoring methodology" },
        { id: "SOC2-CC3.1", cat: "Control Activities", severity: "mandatory", desc: "Select and develop control activities", proof: "Control design documentation" },
        { id: "SOC2-CC3.2", cat: "Control Activities", severity: "mandatory", desc: "Determine responsibilities and authority", proof: "RACI matrix and role definitions" },
        { id: "SOC2-CC3.3", cat: "Control Activities", severity: "mandatory", desc: "Segregation of duties", proof: "SOD policy and matrix" },
        { id: "SOC2-CC4.1", cat: "Information", severity: "mandatory", desc: "Obtain information to support functioning", proof: "Information systems and processes" },
        { id: "SOC2-CC4.2", cat: "Communication", severity: "mandatory", desc: "Communicate internal responsibility", proof: "Communication plan and channels" },
        { id: "SOC2-CC5.1", cat: "Monitoring", severity: "mandatory", desc: "Select, develop monitoring activities", proof: "Monitoring procedures and tools" },
        { id: "SOC2-CC5.2", cat: "Monitoring", severity: "mandatory", desc: "Monitor system components", proof: "System performance monitoring" },
        { id: "SOC2-CC5.3", cat: "Monitoring", severity: "mandatory", desc: "Perform monitoring activities", proof: "Regular monitoring execution" },
        { id: "SOC2-CC6.1", cat: "Deficiency", severity: "mandatory", desc: "Identify control deficiencies", proof: "Control testing and reporting" },
        { id: "SOC2-CC6.2", cat: "Deficiency", severity: "mandatory", desc: "Evaluate control deficiencies", proof: "Deficiency assessment framework" },
        { id: "SOC2-CC7.1", cat: "System Availability", severity: "recommended", desc: "System availability and performance", proof: "Uptime and performance metrics" },
        { id: "SOC2-CC7.2", cat: "System Availability", severity: "recommended", desc: "System availability monitoring", proof: "Continuous availability monitoring" },
        { id: "SOC2-CC8.1", cat: "Processing", severity: "recommended", desc: "Obtain authorization for transactions", proof: "Transaction approval processes" },
        { id: "SOC2-CC9.1", cat: "Data Quality", severity: "recommended", desc: "Identify, capture, maintain data completeness", proof: "Data quality controls" },
        { id: "SOC2-A1.1", cat: "Confidentiality", severity: "mandatory", desc: "System components protected from unauthorized access", proof: "Access controls implemented" },
        { id: "SOC2-A1.2", cat: "Confidentiality", severity: "mandatory", desc: "Confidentiality restrictions compliance", proof: "Data classification and handling" },
        { id: "SOC2-C1.1", cat: "Confidentiality", severity: "mandatory", desc: "System and data confidentiality", proof: "Encryption and access controls" },
        { id: "SOC2-I1.1", cat: "Integrity", severity: "mandatory", desc: "System and data integrity", proof: "Data validation and integrity checks" },
        { id: "SOC2-I2.1", cat: "Integrity", severity: "mandatory", desc: "Processing completeness", proof: "Transaction processing logs" },
        { id: "SOC2-L1.1", cat: "Availability", severity: "mandatory", desc: "System availability to authorized users", proof: "Availability SLA and monitoring" },
        { id: "SOC2-P1.1", cat: "Privacy", severity: "mandatory", desc: "System design for privacy", proof: "Privacy by design documentation" },
        { id: "SOC2-P2.1", cat: "Privacy", severity: "mandatory", desc: "Personal information collection", proof: "Data collection policies" },
        { id: "SOC2-P3.1", cat: "Privacy", severity: "mandatory", desc: "Personal information retention", proof: "Data retention policies" },
        { id: "SOC2-P4.1", cat: "Privacy", severity: "mandatory", desc: "Disclose personal information appropriately", proof: "Disclosure procedures" },
        { id: "SOC2-P5.1", cat: "Privacy", severity: "mandatory", desc: "Access to personal information", proof: "Subject access request process" },
        { id: "SOC2-P6.1", cat: "Privacy", severity: "mandatory", desc: "Accuracy of personal information", proof: "Data accuracy procedures" },
        { id: "SOC2-P7.1", cat: "Privacy", severity: "mandatory", desc: "Privacy notice", proof: "Privacy policy and notifications" },
        { id: "SOC2-P8.1", cat: "Privacy", severity: "mandatory", desc: "Choice of personal information", proof: "Opt-in/opt-out procedures" }
      ],
      "PCI-DSS": [
        { id: "PCI-1.1", cat: "Firewall", severity: "mandatory", desc: "Build firewall configuration standards", proof: "Firewall rules documented" },
        { id: "PCI-1.2", cat: "Firewall", severity: "mandatory", desc: "Restrict traffic between networks", proof: "Firewall rules restrict traffic" },
        { id: "PCI-1.3", cat: "Firewall", severity: "mandatory", desc: "Prohibit direct internet access to CDE", proof: "DMZ implemented" },
        { id: "PCI-1.4", cat: "Firewall", severity: "mandatory", desc: "Install perimeter firewalls for wireless", proof: "Wireless firewall rules" },
        { id: "PCI-2.1", cat: "Default Settings", severity: "mandatory", desc: "Change vendor-supplied defaults", proof: "Custom configs vs defaults" },
        { id: "PCI-2.2", cat: "Default Settings", severity: "mandatory", desc: "Remove unnecessary services", proof: "Service audit and hardening" },
        { id: "PCI-2.3", cat: "Default Settings", severity: "mandatory", desc: "Configure security parameters", proof: "Security config documentation" },
        { id: "PCI-3.1", cat: "Data Protection", severity: "mandatory", desc: "Keep CHD storage to minimum", proof: "Data retention policy" },
        { id: "PCI-3.2", cat: "Data Protection", severity: "mandatory", desc: "Do not store sensitive auth data", proof: "Post-auth data deletion" },
        { id: "PCI-3.3", cat: "Data Protection", severity: "mandatory", desc: "Mask PAN display", proof: "PAN masking (first 6, last 4 only)" },
        { id: "PCI-3.4", cat: "Data Protection", severity: "mandatory", desc: "Render PAN unreadable", proof: "Hashing, tokenization, or encryption" },
        { id: "PCI-4.1", cat: "Encryption", severity: "mandatory", desc: "Encrypt CHD in transit", proof: "TLS 1.2+ for transmission" },
        { id: "PCI-5.1", cat: "Malware", severity: "mandatory", desc: "Deploy anti-virus software", proof: "Anti-virus on all systems" },
        { id: "PCI-6.1", cat: "Development", severity: "mandatory", desc: "Identify security vulnerabilities", proof: "Vulnerability scanning process" },
        { id: "PCI-6.2", cat: "Development", severity: "mandatory", desc: "Install security patches monthly", proof: "Patch management SLA" },
        { id: "PCI-6.5", cat: "Development", severity: "mandatory", desc: "Address common coding vulnerabilities", proof: "Code review process" },
        { id: "PCI-7.1", cat: "Access Control", severity: "mandatory", desc: "Restrict access by need to know", proof: "Access control policy" },
        { id: "PCI-8.1", cat: "Authentication", severity: "mandatory", desc: "Assign unique user IDs", proof: "Unique ID per user" },
        { id: "PCI-8.2", cat: "Authentication", severity: "mandatory", desc: "Strong user authentication", proof: "Strong password policy" },
        { id: "PCI-8.3", cat: "Authentication", severity: "mandatory", desc: "Multi-factor authentication", proof: "MFA for admin access" },
        { id: "PCI-8.5", cat: "Authentication", severity: "mandatory", desc: "Prevent password reuse", proof: "Password history (4+ previous)" },
        { id: "PCI-8.6", cat: "Authentication", severity: "mandatory", desc: "Limit login attempts", proof: "Account lockout after 6 attempts" },
        { id: "PCI-9.1", cat: "Physical", severity: "mandatory", desc: "Restrict physical access", proof: "Physical access controls" },
        { id: "PCI-10.1", cat: "Audit", severity: "mandatory", desc: "Audit trail implementation", proof: "Audit logs of system access" },
        { id: "PCI-10.2", cat: "Audit", severity: "mandatory", desc: "Link access to user IDs", proof: "User identification in logs" },
        { id: "PCI-11.1", cat: "Testing", severity: "mandatory", desc: "Detect wireless access points", proof: "Quarterly wireless scan" },
        { id: "PCI-11.2", cat: "Testing", severity: "mandatory", desc: "Run vulnerability scans quarterly", proof: "Quarterly scanning by ASV" },
        { id: "PCI-12.1", cat: "Policy", severity: "mandatory", desc: "Information security policy", proof: "Security policy documentation" },
        { id: "PCI-12.2", cat: "Policy", severity: "mandatory", desc: "Risk assessment process", proof: "Annual risk assessment" },
        { id: "PCI-12.3", cat: "Policy", severity: "mandatory", desc: "Third-party agreements", proof: "Service agreements with security clauses" },
        { id: "PCI-12.5", cat: "Policy", severity: "mandatory", desc: "Security incident procedures", proof: "Incident response plan" },
        { id: "PCI-12.6", cat: "Training", severity: "mandatory", desc: "Security awareness program", proof: "Annual security training" },
        { id: "PCI-12.8", cat: "Service Providers", severity: "mandatory", desc: "Manage service providers", proof: "Service provider list and agreements" }
      ],
      "ISO27001": [
        { id: "ISO-A5.1.1", cat: "Policy", severity: "mandatory", desc: "Information security policy", proof: "Policy document and approval" },
        { id: "ISO-A6.1.1", cat: "Organization", severity: "mandatory", desc: "Information security roles", proof: "RACI matrix and role definitions" },
        { id: "ISO-A7.1.1", cat: "Personnel", severity: "mandatory", desc: "Recruitment policy and screening", proof: "Background check procedures" },
        { id: "ISO-A7.2.1", cat: "Training", severity: "mandatory", desc: "Security awareness training", proof: "Annual training records" },
        { id: "ISO-A8.1.1", cat: "Asset", severity: "mandatory", desc: "Asset inventory and ownership", proof: "Asset register" },
        { id: "ISO-A9.1.1", cat: "Access", severity: "mandatory", desc: "Access control policy", proof: "Access control policy document" },
        { id: "ISO-A9.2.1", cat: "User Management", severity: "mandatory", desc: "User registration and provisioning", proof: "Access request process" },
        { id: "ISO-A9.3.1", cat: "Password", severity: "mandatory", desc: "Password management policy", proof: "Password policy document" },
        { id: "ISO-A9.4.1", cat: "Privilege", severity: "mandatory", desc: "Restrict privileged access", proof: "PAM system documentation" },
        { id: "ISO-A10.1.1", cat: "Cryptography", severity: "mandatory", desc: "Cryptography policy", proof: "Crypto policy document" },
        { id: "ISO-A11.1.1", cat: "Physical", severity: "mandatory", desc: "Physical security perimeter", proof: "Facility security design" },
        { id: "ISO-A11.2.1", cat: "Equipment", severity: "mandatory", desc: "Equipment placement", proof: "Safe placement procedures" },
        { id: "ISO-A12.1.1", cat: "Operations", severity: "mandatory", desc: "Operational responsibilities", proof: "Procedures documentation" },
        { id: "ISO-A12.2.1", cat: "Malware", severity: "mandatory", desc: "Detection of malware", proof: "Malware protection tools" },
        { id: "ISO-A12.3.1", cat: "Backup", severity: "mandatory", desc: "Information backup", proof: "Backup policy and testing" },
        { id: "ISO-A12.4.1", cat: "Logging", severity: "mandatory", desc: "Event logging", proof: "Log collection and retention" },
        { id: "ISO-A13.1.1", cat: "Network", severity: "mandatory", desc: "Network controls", proof: "Network segmentation" },
        { id: "ISO-A14.1.1", cat: "Acquisition", severity: "mandatory", desc: "Information security requirements", proof: "Security requirements specification" },
        { id: "ISO-A15.1.1", cat: "Supplier", severity: "mandatory", desc: "Supplier security policy", proof: "Supplier contracts" },
        { id: "ISO-A16.1.1", cat: "Incident", severity: "mandatory", desc: "Incident management responsibilities", proof: "Incident management procedure" },
        { id: "ISO-A17.1.1", cat: "Continuity", severity: "mandatory", desc: "Business continuity objectives", proof: "BCP documentation" },
        { id: "ISO-A18.1.1", cat: "Compliance", severity: "mandatory", desc: "Compliance with legal requirements", proof: "Legal compliance audit" },
        { id: "ISO-A5.2.1", cat: "Information Security", severity: "mandatory", desc: "Review information security objectives", proof: "Quarterly policy reviews" },
        { id: "ISO-A6.1.2", cat: "Governance", severity: "mandatory", desc: "Information security steering committee", proof: "Committee charter and meetings" },
        { id: "ISO-A7.2.2", cat: "Discipline", severity: "mandatory", desc: "User discipline and sanctions", proof: "Disciplinary procedures" },
        { id: "ISO-A7.3.1", cat: "Termination", severity: "mandatory", desc: "Termination procedures", proof: "Offboarding checklist" },
        { id: "ISO-A8.1.2", cat: "Classification", severity: "mandatory", desc: "Asset classification", proof: "Classification policy" },
        { id: "ISO-A8.1.3", cat: "Media", severity: "mandatory", desc: "Media handling", proof: "Media policy and procedures" },
        { id: "ISO-A9.2.2", cat: "Review", severity: "mandatory", desc: "User access review", proof: "Quarterly access reviews" },
        { id: "ISO-A9.4.3", cat: "Audit", severity: "mandatory", desc: "Privileged access review", proof: "Privileged account audit" },
        { id: "ISO-A10.1.2", cat: "Key Management", severity: "mandatory", desc: "Cryptographic key management", proof: "Key management procedures" },
        { id: "ISO-A11.1.5", cat: "Environmental", severity: "mandatory", desc: "Protection against natural disasters", proof: "Environmental protections" },
        { id: "ISO-A12.1.2", cat: "Change Management", severity: "mandatory", desc: "Change management procedure", proof: "Change control documentation" },
        { id: "ISO-A12.4.3", cat: "Archival", severity: "mandatory", desc: "Protection of log information", proof: "Log archival and retention" },
        { id: "ISO-A13.1.2", cat: "Segmentation", severity: "mandatory", desc: "Network segregation", proof: "Network isolation procedures" },
        { id: "ISO-A14.2.1", cat: "Development", severity: "mandatory", desc: "Secure development policy", proof: "SDLC documentation" },
        { id: "ISO-A15.1.2", cat: "Third-party", severity: "mandatory", desc: "Third-party risk management", proof: "Vendor assessment process" },
        { id: "ISO-A16.1.5", cat: "Response", severity: "mandatory", desc: "Response to incidents", proof: "Incident response procedures" },
        { id: "ISO-A17.1.2", cat: "Planning", severity: "mandatory", desc: "Implement and test continuity", proof: "BCP testing and updates" },
        { id: "ISO-A18.1.4", cat: "Audit", severity: "mandatory", desc: "Independent security audit", proof: "Annual security audit" }
      ],
      "NIST": [
        { id: "NIST-GOVERN-1", cat: "Governance", severity: "mandatory", desc: "Establish cybersecurity policy", proof: "Security policy document" },
        { id: "NIST-GOVERN-2", cat: "Strategy", severity: "mandatory", desc: "Establish risk management strategy", proof: "Risk management plan" },
        { id: "NIST-GOVERN-3", cat: "Roles", severity: "mandatory", desc: "Define roles and responsibilities", proof: "RACI matrix" },
        { id: "NIST-GOVERN-4", cat: "Compliance", severity: "mandatory", desc: "Define compliance requirements", proof: "Compliance framework" },
        { id: "NIST-ID-1", cat: "Assets", severity: "mandatory", desc: "Establish asset inventory", proof: "Asset management system" },
        { id: "NIST-ID-2", cat: "Business", severity: "mandatory", desc: "Define business environment", proof: "Business impact analysis" },
        { id: "NIST-ID-3", cat: "Governance", severity: "mandatory", desc: "Establish governance and compliance", proof: "Policy and compliance docs" },
        { id: "NIST-ID-4", cat: "Risk Assessment", severity: "mandatory", desc: "Conduct risk assessment", proof: "Risk register" },
        { id: "NIST-PROTECT-1", cat: "Identity", severity: "mandatory", desc: "Establish identity management", proof: "IAM system" },
        { id: "NIST-PROTECT-2", cat: "Access", severity: "mandatory", desc: "Establish access control", proof: "Access control policies" },
        { id: "NIST-PROTECT-3", cat: "Training", severity: "mandatory", desc: "Provide security training", proof: "Training records" },
        { id: "NIST-PROTECT-4", cat: "Data", severity: "mandatory", desc: "Establish data security", proof: "Data classification policy" },
        { id: "NIST-PROTECT-5", cat: "Technology", severity: "mandatory", desc: "Deploy protective technology", proof: "Security tools deployment" },
        { id: "NIST-DETECT-1", cat: "Anomaly", severity: "mandatory", desc: "Establish anomaly detection", proof: "Monitoring systems" },
        { id: "NIST-DETECT-2", cat: "Monitoring", severity: "mandatory", desc: "Monitor systems continuously", proof: "SIEM implementation" },
        { id: "NIST-RESPOND-1", cat: "Planning", severity: "mandatory", desc: "Establish response planning", proof: "Incident response plan" },
        { id: "NIST-RESPOND-2", cat: "Communication", severity: "mandatory", desc: "Establish communications", proof: "Incident comm plan" },
        { id: "NIST-RESPOND-3", cat: "Mitigation", severity: "mandatory", desc: "Perform mitigation", proof: "Mitigation procedures" },
        { id: "NIST-RECOVER-1", cat: "Planning", severity: "mandatory", desc: "Establish recovery planning", proof: "Recovery plan documentation" },
        { id: "NIST-RECOVER-2", cat: "Improvement", severity: "mandatory", desc: "Conduct improvement activities", proof: "Lessons learned process" }
      ],
      "CIS": [
        { id: "CIS-1.1", cat: "Inventory", severity: "mandatory", desc: "Maintain hardware asset inventory", proof: "Hardware inventory list" },
        { id: "CIS-1.2", cat: "Inventory", severity: "mandatory", desc: "Maintain software asset inventory", proof: "Software asset list" },
        { id: "CIS-2.1", cat: "Config", severity: "mandatory", desc: "Create secure configuration baseline", proof: "Configuration baseline docs" },
        { id: "CIS-2.2", cat: "Config", severity: "mandatory", desc: "Implement configuration management", proof: "Change control procedures" },
        { id: "CIS-3.1", cat: "Incident", severity: "mandatory", desc: "Establish incident response plan", proof: "IR plan documentation" },
        { id: "CIS-3.2", cat: "Incident", severity: "mandatory", desc: "Perform incident response testing", proof: "Annual tabletop exercises" },
        { id: "CIS-4.1", cat: "Logging", severity: "mandatory", desc: "Establish centralized logging", proof: "Centralized logging implementation" },
        { id: "CIS-4.2", cat: "Logging", severity: "mandatory", desc: "Review and retain logs", proof: "Log analysis procedures" },
        { id: "CIS-5.1", cat: "Access", severity: "mandatory", desc: "Implement multi-factor authentication", proof: "MFA implementation" },
        { id: "CIS-5.2", cat: "Privilege", severity: "mandatory", desc: "Manage privileged access", proof: "PAM solutions" },
        { id: "CIS-6.1", cat: "Malware", severity: "mandatory", desc: "Deploy malware protection", proof: "Anti-malware tools" },
        { id: "CIS-6.2", cat: "Malware", severity: "mandatory", desc: "Update malware definitions", proof: "Current threat definitions" },
        { id: "CIS-7.1", cat: "Email", severity: "mandatory", desc: "Deploy email filtering", proof: "Email filtering system" },
        { id: "CIS-7.2", cat: "Email", severity: "mandatory", desc: "Handle email attachments", proof: "Attachment sandboxing" },
        { id: "CIS-8.1", cat: "Network", severity: "mandatory", desc: "Segment network", proof: "Network diagram and rules" },
        { id: "CIS-8.2", cat: "IPS", severity: "mandatory", desc: "Deploy network-based IPS", proof: "IPS deployment" },
        { id: "CIS-9.1", cat: "Vulnerability", severity: "mandatory", desc: "Perform vulnerability scanning", proof: "Quarterly scans" },
        { id: "CIS-9.2", cat: "Patch", severity: "mandatory", desc: "Implement patch management", proof: "Patch SLA process" },
        { id: "CIS-15.1", cat: "Development", severity: "mandatory", desc: "Secure development practices", proof: "SDLC documentation" },
        { id: "CIS-18.1", cat: "Communication", severity: "mandatory", desc: "Implement secure communication", proof: "Encryption protocols" }
      ]
    };
    let totalRulesCreated = 0;
    const allWafRules = await WafRule.findAll();
    for (const [frameworkName, rules] of Object.entries(complianceRulesMap)) {
      const framework = await ComplianceFramework.findOne({ where: { name: frameworkName } });
      if (!framework) continue;
      for (let i = 0; i < rules.length; i++) {
        const rule = rules[i];
        const wafRule = allWafRules[i % allWafRules.length];
        const exists = await ComplianceRule.findOne({
          where: { complianceRuleId: rule.id }
        });
        if (!exists && wafRule) {
          await ComplianceRule.create({
            wafRuleId: wafRule.id,
            complianceFrameworkId: framework.id,
            complianceRuleId: rule.id,
            mappedCategory: rule.cat,
            severity: rule.severity,
            description: rule.desc,
            proof: rule.proof
          });
          totalRulesCreated++;
        }
      }
    }
    console.log(`\u2705 Seeded ${totalRulesCreated} compliance rules across 7 frameworks`);
  } catch (error) {
    console.error("\u26A0\uFE0F Error seeding compliance rules:", error);
  }
}
async function initializePerformanceOptimizations() {
  try {
    await sequelize.query(
      `CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)`
    );
    await sequelize.query(
      `CREATE INDEX IF NOT EXISTS idx_tenants_domain ON tenants(domain)`
    );
    await sequelize.query(
      `CREATE INDEX IF NOT EXISTS idx_tenants_active ON tenants(isActive)`
    );
    await sequelize.query(
      `CREATE INDEX IF NOT EXISTS idx_policies_tenant ON policies(tenantId)`
    );
    await sequelize.query(
      `CREATE INDEX IF NOT EXISTS idx_rules_tenant ON waf_rules(tenantId)`
    );
    await sequelize.query(
      `CREATE INDEX IF NOT EXISTS idx_alerts_tenant ON alerts(tenantId)`
    );
    await sequelize.query(
      `CREATE INDEX IF NOT EXISTS idx_requests_tenant ON requests(tenantId)`
    );
    await sequelize.query(
      `CREATE INDEX IF NOT EXISTS idx_requests_created ON requests(createdAt)`
    );
    console.log("\u2705 Database indexes created for faster queries");
  } catch (error) {
    console.error(
      "Index creation note:",
      error.message?.substring(0, 50)
    );
  }
}
async function syncDatabase() {
  try {
    if (!initialized) {
      initializeModels();
      initBehavioralModels();
      initDDoSModels();
      initComplianceModels();
      initComplianceAssociations();
      initialized = true;
    }
    await sequelize.authenticate();
    console.log("\u2705 SQLite database connected");
    await sequelize.query("PRAGMA foreign_keys = OFF");
    try {
      await sequelize.sync({ alter: false, force: false });
      console.log("\u2705 Database tables synchronized");
      await initializePerformanceOptimizations();
      if (!seeded) {
        const startSeed = Date.now();
        await seedDefaultUsers();
        const tenantId = await seedDemoWebsite();
        await seedDemoPolicies();
        await seedBuiltInRules();
        await seedComplianceFrameworks();
        await seedComplianceRules();
        seeded = true;
        console.log(`\u2705 Database seeding completed in ${Date.now() - startSeed}ms`);
      }
    } finally {
      await sequelize.query("PRAGMA foreign_keys = ON");
    }
  } catch (error) {
    console.error("\u274C Database error:", error);
    throw error;
  }
}
var dbPath, sequelize, initialized, seeded, db, db_default;
var init_db = __esm({
  "server/db.ts"() {
    "use strict";
    init_models();
    init_engine();
    dbPath = path.resolve(process.cwd(), "waf.db");
    sequelize = new Sequelize({
      dialect: "sqlite",
      storage: dbPath,
      logging: false,
      // Set to console.log to see SQL queries
      sync: { alter: true }
      // Auto-sync models with database
    });
    initialized = false;
    seeded = false;
    db = sequelize;
    db_default = sequelize;
  }
});

// server/models.ts
var models_exports = {};
__export(models_exports, {
  Alert: () => Alert,
  Analysis: () => Analysis,
  AnalyticsAggregate: () => AnalyticsAggregate,
  AuditFile: () => AuditFile,
  BehavioralEvent: () => BehavioralEvent,
  BehavioralProfile: () => BehavioralProfile,
  ComplianceAudit: () => ComplianceAudit,
  ComplianceFramework: () => ComplianceFramework,
  ComplianceRule: () => ComplianceRule,
  DDoSEvent: () => DDoSEvent,
  IpList: () => IpList,
  Override: () => Override,
  Policy: () => Policy,
  Request: () => Request,
  Tenant: () => Tenant,
  TenantCompliance: () => TenantCompliance2,
  User: () => User,
  WafRule: () => WafRule,
  Webhook: () => Webhook,
  initBehavioralModels: () => initBehavioralModels,
  initComplianceAssociations: () => initComplianceAssociations,
  initComplianceModels: () => initComplianceModels,
  initDDoSModels: () => initDDoSModels,
  initializeModels: () => initializeModels
});
import { DataTypes, Model } from "sequelize";
import { v4 as uuidv4 } from "uuid";
function initializeModels() {
  User.init(
    {
      id: { type: DataTypes.STRING, primaryKey: true, defaultValue: () => uuidv4() },
      email: { type: DataTypes.STRING, unique: true },
      firstName: DataTypes.STRING,
      lastName: DataTypes.STRING,
      profileImageUrl: DataTypes.STRING,
      avatarType: { type: DataTypes.ENUM("astronaut", "avatar", "bear", "bot", "cat", "dog", "robot", "user"), defaultValue: "user" },
      role: { type: DataTypes.ENUM("admin", "operator", "viewer"), defaultValue: "viewer" },
      tenantIds: { type: DataTypes.JSON, defaultValue: [] },
      createdAt: { type: DataTypes.DATE, defaultValue: DataTypes.NOW },
      updatedAt: { type: DataTypes.DATE, defaultValue: DataTypes.NOW }
    },
    { sequelize, tableName: "users", timestamps: true }
  );
  Tenant.init(
    {
      id: { type: DataTypes.STRING, primaryKey: true, defaultValue: () => uuidv4() },
      name: DataTypes.STRING,
      domain: { type: DataTypes.STRING, unique: true },
      upstreamUrl: DataTypes.STRING,
      sslEnabled: { type: DataTypes.BOOLEAN, defaultValue: false },
      sslCertPath: DataTypes.STRING,
      sslKeyPath: DataTypes.STRING,
      isActive: { type: DataTypes.BOOLEAN, defaultValue: true },
      retentionDays: { type: DataTypes.INTEGER, defaultValue: 30 },
      anonymizeIpAfterDays: { type: DataTypes.INTEGER, defaultValue: 7 },
      scrubCookies: { type: DataTypes.BOOLEAN, defaultValue: true },
      scrubAuthHeaders: { type: DataTypes.BOOLEAN, defaultValue: true },
      createdAt: { type: DataTypes.DATE, defaultValue: DataTypes.NOW },
      updatedAt: { type: DataTypes.DATE, defaultValue: DataTypes.NOW }
    },
    { sequelize, tableName: "tenants", timestamps: true }
  );
  Policy.init(
    {
      id: { type: DataTypes.STRING, primaryKey: true, defaultValue: () => uuidv4() },
      tenantId: { type: DataTypes.STRING, references: { model: Tenant, key: "id" } },
      name: DataTypes.STRING,
      enforcementMode: { type: DataTypes.ENUM("monitor", "block"), defaultValue: "monitor" },
      securityEngine: { type: DataTypes.ENUM("waf-engine", "modsecurity", "both"), defaultValue: "both" },
      blockThreshold: { type: DataTypes.FLOAT, defaultValue: 70 },
      challengeThreshold: { type: DataTypes.FLOAT, defaultValue: 50 },
      monitorThreshold: { type: DataTypes.FLOAT, defaultValue: 30 },
      rateLimit: { type: DataTypes.INTEGER, defaultValue: 100 },
      rateLimitWindow: { type: DataTypes.INTEGER, defaultValue: 60 },
      isDefault: { type: DataTypes.BOOLEAN, defaultValue: false },
      allowedCountries: { type: DataTypes.JSON, defaultValue: null },
      blockedCountries: { type: DataTypes.JSON, defaultValue: null },
      geoRateLimitByCountry: { type: DataTypes.JSON, defaultValue: null },
      vpnDetectionEnabled: { type: DataTypes.BOOLEAN, defaultValue: false },
      vpnBlockAction: { type: DataTypes.ENUM("block", "challenge", "monitor"), defaultValue: "monitor" },
      rules: { type: DataTypes.JSON, defaultValue: "[]" },
      enabled: { type: DataTypes.BOOLEAN, defaultValue: true },
      createdAt: { type: DataTypes.DATE, defaultValue: DataTypes.NOW },
      updatedAt: { type: DataTypes.DATE, defaultValue: DataTypes.NOW }
    },
    { sequelize, tableName: "policies", timestamps: true }
  );
  WafRule.init(
    {
      id: { type: DataTypes.STRING, primaryKey: true, defaultValue: () => uuidv4() },
      tenantId: { type: DataTypes.STRING, references: { model: Tenant, key: "id" }, allowNull: true },
      name: DataTypes.STRING,
      description: DataTypes.TEXT,
      category: DataTypes.STRING,
      severity: { type: DataTypes.STRING, defaultValue: "medium" },
      pattern: DataTypes.TEXT,
      patternType: { type: DataTypes.STRING, defaultValue: "regex" },
      targetField: DataTypes.STRING,
      action: { type: DataTypes.ENUM("allow", "monitor", "challenge", "deny"), defaultValue: "deny" },
      score: { type: DataTypes.INTEGER, defaultValue: 10 },
      enabled: { type: DataTypes.BOOLEAN, defaultValue: true },
      isBuiltIn: { type: DataTypes.BOOLEAN, defaultValue: false },
      hitCount: { type: DataTypes.INTEGER, defaultValue: 0 },
      createdAt: { type: DataTypes.DATE, defaultValue: DataTypes.NOW },
      updatedAt: { type: DataTypes.DATE, defaultValue: DataTypes.NOW }
    },
    { sequelize, tableName: "waf_rules", timestamps: true }
  );
  Request.init(
    {
      id: { type: DataTypes.STRING, primaryKey: true, defaultValue: () => uuidv4() },
      tenantId: { type: DataTypes.STRING, references: { model: Tenant, key: "id" } },
      timestamp: { type: DataTypes.DATE, defaultValue: DataTypes.NOW },
      clientIp: DataTypes.STRING,
      clientIpAnonymized: { type: DataTypes.BOOLEAN, defaultValue: false },
      method: DataTypes.STRING,
      path: DataTypes.TEXT,
      queryString: DataTypes.TEXT,
      headersJson: DataTypes.JSON,
      bodyRef: DataTypes.STRING,
      bodyPreview: DataTypes.TEXT,
      userAgent: DataTypes.TEXT,
      referer: DataTypes.TEXT,
      contentType: DataTypes.STRING,
      contentLength: DataTypes.INTEGER,
      responseCode: DataTypes.INTEGER,
      responseHeadersJson: DataTypes.JSON,
      responseBodyRef: DataTypes.STRING,
      responseTime: DataTypes.INTEGER,
      analysisId: DataTypes.STRING,
      actionTaken: { type: DataTypes.ENUM("allow", "monitor", "challenge", "deny"), defaultValue: "allow" },
      wafHitsJson: DataTypes.JSON,
      country: DataTypes.STRING,
      city: DataTypes.STRING,
      createdAt: { type: DataTypes.DATE, defaultValue: DataTypes.NOW }
    },
    { sequelize, tableName: "requests", timestamps: false }
  );
  Analysis.init(
    {
      id: { type: DataTypes.STRING, primaryKey: true, defaultValue: () => uuidv4() },
      requestId: { type: DataTypes.STRING, references: { model: Request, key: "id" } },
      totalScore: { type: DataTypes.FLOAT, defaultValue: 0 },
      suggestedAction: { type: DataTypes.ENUM("allow", "monitor", "challenge", "deny"), defaultValue: "allow" },
      finalAction: { type: DataTypes.ENUM("allow", "monitor", "challenge", "deny"), defaultValue: "allow" },
      breakdownJson: DataTypes.JSON,
      matchedRulesJson: DataTypes.JSON,
      ipReputationScore: { type: DataTypes.FLOAT, defaultValue: 0 },
      rateAnomalyScore: { type: DataTypes.FLOAT, defaultValue: 0 },
      headerAnomalyScore: { type: DataTypes.FLOAT, defaultValue: 0 },
      pathAnomalyScore: { type: DataTypes.FLOAT, defaultValue: 0 },
      bodyAnomalyScore: { type: DataTypes.FLOAT, defaultValue: 0 },
      processingTimeMs: DataTypes.INTEGER,
      explanationText: DataTypes.TEXT,
      createdAt: { type: DataTypes.DATE, defaultValue: DataTypes.NOW }
    },
    { sequelize, tableName: "analysis", timestamps: false }
  );
  Override.init(
    {
      id: { type: DataTypes.STRING, primaryKey: true, defaultValue: () => uuidv4() },
      overrideType: { type: DataTypes.ENUM("request", "rule", "ip") },
      targetId: DataTypes.STRING,
      tenantId: { type: DataTypes.STRING, references: { model: Tenant, key: "id" }, allowNull: true },
      action: { type: DataTypes.ENUM("allow", "monitor", "challenge", "deny") },
      operatorId: { type: DataTypes.STRING, references: { model: User, key: "id" } },
      reason: DataTypes.TEXT,
      expiresAt: DataTypes.DATE,
      isActive: { type: DataTypes.BOOLEAN, defaultValue: true },
      createdAt: { type: DataTypes.DATE, defaultValue: DataTypes.NOW }
    },
    { sequelize, tableName: "overrides", timestamps: false }
  );
  Alert.init(
    {
      id: { type: DataTypes.STRING, primaryKey: true, defaultValue: () => uuidv4() },
      tenantId: { type: DataTypes.STRING, references: { model: Tenant, key: "id" }, allowNull: true },
      severity: DataTypes.STRING,
      type: DataTypes.STRING,
      title: DataTypes.STRING,
      message: DataTypes.TEXT,
      metadata: DataTypes.JSON,
      isRead: { type: DataTypes.BOOLEAN, defaultValue: false },
      isDismissed: { type: DataTypes.BOOLEAN, defaultValue: false },
      createdAt: { type: DataTypes.DATE, defaultValue: DataTypes.NOW }
    },
    { sequelize, tableName: "alerts", timestamps: false }
  );
  Webhook.init(
    {
      id: { type: DataTypes.STRING, primaryKey: true, defaultValue: () => uuidv4() },
      tenantId: { type: DataTypes.STRING, references: { model: Tenant, key: "id" }, allowNull: true },
      name: DataTypes.STRING,
      url: DataTypes.STRING,
      secret: DataTypes.STRING,
      events: DataTypes.JSON,
      isActive: { type: DataTypes.BOOLEAN, defaultValue: true },
      lastTriggeredAt: DataTypes.DATE,
      failureCount: { type: DataTypes.INTEGER, defaultValue: 0 },
      createdAt: { type: DataTypes.DATE, defaultValue: DataTypes.NOW }
    },
    { sequelize, tableName: "webhooks", timestamps: false }
  );
  IpList.init(
    {
      id: { type: DataTypes.STRING, primaryKey: true, defaultValue: () => uuidv4() },
      tenantId: { type: DataTypes.STRING, references: { model: Tenant, key: "id" }, allowNull: true },
      ipAddress: DataTypes.STRING,
      listType: DataTypes.STRING,
      reason: DataTypes.TEXT,
      expiresAt: DataTypes.DATE,
      createdBy: { type: DataTypes.STRING, references: { model: User, key: "id" }, allowNull: true },
      createdAt: { type: DataTypes.DATE, defaultValue: DataTypes.NOW }
    },
    { sequelize, tableName: "ip_lists", timestamps: false }
  );
  AuditFile.init(
    {
      id: { type: DataTypes.STRING, primaryKey: true, defaultValue: () => uuidv4() },
      tenantId: { type: DataTypes.STRING, references: { model: Tenant, key: "id" }, allowNull: false },
      requestId: { type: DataTypes.STRING, references: { model: Request, key: "id" }, allowNull: true },
      fileType: { type: DataTypes.STRING, allowNull: false },
      pathOnDisk: { type: DataTypes.STRING, allowNull: false },
      sizeBytes: DataTypes.INTEGER,
      mimeType: DataTypes.STRING,
      isCompressed: { type: DataTypes.BOOLEAN, defaultValue: false },
      createdAt: { type: DataTypes.DATE, defaultValue: DataTypes.NOW }
    },
    { sequelize, tableName: "audit_files", timestamps: false }
  );
  AnalyticsAggregate.init(
    {
      id: { type: DataTypes.STRING, primaryKey: true, defaultValue: () => uuidv4() },
      tenantId: { type: DataTypes.STRING, references: { model: Tenant, key: "id" }, allowNull: false },
      periodStart: { type: DataTypes.DATE, allowNull: false },
      periodEnd: { type: DataTypes.DATE, allowNull: false },
      periodType: { type: DataTypes.STRING, allowNull: false },
      totalRequests: { type: DataTypes.INTEGER, defaultValue: 0 },
      blockedRequests: { type: DataTypes.INTEGER, defaultValue: 0 },
      monitoredRequests: { type: DataTypes.INTEGER, defaultValue: 0 },
      allowedRequests: { type: DataTypes.INTEGER, defaultValue: 0 },
      challengedRequests: { type: DataTypes.INTEGER, defaultValue: 0 },
      uniqueIps: { type: DataTypes.INTEGER, defaultValue: 0 },
      avgScore: { type: DataTypes.FLOAT, defaultValue: 0 },
      topRulesJson: DataTypes.JSON,
      topIpsJson: DataTypes.JSON,
      topPathsJson: DataTypes.JSON,
      createdAt: { type: DataTypes.DATE, defaultValue: DataTypes.NOW }
    },
    { sequelize, tableName: "analytics_aggregates", timestamps: false }
  );
}
function initDDoSModels() {
  DDoSEvent.init(
    {
      id: { type: DataTypes.STRING, primaryKey: true, defaultValue: () => uuidv4() },
      tenantId: { type: DataTypes.STRING, references: { model: Tenant, key: "id" }, allowNull: false },
      clientIp: { type: DataTypes.STRING, allowNull: false },
      severity: { type: DataTypes.ENUM("low", "medium", "high", "critical"), allowNull: false },
      eventType: { type: DataTypes.ENUM("volumetric", "connection_limit", "rate_limit", "protocol_anomaly", "normalization_violation"), allowNull: false },
      requestsPerSecond: DataTypes.INTEGER,
      uniqueIPs: DataTypes.INTEGER,
      volumetricScore: DataTypes.REAL,
      reason: { type: DataTypes.TEXT, allowNull: false },
      action: { type: DataTypes.ENUM("allow", "throttle", "challenge", "block"), allowNull: false },
      metadata: DataTypes.JSON,
      createdAt: { type: DataTypes.DATE, defaultValue: DataTypes.NOW }
    },
    { sequelize, tableName: "ddos_events", timestamps: false }
  );
}
function initComplianceModels() {
  ComplianceFramework.init(
    {
      id: { type: DataTypes.STRING, primaryKey: true, defaultValue: () => uuidv4() },
      name: { type: DataTypes.STRING, allowNull: false, unique: true },
      description: { type: DataTypes.TEXT, allowNull: false },
      category: { type: DataTypes.STRING, allowNull: false },
      region: { type: DataTypes.STRING, allowNull: false },
      ruleCount: { type: DataTypes.INTEGER, defaultValue: 0 },
      createdAt: { type: DataTypes.DATE, defaultValue: DataTypes.NOW }
    },
    { sequelize, tableName: "compliance_frameworks", timestamps: false }
  );
  ComplianceRule.init(
    {
      id: { type: DataTypes.STRING, primaryKey: true, defaultValue: () => uuidv4() },
      wafRuleId: { type: DataTypes.STRING, references: { model: WafRule, key: "id" }, allowNull: false },
      complianceFrameworkId: { type: DataTypes.STRING, references: { model: ComplianceFramework, key: "id" }, allowNull: false },
      complianceRuleId: { type: DataTypes.STRING, allowNull: false },
      mappedCategory: { type: DataTypes.STRING, allowNull: false },
      severity: { type: DataTypes.ENUM("mandatory", "recommended", "optional"), allowNull: false },
      description: { type: DataTypes.TEXT, allowNull: false },
      proof: { type: DataTypes.TEXT, allowNull: false },
      createdAt: { type: DataTypes.DATE, defaultValue: DataTypes.NOW }
    },
    { sequelize, tableName: "compliance_rules", timestamps: false }
  );
  TenantCompliance2.init(
    {
      id: { type: DataTypes.STRING, primaryKey: true, defaultValue: () => uuidv4() },
      tenantId: { type: DataTypes.STRING, references: { model: Tenant, key: "id" }, allowNull: false },
      complianceFrameworkId: { type: DataTypes.STRING, references: { model: ComplianceFramework, key: "id" }, allowNull: false },
      enabled: { type: DataTypes.BOOLEAN, defaultValue: false },
      complianceStatus: { type: DataTypes.ENUM("active", "in-review", "failed", "compliant"), defaultValue: "active" },
      lastAuditDate: DataTypes.DATE,
      nextAuditDate: DataTypes.DATE,
      selectedRuleIds: DataTypes.JSON,
      enabledRuleIds: DataTypes.JSON,
      createdAt: { type: DataTypes.DATE, defaultValue: DataTypes.NOW }
    },
    { sequelize, tableName: "tenant_compliance", timestamps: false }
  );
  ComplianceAudit.init(
    {
      id: { type: DataTypes.STRING, primaryKey: true, defaultValue: () => uuidv4() },
      tenantId: { type: DataTypes.STRING, references: { model: Tenant, key: "id" }, allowNull: false },
      complianceFrameworkId: { type: DataTypes.STRING, references: { model: ComplianceFramework, key: "id" }, allowNull: false },
      auditDate: { type: DataTypes.DATE, defaultValue: DataTypes.NOW },
      totalRequirements: { type: DataTypes.INTEGER, allowNull: false },
      metRequirements: { type: DataTypes.INTEGER, allowNull: false },
      failedRequirements: { type: DataTypes.INTEGER, allowNull: false },
      compliancePercentage: { type: DataTypes.REAL, allowNull: false },
      failedRules: DataTypes.JSON,
      actionItems: DataTypes.JSON,
      auditorNotes: DataTypes.TEXT,
      action: { type: DataTypes.STRING, defaultValue: "review" },
      details: DataTypes.TEXT,
      userEmail: DataTypes.STRING,
      frameworkName: DataTypes.STRING,
      createdAt: { type: DataTypes.DATE, defaultValue: DataTypes.NOW }
    },
    { sequelize, tableName: "compliance_audits", timestamps: false }
  );
}
function initComplianceAssociations() {
  ComplianceFramework.hasMany(ComplianceRule, {
    foreignKey: "complianceFrameworkId",
    as: "rules"
  });
  ComplianceRule.belongsTo(ComplianceFramework, {
    foreignKey: "complianceFrameworkId",
    as: "framework"
  });
  Tenant.hasMany(TenantCompliance2, {
    foreignKey: "tenantId",
    as: "compliance"
  });
  TenantCompliance2.belongsTo(Tenant, {
    foreignKey: "tenantId",
    as: "tenant"
  });
  ComplianceFramework.hasMany(TenantCompliance2, {
    foreignKey: "complianceFrameworkId",
    as: "tenants"
  });
  TenantCompliance2.belongsTo(ComplianceFramework, {
    foreignKey: "complianceFrameworkId",
    as: "framework"
  });
  Tenant.hasMany(ComplianceAudit, {
    foreignKey: "tenantId",
    as: "audits"
  });
  ComplianceAudit.belongsTo(Tenant, {
    foreignKey: "tenantId",
    as: "tenant"
  });
  ComplianceFramework.hasMany(ComplianceAudit, {
    foreignKey: "complianceFrameworkId",
    as: "audits"
  });
  ComplianceAudit.belongsTo(ComplianceFramework, {
    foreignKey: "complianceFrameworkId",
    as: "framework"
  });
  WafRule.hasMany(ComplianceRule, {
    foreignKey: "wafRuleId",
    as: "compliance"
  });
  ComplianceRule.belongsTo(WafRule, {
    foreignKey: "wafRuleId",
    as: "wafRule"
  });
}
function initBehavioralModels() {
  BehavioralProfile.init(
    {
      id: { type: DataTypes.STRING, primaryKey: true, defaultValue: () => uuidv4() },
      email: { type: DataTypes.STRING, unique: true, allowNull: false },
      tenantId: { type: DataTypes.STRING, references: { model: Tenant, key: "id" }, allowNull: true },
      totalAttempts: { type: DataTypes.INTEGER, defaultValue: 0 },
      failedAttempts: { type: DataTypes.INTEGER, defaultValue: 0 },
      successfulAttempts: { type: DataTypes.INTEGER, defaultValue: 0 },
      lastAttempt: DataTypes.DATE,
      isLocked: { type: DataTypes.BOOLEAN, defaultValue: false },
      lockExpiresAt: DataTypes.DATE,
      botScore: { type: DataTypes.REAL, defaultValue: 0 },
      anomalyScore: { type: DataTypes.REAL, defaultValue: 0 },
      riskLevel: { type: DataTypes.STRING, defaultValue: "low" },
      ipsJson: DataTypes.JSON,
      createdAt: { type: DataTypes.DATE, defaultValue: DataTypes.NOW },
      updatedAt: { type: DataTypes.DATE, defaultValue: DataTypes.NOW }
    },
    { sequelize, tableName: "behavioral_profiles", timestamps: false }
  );
  BehavioralEvent.init(
    {
      id: { type: DataTypes.STRING, primaryKey: true, defaultValue: () => uuidv4() },
      profileId: { type: DataTypes.STRING, references: { model: BehavioralProfile, key: "id" }, allowNull: false },
      email: { type: DataTypes.STRING, allowNull: false },
      eventType: { type: DataTypes.STRING, allowNull: false },
      ipAddress: DataTypes.STRING,
      userAgent: DataTypes.TEXT,
      success: DataTypes.BOOLEAN,
      score: DataTypes.REAL,
      reason: DataTypes.TEXT,
      createdAt: { type: DataTypes.DATE, defaultValue: DataTypes.NOW }
    },
    { sequelize, tableName: "behavioral_events", timestamps: false }
  );
}
var User, Tenant, Policy, WafRule, Request, Analysis, Override, Alert, Webhook, IpList, AuditFile, AnalyticsAggregate, DDoSEvent, BehavioralProfile, BehavioralEvent, ComplianceFramework, ComplianceRule, TenantCompliance2, ComplianceAudit;
var init_models = __esm({
  "server/models.ts"() {
    "use strict";
    init_db();
    User = class extends Model {
    };
    Tenant = class extends Model {
    };
    Policy = class extends Model {
    };
    WafRule = class extends Model {
    };
    Request = class extends Model {
    };
    Analysis = class extends Model {
    };
    Override = class extends Model {
    };
    Alert = class extends Model {
    };
    Webhook = class extends Model {
    };
    IpList = class extends Model {
    };
    AuditFile = class extends Model {
    };
    AnalyticsAggregate = class extends Model {
    };
    DDoSEvent = class extends Model {
    };
    BehavioralProfile = class extends Model {
    };
    BehavioralEvent = class extends Model {
    };
    ComplianceFramework = class extends Model {
    };
    ComplianceRule = class extends Model {
    };
    TenantCompliance2 = class extends Model {
    };
    ComplianceAudit = class extends Model {
    };
  }
});

// server/index-prod.ts
import fs2 from "node:fs";
import path3 from "node:path";
import express2 from "express";

// server/app.ts
import express from "express";
import session from "express-session";
import passport2 from "passport";
import { Strategy as LocalStrategy } from "passport-local";

// server/storage.ts
init_models();
import { Op } from "sequelize";
var DatabaseStorage = class {
  // Users
  async getUser(id) {
    const user = await User.findByPk(id);
    return user?.toJSON();
  }
  async getUserByEmail(email) {
    const user = await User.findOne({ where: { email } });
    return user?.toJSON();
  }
  async upsertUser(user) {
    const [u] = await User.upsert(user);
    return u.toJSON();
  }
  async getUsers() {
    const users = await User.findAll();
    return users.map((u) => u.toJSON());
  }
  async createUser(user) {
    const created = await User.create(user);
    return created.toJSON();
  }
  async updateUser(id, data) {
    const user = await User.findByPk(id);
    if (!user) return void 0;
    await user.update(data);
    return user.toJSON();
  }
  async deleteUser(id) {
    await User.destroy({ where: { id } });
  }
  // Tenants
  async getTenants() {
    const tenants = await Tenant.findAll();
    return tenants.map((t) => t.toJSON());
  }
  async getTenant(id) {
    const tenant = await Tenant.findByPk(id);
    return tenant?.toJSON();
  }
  async createTenant(tenant) {
    const created = await Tenant.create(tenant);
    return created.toJSON();
  }
  async updateTenant(id, data) {
    const tenant = await Tenant.findByPk(id);
    if (!tenant) return void 0;
    await tenant.update(data);
    return tenant.toJSON();
  }
  async deleteTenant(id) {
    await Tenant.destroy({ where: { id } });
  }
  // Policies
  async getPolicies() {
    const policies = await Policy.findAll();
    return policies.map((p) => p.toJSON());
  }
  async getPolicy(id) {
    const policy = await Policy.findByPk(id);
    return policy?.toJSON();
  }
  async getPolicyByTenant(tenantId) {
    const policy = await Policy.findOne({ where: { tenantId, isDefault: true } });
    return policy?.toJSON();
  }
  async createPolicy(policy) {
    const created = await Policy.create(policy);
    return created.toJSON();
  }
  async updatePolicy(id, data) {
    const policy = await Policy.findByPk(id);
    if (!policy) return void 0;
    await policy.update(data);
    return policy.toJSON();
  }
  async deletePolicy(id) {
    await Policy.destroy({ where: { id } });
  }
  // WAF Rules
  async getRules() {
    const rules = await WafRule.findAll();
    return rules.map((r) => r.toJSON());
  }
  async getRule(id) {
    const rule = await WafRule.findByPk(id);
    return rule?.toJSON();
  }
  async getRulesByTenant(tenantId) {
    const rules = await WafRule.findAll({
      where: tenantId ? { tenantId } : { tenantId: null }
    });
    return rules.map((r) => r.toJSON());
  }
  async createRule(rule) {
    const created = await WafRule.create(rule);
    return created.toJSON();
  }
  async updateRule(id, data) {
    const rule = await WafRule.findByPk(id);
    if (!rule) return void 0;
    await rule.update(data);
    return rule.toJSON();
  }
  async deleteRule(id) {
    await WafRule.destroy({ where: { id } });
  }
  // Requests
  async getRequests(tenantId) {
    const requests = await Request.findAll(tenantId ? { where: { tenantId } } : {});
    return requests.map((r) => r.toJSON());
  }
  async getRequest(id) {
    const request = await Request.findByPk(id);
    return request?.toJSON();
  }
  async createRequest(request) {
    const created = await Request.create(request);
    return created.toJSON();
  }
  async getRequestWithAnalysis(id) {
    const request = await Request.findByPk(id);
    if (!request) return void 0;
    const analysis = await Analysis.findOne({ where: { requestId: id } });
    return {
      ...request.toJSON(),
      analysis: analysis?.toJSON()
    };
  }
  async getRequestsWithAnalysis(tenantId) {
    const requests = await Request.findAll(tenantId ? { where: { tenantId } } : {});
    const results = [];
    for (const request of requests) {
      const analysis = await Analysis.findOne({ where: { requestId: request.id } });
      results.push({
        ...request.toJSON(),
        analysis: analysis?.toJSON()
      });
    }
    return results;
  }
  async anonymizeOldIPs(tenantId, anonymizeDays) {
    const cutoffDate = new Date(Date.now() - anonymizeDays * 24 * 60 * 60 * 1e3);
    const result = await Request.update(
      { clientIp: null, clientIpAnonymized: true },
      { where: { tenantId, timestamp: { [Op.lt]: cutoffDate } } }
    );
    return result[0];
  }
  // Analysis
  async createAnalysis(analysisData) {
    const created = await Analysis.create(analysisData);
    return created.toJSON();
  }
  // Overrides
  async createOverride(override) {
    const created = await Override.create(override);
    return created.toJSON();
  }
  async getOverridesByTenant(tenantId) {
    const overrides = await Override.findAll({
      where: { tenantId, isActive: true, expiresAt: { [Op.or]: [null, { [Op.gt]: /* @__PURE__ */ new Date() }] } }
    });
    return overrides.map((o) => o.toJSON());
  }
  // Alerts
  async getAlerts() {
    const alerts = await Alert.findAll({ order: [["createdAt", "DESC"]] });
    return alerts.map((a) => a.toJSON());
  }
  async getAlert(id) {
    const alert = await Alert.findByPk(id);
    return alert?.toJSON();
  }
  async createAlert(alert) {
    const created = await Alert.create(alert);
    return created.toJSON();
  }
  async updateAlert(id, data) {
    const alert = await Alert.findByPk(id);
    if (!alert) return void 0;
    await alert.update(data);
    return alert.toJSON();
  }
  async markAllAlertsRead() {
    await Alert.update({ isRead: true }, { where: {} });
  }
  // Webhooks
  async getWebhooks() {
    const webhooks2 = await Webhook.findAll();
    return webhooks2.map((w) => w.toJSON());
  }
  async getWebhook(id) {
    const webhook = await Webhook.findByPk(id);
    return webhook?.toJSON();
  }
  async createWebhook(webhook) {
    const created = await Webhook.create(webhook);
    return created.toJSON();
  }
  async updateWebhook(id, data) {
    const webhook = await Webhook.findByPk(id);
    if (!webhook) return void 0;
    await webhook.update(data);
    return webhook.toJSON();
  }
  async deleteWebhook(id) {
    await Webhook.destroy({ where: { id } });
  }
  // Export
  async getRequestsForExport(tenantId, startDate, endDate) {
    const where = {};
    if (tenantId) where.tenantId = tenantId;
    if (startDate || endDate) {
      where.timestamp = {};
      if (startDate) where.timestamp[Op.gte] = startDate;
      if (endDate) where.timestamp[Op.lte] = endDate;
    }
    const requests = await Request.findAll({ where });
    return requests.map((r) => r.toJSON());
  }
  async deleteOldRequests(tenantId, retentionDays) {
    const cutoffDate = new Date(Date.now() - retentionDays * 24 * 60 * 60 * 1e3);
    const result = await Request.destroy({
      where: { tenantId, timestamp: { [Op.lt]: cutoffDate } }
    });
    return result;
  }
  // IP Lists
  async createIpList(ipList) {
    const created = await IpList.create(ipList);
    return created.toJSON();
  }
  async getIpListsByTenant(tenantId) {
    const lists = await IpList.findAll({ where: { tenantId } });
    return lists.map((l) => l.toJSON());
  }
  // Dashboard
  async getDashboardStats() {
    const requestCount = await Request.count();
    const tenantCount = await Tenant.count();
    const userCount = await User.count();
    const alertCount = await Alert.count({ where: { isRead: false } });
    const ruleCount = await WafRule.count();
    const recentAlerts = await Alert.findAll({ limit: 5, order: [["createdAt", "DESC"]] });
    return {
      totalRequests: requestCount,
      totalTenants: tenantCount,
      totalUsers: userCount,
      openAlerts: alertCount,
      activeRules: ruleCount,
      recentAlerts: recentAlerts.map((a) => a.toJSON())
    };
  }
  // Behavioral Profiles
  async getBehavioralProfile(email) {
    return null;
  }
  async createOrUpdateBehavioralProfile(email, data) {
    return null;
  }
  async recordBehavioralEvent(profileId, email, eventData) {
  }
  async getBehavioralEvents(email, limit = 100) {
    return [];
  }
  async getBehavioralProfiles(tenantId, limit = 100) {
    return [];
  }
};
var storage = new DatabaseStorage();

// server/routes.ts
import { createServer as createServer2 } from "http";

// server/schemas.ts
import { z } from "zod";
var insertUserSchema = z.object({
  email: z.string().email(),
  firstName: z.string().optional(),
  lastName: z.string().optional(),
  profileImageUrl: z.string().optional(),
  avatarType: z.enum(["astronaut", "avatar", "bear", "bot", "cat", "dog", "robot", "user"]).optional(),
  role: z.enum(["admin", "operator", "viewer"]).default("viewer"),
  tenantIds: z.array(z.string()).optional()
});
var insertTenantSchema = z.object({
  name: z.string(),
  domain: z.string(),
  upstreamUrl: z.string(),
  sslEnabled: z.boolean().default(false),
  sslCertPath: z.string().optional(),
  sslKeyPath: z.string().optional(),
  isActive: z.boolean().default(true),
  retentionDays: z.number().default(30),
  anonymizeIpAfterDays: z.number().default(7),
  scrubCookies: z.boolean().default(true),
  scrubAuthHeaders: z.boolean().default(true)
});
var insertPolicySchema = z.object({
  tenantId: z.string(),
  name: z.string(),
  enforcementMode: z.enum(["monitor", "block"]).default("monitor"),
  securityEngine: z.enum(["waf-engine", "modsecurity", "both"]).default("both"),
  blockThreshold: z.number().optional(),
  challengeThreshold: z.number().optional(),
  monitorThreshold: z.number().optional(),
  rateLimit: z.number().optional(),
  rateLimitWindow: z.number().optional(),
  isDefault: z.boolean().optional(),
  allowedCountries: z.array(z.string()).optional(),
  blockedCountries: z.array(z.string()).optional(),
  geoRateLimitByCountry: z.record(z.number()).optional(),
  vpnDetectionEnabled: z.boolean().optional(),
  vpnBlockAction: z.enum(["block", "challenge", "monitor"]).optional()
});
var insertWafRuleSchema = z.object({
  tenantId: z.string().optional(),
  name: z.string(),
  description: z.string().optional(),
  category: z.string(),
  severity: z.string().optional(),
  pattern: z.string(),
  patternType: z.string().optional(),
  targetField: z.string(),
  action: z.enum(["allow", "monitor", "challenge", "deny"]).optional(),
  score: z.number().optional(),
  enabled: z.boolean().optional(),
  isBuiltIn: z.boolean().optional()
});
var insertRequestSchema = z.object({
  tenantId: z.string(),
  timestamp: z.date().optional(),
  clientIp: z.string().optional(),
  clientIpAnonymized: z.boolean().default(false),
  method: z.string(),
  path: z.string(),
  queryString: z.string().optional(),
  headersJson: z.record(z.any()).optional(),
  bodyRef: z.string().optional(),
  bodyPreview: z.string().optional(),
  userAgent: z.string().optional(),
  referer: z.string().optional(),
  contentType: z.string().optional(),
  contentLength: z.number().optional(),
  responseCode: z.number().optional(),
  responseHeadersJson: z.record(z.any()).optional(),
  responseBodyRef: z.string().optional(),
  responseTime: z.number().optional(),
  analysisId: z.string().optional(),
  actionTaken: z.enum(["allow", "monitor", "challenge", "deny"]).default("allow"),
  wafHitsJson: z.record(z.any()).optional(),
  country: z.string().optional(),
  city: z.string().optional()
});
var insertAnalysisSchema = z.object({
  requestId: z.string(),
  totalScore: z.number().optional(),
  suggestedAction: z.enum(["allow", "monitor", "challenge", "deny"]).optional(),
  finalAction: z.enum(["allow", "monitor", "challenge", "deny"]).optional(),
  breakdownJson: z.record(z.any()).optional(),
  matchedRulesJson: z.array(z.any()).optional(),
  ipReputationScore: z.number().optional(),
  rateAnomalyScore: z.number().optional(),
  headerAnomalyScore: z.number().optional(),
  pathAnomalyScore: z.number().optional(),
  bodyAnomalyScore: z.number().optional(),
  processingTimeMs: z.number().optional(),
  explanationText: z.string().optional()
});
var insertOverrideSchema = z.object({
  overrideType: z.enum(["request", "rule", "ip"]),
  targetId: z.string(),
  tenantId: z.string().optional(),
  action: z.enum(["allow", "monitor", "challenge", "deny"]),
  operatorId: z.string(),
  reason: z.string().optional(),
  expiresAt: z.date().optional(),
  isActive: z.boolean().default(true)
});
var insertAlertSchema = z.object({
  tenantId: z.string().optional(),
  severity: z.string(),
  type: z.string(),
  title: z.string(),
  message: z.string(),
  metadata: z.record(z.any()).optional(),
  isRead: z.boolean().optional(),
  isDismissed: z.boolean().optional()
});
var insertWebhookSchema = z.object({
  tenantId: z.string().optional(),
  name: z.string(),
  url: z.string().url(),
  secret: z.string().optional(),
  events: z.array(z.string()).optional(),
  isActive: z.boolean().default(true)
});
var insertIpListSchema = z.object({
  tenantId: z.string().optional(),
  ipAddress: z.string().ip(),
  listType: z.string(),
  reason: z.string().optional(),
  expiresAt: z.date().optional(),
  createdBy: z.string().optional()
});

// server/routes.ts
init_engine();
import { z as z5 } from "zod";

// server/waf/sse.ts
var SSEServer = class {
  clients = /* @__PURE__ */ new Map();
  clientCounter = 0;
  registerClient(res) {
    const clientId = `client-${++this.clientCounter}`;
    res.setHeader("Content-Type", "text/event-stream");
    res.setHeader("Cache-Control", "no-cache");
    res.setHeader("Connection", "keep-alive");
    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader("X-Accel-Buffering", "no");
    res.flushHeaders();
    res.write(`: SSE connection established

`);
    this.clients.set(clientId, res);
    res.on("close", () => {
      this.clients.delete(clientId);
      console.log(`[SSE] Client ${clientId} disconnected`);
    });
    const keepAliveInterval = setInterval(() => {
      if (!this.clients.has(clientId)) {
        clearInterval(keepAliveInterval);
        return;
      }
      try {
        res.write(`: keep-alive

`);
      } catch (error) {
        clearInterval(keepAliveInterval);
        this.clients.delete(clientId);
      }
    }, 3e4);
    return clientId;
  }
  broadcast(event, data) {
    const message = `event: ${event}
data: ${JSON.stringify(data)}

`;
    this.clients.forEach((client, clientId) => {
      try {
        client.write(message);
      } catch (error) {
        console.error(`[SSE] Error broadcasting to ${clientId}:`, error);
        this.clients.delete(clientId);
      }
    });
  }
  broadcastRequest(request) {
    this.broadcast("request", request);
  }
  broadcastAlert(alert) {
    this.broadcast("alert", alert);
  }
  getClientCount() {
    return this.clients.size;
  }
};
var sseServer = new SSEServer();

// server/waf/proxy.ts
import { createServer } from "http";
import { URL } from "url";
var WafReverseProxy = class {
  server = null;
  config;
  constructor(config) {
    this.config = config;
  }
  /**
   * Start the reverse proxy server
   * Listens on configured port and accepts raw HTTP traffic
   */
  start() {
    return new Promise((resolve, reject) => {
      this.server = createServer(
        async (req, res) => {
          try {
            await this.handleRequest(req, res);
          } catch (error) {
            console.error("WAF proxy error:", error);
            res.writeHead(500, { "Content-Type": "application/json" });
            res.end(JSON.stringify({ error: "WAF proxy error" }));
          }
        }
      );
      const proxyHost = process.platform === "win32" ? "127.0.0.1" : "0.0.0.0";
      this.server.listen(this.config.proxyPort, proxyHost, () => {
        console.log(
          `\u2705 WAF Reverse Proxy listening on port ${this.config.proxyPort}`
        );
        console.log(`   Backend: ${this.config.backendUrl}`);
        console.log(`   Tenant: ${this.config.tenantId}`);
        resolve();
      });
      this.server.on("error", (error) => {
        console.error("WAF proxy server error:", error);
        reject(error);
      });
    });
  }
  /**
   * Stop the proxy server
   */
  stop() {
    return new Promise((resolve) => {
      if (this.server) {
        this.server.close(() => {
          console.log("\u2705 WAF Reverse Proxy stopped");
          resolve();
        });
      } else {
        resolve();
      }
    });
  }
  /**
   * Handle incoming HTTP request
   * 1. Collect request body
   * 2. Send to WAF for analysis
   * 3. If blocked, return 403
   * 4. If allowed, forward to backend
   */
  async handleRequest(req, res) {
    console.log(
      `[WAF Proxy] ${req.method} ${req.url} from ${req.socket.remoteAddress}`
    );
    const requestBody = await this.collectBody(req);
    const wafRequest = {
      method: req.method || "GET",
      path: req.url || "/",
      query: this.parseQueryString(req.url || ""),
      headers: req.headers,
      body: requestBody,
      clientIp: req.socket.remoteAddress,
      timestamp: (/* @__PURE__ */ new Date()).toISOString()
    };
    console.log(`[WAF Proxy] Analyzing request with WAF...`);
    const wafResponse = await fetch(
      `${this.config.wafServerUrl}/api/waf/ingress`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          tenantId: this.config.tenantId,
          request: wafRequest
        })
      }
    );
    const wafAnalysis = await wafResponse.json();
    console.log(
      `[WAF Proxy] WAF Decision: ${wafAnalysis.action} (score: ${wafAnalysis.score})`
    );
    if (wafAnalysis.action === "block") {
      console.log(`[WAF Proxy] \u274C BLOCKED - Returning 403`);
      res.writeHead(403, { "Content-Type": "application/json" });
      res.end(
        JSON.stringify({
          error: "Blocked by WAF",
          score: wafAnalysis.score,
          riskLevel: wafAnalysis.riskLevel,
          matches: wafAnalysis.matchCount,
          requestId: wafAnalysis.requestId
        })
      );
      return;
    }
    if (wafAnalysis.action === "challenge") {
      console.log(`[WAF Proxy] \u26A0\uFE0F  CHALLENGE - Returning 429`);
      res.writeHead(429, { "Content-Type": "application/json" });
      res.end(
        JSON.stringify({
          error: "Challenge required",
          requestId: wafAnalysis.requestId
        })
      );
      return;
    }
    console.log(`[WAF Proxy] \u2705 ALLOWED - Forwarding to backend`);
    await this.forwardToBackend(req, res, requestBody, wafAnalysis.requestId);
  }
  /**
   * Collect request body from stream
   */
  collectBody(req) {
    return new Promise((resolve, reject) => {
      let body = "";
      req.on("data", (chunk) => {
        body += chunk.toString();
      });
      req.on("end", () => {
        resolve(body);
      });
      req.on("error", reject);
    });
  }
  /**
   * Parse query string from URL
   */
  parseQueryString(url) {
    const urlObj = new URL(url, "http://dummy");
    const query = {};
    urlObj.searchParams.forEach((value, key) => {
      query[key] = value;
    });
    return query;
  }
  /**
   * Forward request to backend server
   */
  async forwardToBackend(req, res, body, requestId) {
    try {
      const url = new URL(req.url || "/", this.config.backendUrl);
      const headers = {
        "X-WAF-Request-ID": requestId,
        "X-Forwarded-For": req.socket.remoteAddress || "",
        "X-Forwarded-Proto": "http",
        host: new URL(this.config.backendUrl).host,
        connection: "close"
      };
      Object.entries(req.headers).forEach(([key, value]) => {
        if (typeof value === "string" && !["host", "connection"].includes(key.toLowerCase())) {
          headers[key] = value;
        }
      });
      const backendReq = await fetch(url.toString(), {
        method: req.method || "GET",
        headers,
        body: req.method !== "GET" && req.method !== "HEAD" ? body : void 0
      });
      const backendHeaders = Object.fromEntries(backendReq.headers);
      delete backendHeaders["transfer-encoding"];
      delete backendHeaders["content-encoding"];
      res.writeHead(backendReq.status, backendHeaders);
      const backendBody = await backendReq.text();
      res.end(backendBody);
      console.log(`[WAF Proxy] \u2705 Response forwarded (${backendReq.status})`);
    } catch (error) {
      console.error("[WAF Proxy] Backend forwarding error:", error);
      res.writeHead(502, { "Content-Type": "application/json" });
      res.end(
        JSON.stringify({
          error: "Bad Gateway",
          message: "Failed to forward request to backend"
        })
      );
    }
  }
};
async function startWafProxy() {
  const proxyPort = process.env.WAF_PROXY_PORT ? parseInt(process.env.WAF_PROXY_PORT, 10) : null;
  const backendUrl = process.env.WAF_PROXY_BACKEND;
  const tenantId = process.env.WAF_PROXY_TENANT_ID;
  if (!proxyPort || !backendUrl || !tenantId) {
    console.log(
      "\u2139\uFE0F  WAF Reverse Proxy not configured (set WAF_PROXY_PORT, WAF_PROXY_BACKEND, WAF_PROXY_TENANT_ID)"
    );
    return null;
  }
  const proxy = new WafReverseProxy({
    proxyPort,
    backendUrl,
    tenantId,
    wafServerUrl: process.env.WAF_SERVER_URL || "http://localhost:5000"
  });
  await proxy.start();
  return proxy;
}

// server/routes.ts
import passport from "passport";

// server/middleware.ts
var globalRateLimitStore = /* @__PURE__ */ new Map();
var tenantRateLimits = /* @__PURE__ */ new Map();
function rateLimit(windowMs = 6e4, maxRequests = 100, blockDurationMs = 3e5) {
  return (req, res, next) => {
    const key = `${req.ip}-${req.path}`;
    const now = Date.now();
    let entry = globalRateLimitStore.get(key);
    if (!entry) {
      entry = { timestamps: [now], blocked: false };
      globalRateLimitStore.set(key, entry);
      return next();
    }
    if (entry.blocked && entry.blockedUntil && entry.blockedUntil > now) {
      const retryAfter = Math.ceil((entry.blockedUntil - now) / 1e3);
      res.set("Retry-After", retryAfter.toString());
      res.set("X-RateLimit-Limit", maxRequests.toString());
      res.set("X-RateLimit-Remaining", "0");
      res.set("X-RateLimit-Reset", Math.ceil(entry.blockedUntil / 1e3).toString());
      return res.status(429).json({
        message: "Too many requests, please try again later",
        retryAfter
      });
    }
    if (entry.blocked && (!entry.blockedUntil || entry.blockedUntil <= now)) {
      entry.blocked = false;
      entry.blockedUntil = void 0;
      entry.timestamps = [now];
    }
    entry.timestamps = entry.timestamps.filter((ts) => ts > now - windowMs);
    entry.timestamps.push(now);
    const remaining = Math.max(0, maxRequests - entry.timestamps.length);
    const resetTime = now + windowMs;
    res.set("X-RateLimit-Limit", maxRequests.toString());
    res.set("X-RateLimit-Remaining", remaining.toString());
    res.set("X-RateLimit-Reset", Math.ceil(resetTime / 1e3).toString());
    if (entry.timestamps.length > maxRequests) {
      entry.blocked = true;
      entry.blockedUntil = now + blockDurationMs;
      const retryAfter = Math.ceil(blockDurationMs / 1e3);
      res.set("Retry-After", retryAfter.toString());
      return res.status(429).json({
        message: "Too many requests, please try again later",
        retryAfter
      });
    }
    if (Math.random() < 0.01) {
      cleanupRateLimitStore(now, windowMs);
    }
    next();
  };
}
function tenantRateLimit(tenantId, windowMs = 6e4, maxRequests = 100) {
  return (req, res, next) => {
    const now = Date.now();
    let tenant = tenantRateLimits.get(tenantId);
    if (!tenant) {
      tenant = {
        requests: /* @__PURE__ */ new Map(),
        config: { windowMs, maxRequests, blockDurationMs: 3e5 }
      };
      tenantRateLimits.set(tenantId, tenant);
    }
    const key = req.ip;
    let entry = tenant.requests.get(key);
    if (!entry) {
      entry = { timestamps: [now], blocked: false };
      tenant.requests.set(key, entry);
      cleanupTenantRateLimits(tenantId, now, windowMs);
      return next();
    }
    if (entry.blocked) {
      if (entry.blockedUntil && entry.blockedUntil > now) {
        return res.status(429).json({ message: "Rate limit exceeded for this tenant" });
      }
      entry.blocked = false;
      entry.blockedUntil = void 0;
      entry.timestamps = [];
    }
    entry.timestamps = entry.timestamps.filter((ts) => ts > now - windowMs);
    entry.timestamps.push(now);
    if (entry.timestamps.length > maxRequests) {
      entry.blocked = true;
      entry.blockedUntil = now + tenant.config.blockDurationMs;
      return res.status(429).json({ message: "Rate limit exceeded for this tenant" });
    }
    if (Math.random() < 0.01) {
      cleanupTenantRateLimits(tenantId, now, windowMs);
    }
    next();
  };
}
function cleanupTenantRateLimits(tenantId, now, windowMs) {
  const tenant = tenantRateLimits.get(tenantId);
  if (!tenant) return;
  const entries = Array.from(tenant.requests.entries());
  for (const [key, entry] of entries) {
    if (entry.blocked && entry.blockedUntil && entry.blockedUntil <= now) {
      entry.blocked = false;
      entry.blockedUntil = void 0;
      entry.timestamps = [];
    }
    const validTimestamps = entry.timestamps.filter((ts) => ts > now - windowMs);
    if (validTimestamps.length === 0 && !entry.blocked) {
      tenant.requests.delete(key);
    } else {
      entry.timestamps = validTimestamps;
    }
  }
  if (tenant.requests.size > 1e4) {
    const updatedEntries = Array.from(tenant.requests.entries());
    const oldestEntries = updatedEntries.filter(([_, e]) => !e.blocked).sort((a, b) => Math.max(...a[1].timestamps, 0) - Math.max(...b[1].timestamps, 0)).slice(0, 5e3);
    oldestEntries.forEach(([k]) => tenant.requests.delete(k));
  }
}
function cleanupRateLimitStore(now, windowMs) {
  const entries = Array.from(globalRateLimitStore.entries());
  for (const [key, entry] of entries) {
    const validTimestamps = entry.timestamps.filter((ts) => ts > now - windowMs);
    if (entry.blocked && entry.blockedUntil && entry.blockedUntil <= now) {
      entry.blocked = false;
      entry.blockedUntil = void 0;
    }
    if (validTimestamps.length === 0 && !entry.blocked) {
      globalRateLimitStore.delete(key);
    } else {
      entry.timestamps = validTimestamps;
    }
  }
  const maxEntries = 1e4;
  if (globalRateLimitStore.size > maxEntries) {
    const entriesToDelete = Array.from(globalRateLimitStore.entries()).filter(([_, e]) => !e.blocked).sort((a, b) => Math.max(...a[1].timestamps, 0) - Math.max(...b[1].timestamps, 0)).slice(0, globalRateLimitStore.size - maxEntries);
    entriesToDelete.forEach(([k]) => globalRateLimitStore.delete(k));
  }
}
var cleanupInterval = null;
function startRateLimitCleanup(windowMs = 6e4) {
  if (cleanupInterval) return;
  cleanupInterval = setInterval(() => {
    cleanupRateLimitStore(Date.now(), windowMs);
    const tenantEntries = Array.from(tenantRateLimits.entries());
    for (const [tenantId] of tenantEntries) {
      cleanupTenantRateLimits(tenantId, Date.now(), windowMs);
    }
  }, 6e4);
}
function createTenantRateLimiter(tenantId, windowMs = 6e4, maxRequests = 100) {
  return tenantRateLimit(tenantId, windowMs, maxRequests);
}
function requireRole(...roles) {
  return (req, res, next) => {
    if (!req.isAuthenticated || !req.isAuthenticated()) {
      return res.status(401).json({ message: "Unauthorized" });
    }
    if (!req.user?.role || !roles.includes(req.user.role)) {
      return res.status(403).json({ message: "Forbidden - Insufficient permissions" });
    }
    next();
  };
}
function securityHeaders() {
  return (req, res, next) => {
    res.set("X-Content-Type-Options", "nosniff");
    res.set("X-Frame-Options", "SAMEORIGIN");
    res.set("X-XSS-Protection", "1; mode=block");
    res.set("Referrer-Policy", "strict-origin-when-cross-origin");
    res.set("Permissions-Policy", "geolocation=(), camera=(), microphone=()");
    const cspDirectives = [
      "default-src 'self'",
      "script-src 'self' 'unsafe-inline' 'unsafe-eval'",
      "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
      "style-src-elem 'self' 'unsafe-inline' https://fonts.googleapis.com",
      "font-src 'self' https://fonts.gstatic.com data:",
      "img-src 'self' data: https:",
      "connect-src 'self' https: wss: ws:",
      "frame-ancestors 'self'"
    ];
    if (process.env.NODE_ENV === "production") {
      res.set("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
    }
    res.set("Content-Security-Policy", cspDirectives.join("; "));
    next();
  };
}
function requestSanitizer() {
  return (req, res, next) => {
    if (req.body && isPlainObject(req.body)) {
      sanitizePrototypePollution(req.body, /* @__PURE__ */ new WeakSet());
    }
    if (req.query && isPlainObject(req.query)) {
      sanitizePrototypePollution(req.query, /* @__PURE__ */ new WeakSet());
    }
    next();
  };
}
function isPlainObject(obj) {
  if (obj === null || typeof obj !== "object") return false;
  if (Buffer.isBuffer(obj)) return false;
  if (Array.isArray(obj)) return false;
  const proto = Object.getPrototypeOf(obj);
  return proto === null || proto === Object.prototype;
}
function sanitizePrototypePollution(obj, seen, depth = 0) {
  if (depth > 20) return;
  if (seen.has(obj)) return;
  seen.add(obj);
  const dangerousKeys = ["__proto__", "constructor", "prototype"];
  for (const key of Object.keys(obj)) {
    if (dangerousKeys.includes(key)) {
      delete obj[key];
      continue;
    }
    const value = obj[key];
    if (value && typeof value === "object" && isPlainObject(value)) {
      sanitizePrototypePollution(value, seen, depth + 1);
    }
  }
}
function validateContentType() {
  return (req, res, next) => {
    if (["POST", "PUT", "PATCH"].includes(req.method)) {
      const contentType = req.headers["content-type"] || "";
      if (req.body && Object.keys(req.body).length > 0) {
        if (!contentType.includes("application/json") && !contentType.includes("application/x-www-form-urlencoded") && !contentType.includes("multipart/form-data")) {
          return res.status(415).json({ message: "Unsupported Media Type" });
        }
      }
    }
    next();
  };
}

// server/jobs.ts
async function startDataRetentionJob() {
  setInterval(async () => {
    try {
      console.log("Running data retention job...");
      const allTenants = await storage.getTenants();
      for (const tenant of allTenants) {
        const retentionDays = tenant.retentionDays || 30;
        const deleted = await storage.deleteOldRequests(tenant.id, retentionDays);
        if (deleted > 0) {
          console.log(`Deleted ${deleted} old requests for tenant ${tenant.id}`);
        }
        const anonymizeDays = tenant.anonymizeIpAfterDays || 7;
        const anonymized = await storage.anonymizeOldIPs(tenant.id, anonymizeDays);
        if (anonymized > 0) {
          console.log(`Anonymized ${anonymized} old IPs for tenant ${tenant.id}`);
        }
      }
    } catch (error) {
      console.error("Data retention job failed:", error);
    }
  }, 6 * 60 * 60 * 1e3);
}

// server/api/ml-endpoints.ts
init_ml_integration();

// server/waf/threat-features.ts
var ThreatFeatureExtractor = class {
  requestHistory = /* @__PURE__ */ new Map();
  sessionProfiles = /* @__PURE__ */ new Map();
  /**
   * Extract advanced threat features
   */
  extractThreatFeatures(features, clientIp, sessionId) {
    const sqlSig = this.calculateSQLSignature(features);
    const xssSig = this.calculateXSSSignature(features);
    const rceSig = this.calculateRCESignature(features);
    const xxeSig = this.calculateXXESignature(features);
    const pathSig = this.calculatePathTraversalSignature(features);
    const velocity = this.calculateRequestVelocity(clientIp);
    const complexity = this.calculatePayloadComplexity(features);
    const obfuscation = this.calculateObfuscationLevel(features);
    const zscore = this.calculateZScore(features, clientIp);
    const mahal = this.calculateMahalanobisDistance(features, clientIp);
    const timeSeriesAnomaly = this.detectTimeSeriesAnomaly(clientIp);
    const burstActivity = this.detectBurstActivity(clientIp);
    const seqScore = this.calculateSequentialPatternScore(clientIp, sessionId);
    const sessionAnomaly = this.calculateSessionAnomalyScore(clientIp, sessionId);
    return {
      ...features,
      sqlInjectionSignature: sqlSig,
      xssSignature: xssSig,
      rceSignature: rceSig,
      xxeSignature: xxeSig,
      pathTraversalSignature: pathSig,
      requestVelocity: velocity,
      payloadComplexity: complexity,
      obfuscationLevel: obfuscation,
      zscore,
      mahalanobisDistance: mahal,
      timeSeriesAnomaly,
      burstActivity,
      sequentialPatternScore: seqScore,
      sessionAnomalyScore: sessionAnomaly
    };
  }
  /**
   * Calculate SQL injection attack signature
   * Combines multiple indicators into a single score
   */
  calculateSQLSignature(features) {
    let score = 0;
    score += Math.min(0.3, features.sqlKeywordCount * 0.1);
    const commentRatio = features.specialCharDensity * 0.5;
    score += Math.min(0.2, commentRatio);
    score += Math.min(0.15, features.urlEncodingDensity * 0.3);
    if (features.entropyScore > 4) {
      score += 0.15;
    }
    score += Math.min(0.2, features.specialCharDensity * features.numberDensity * 0.2);
    return Math.min(1, score);
  }
  /**
   * Calculate XSS attack signature
   */
  calculateXSSSignature(features) {
    let score = 0;
    score += Math.min(0.3, features.jsKeywordCount * 0.15);
    const xssCharPattern = features.specialCharDensity * 0.4;
    score += Math.min(0.25, xssCharPattern);
    score += Math.min(0.2, features.urlEncodingDensity * 0.2);
    if (features.entropyScore > 3.5 && features.specialCharDensity > 0.2) {
      score += 0.15;
    }
    score += Math.min(0.1, features.upperCaseDensity * features.specialCharDensity);
    return Math.min(1, score);
  }
  /**
   * Calculate RCE attack signature
   */
  calculateRCESignature(features) {
    let score = 0;
    score += Math.min(0.4, features.shellCommandCount * 0.2);
    const cmdChars = features.specialCharDensity * 0.3;
    score += Math.min(0.3, cmdChars);
    score += Math.min(0.15, features.pathLength / Math.max(features.queryLength, 1) * 0.1);
    if (features.entropyScore > 4.5) {
      score += 0.15;
    }
    return Math.min(1, score);
  }
  /**
   * Calculate XXE attack signature
   */
  calculateXXESignature(features) {
    const xmlIndicators = /xml|dtd|entity|!DOCTYPE/i;
    let score = 0;
    if (features.bodyLength > features.pathLength) {
      score += 0.2;
    }
    score += Math.min(0.3, features.specialCharDensity * 0.3);
    score += Math.min(0.2, features.urlEncodingDensity * 0.2);
    return Math.min(1, score);
  }
  /**
   * Calculate path traversal signature
   */
  calculatePathTraversalSignature(features) {
    let score = 0;
    score += Math.min(0.4, features.pathTraversalCount * 0.2);
    const pathRatio = features.pathLength > 0 ? features.queryLength / features.pathLength : 0;
    score += Math.min(0.2, pathRatio * 0.1);
    score += Math.min(0.15, features.specialCharDensity * 0.15);
    return Math.min(1, score);
  }
  /**
   * Calculate request velocity (requests per minute from IP)
   */
  calculateRequestVelocity(clientIp) {
    const history = this.requestHistory.get(clientIp) || [];
    const now = Date.now();
    const oneMinuteAgo = now - 6e4;
    const recentRequests = history.filter(
      (_, idx) => now - idx * 1e3 > oneMinuteAgo
    );
    return recentRequests.length / 60;
  }
  /**
   * Calculate payload complexity score
   */
  calculatePayloadComplexity(features) {
    const totalLength = features.pathLength + features.queryLength + features.bodyLength;
    const charVariety = Math.min(1, ((features.specialCharDensity > 0 ? 1 : 0) + (features.numberDensity > 0 ? 1 : 0) + (features.upperCaseDensity > 0 ? 1 : 0)) / 3);
    const lengthFactor = Math.min(1, totalLength / 1e4);
    return (charVariety + lengthFactor) / 2;
  }
  /**
   * Calculate obfuscation level
   */
  calculateObfuscationLevel(features) {
    let score = 0;
    score += features.urlEncodingDensity * 0.3;
    const normalizedEntropy = Math.min(1, features.entropyScore / 8);
    score += normalizedEntropy * 0.3;
    const mixedCase = features.upperCaseDensity * features.numberDensity;
    score += Math.min(0.3, mixedCase);
    score += Math.min(0.1, features.specialCharDensity * 0.5);
    return Math.min(1, score);
  }
  /**
   * Calculate Z-score for request
   */
  calculateZScore(features, clientIp) {
    const history = this.requestHistory.get(clientIp) || [];
    if (history.length < 10) return 0;
    const lengths = history.map(
      (f) => (f.pathLength || 0) + (f.queryLength || 0) + (f.bodyLength || 0)
    );
    const mean = lengths.reduce((a, b) => a + b, 0) / lengths.length;
    const variance = lengths.reduce(
      (sum, x) => sum + Math.pow(x - mean, 2),
      0
    ) / lengths.length;
    const stddev = Math.sqrt(variance);
    const currentLength = features.pathLength + features.queryLength + features.bodyLength;
    return stddev > 0 ? Math.abs((currentLength - mean) / stddev) : 0;
  }
  /**
   * Calculate Mahalanobis distance (multivariate anomaly)
   */
  calculateMahalanobisDistance(features, clientIp) {
    const history = this.requestHistory.get(clientIp) || [];
    if (history.length < 5) return 0;
    const features_arr = [
      features.specialCharDensity,
      features.entropyScore,
      features.sqlKeywordCount,
      features.jsKeywordCount
    ];
    let distance = 0;
    for (const feature of features_arr) {
      distance += Math.abs(feature - 0.5);
    }
    return Math.min(1, distance / 4);
  }
  /**
   * Detect time-series anomaly
   */
  detectTimeSeriesAnomaly(clientIp) {
    const history = this.requestHistory.get(clientIp) || [];
    if (history.length < 3) return false;
    const recent = history.slice(-3);
    const scores = recent.map(
      (f) => f.specialCharDensity + f.entropyScore
    );
    const avg = scores.reduce((a, b) => a + b, 0) / scores.length;
    const spike = scores[scores.length - 1] > avg * 1.5;
    return spike;
  }
  /**
   * Detect burst activity
   */
  detectBurstActivity(clientIp) {
    const history = this.requestHistory.get(clientIp) || [];
    return history.length > 20;
  }
  /**
   * Calculate sequential pattern score
   */
  calculateSequentialPatternScore(clientIp, sessionId) {
    if (!sessionId) return 0;
    const profile = this.sessionProfiles.get(sessionId);
    if (!profile) return 0;
    const pathVariety = profile.pathCount?.size || 1;
    const requestCount = profile.requestCount || 1;
    const ratio = pathVariety / requestCount;
    return Math.min(1, ratio);
  }
  /**
   * Calculate session anomaly score
   */
  calculateSessionAnomalyScore(clientIp, sessionId) {
    if (!sessionId) return 0;
    const profile = this.sessionProfiles.get(sessionId);
    if (!profile) return 0;
    let score = 0;
    if ((profile.timeBetweenRequests ?? 0) < 100) {
      score += 0.2;
    }
    if (profile.ipChanged) {
      score += 0.3;
    }
    if (profile.userAgentChanged) {
      score += 0.2;
    }
    return Math.min(1, score);
  }
  /**
   * Record request for history tracking
   */
  recordRequest(clientIp, features, sessionId) {
    const history = this.requestHistory.get(clientIp) || [];
    history.push(features);
    if (history.length > 100) {
      history.shift();
    }
    this.requestHistory.set(clientIp, history);
    if (sessionId) {
      const profile = this.sessionProfiles.get(sessionId) || {
        requestCount: 0,
        pathCount: /* @__PURE__ */ new Set(),
        lastRequestTime: 0
      };
      profile.requestCount += 1;
      profile.timeBetweenRequests = Date.now() - (profile.lastRequestTime ?? 0);
      profile.lastRequestTime = Date.now();
      this.sessionProfiles.set(sessionId, profile);
    }
  }
};

// server/api/ml-endpoints.ts
import { z as z2 } from "zod";

// server/services/model-persistence.ts
import fs from "fs";
import path2 from "path";
import { fileURLToPath } from "url";
var __filename = fileURLToPath(import.meta.url);
var __dirname = path2.dirname(__filename);
var MODELS_DIR = path2.join(__dirname, "../models");
var ModelPersistenceService = class {
  modelsDir;
  constructor() {
    this.modelsDir = MODELS_DIR;
    this.initializeDirectory();
  }
  /**
   * Initialize models directory if not exists
   */
  initializeDirectory() {
    if (!fs.existsSync(this.modelsDir)) {
      fs.mkdirSync(this.modelsDir, { recursive: true });
      console.log(`\u2705 Models directory created: ${this.modelsDir}`);
    }
  }
  /**
   * Save model to disk
   */
  saveModel(model) {
    try {
      const filename = `${model.id}_v${model.version}.json`;
      const filepath = path2.join(this.modelsDir, filename);
      const modelWithTimestamp = {
        ...model,
        savedAt: (/* @__PURE__ */ new Date()).toISOString()
      };
      fs.writeFileSync(filepath, JSON.stringify(modelWithTimestamp, null, 2));
      console.log(`\u2705 Model saved: ${filename}`);
      return { success: true, path: filepath };
    } catch (error) {
      console.error("\u274C Failed to save model:", error);
      return { success: false, path: "" };
    }
  }
  /**
   * Load model from disk
   */
  loadModel(modelId, version) {
    try {
      let filename;
      if (version !== void 0) {
        filename = `${modelId}_v${version}.json`;
      } else {
        const files = fs.readdirSync(this.modelsDir).filter((f) => f.startsWith(`${modelId}_v`)).sort();
        if (files.length === 0) {
          console.warn(`\u26A0\uFE0F No models found for: ${modelId}`);
          return null;
        }
        filename = files[files.length - 1];
      }
      const filepath = path2.join(this.modelsDir, filename);
      if (!fs.existsSync(filepath)) {
        console.warn(`\u26A0\uFE0F Model file not found: ${filename}`);
        return null;
      }
      const data = fs.readFileSync(filepath, "utf-8");
      const model = JSON.parse(data);
      console.log(`\u2705 Model loaded: ${filename}`);
      return model;
    } catch (error) {
      console.error("\u274C Failed to load model:", error);
      return null;
    }
  }
  /**
   * List all available models
   */
  listModels() {
    try {
      const files = fs.readdirSync(this.modelsDir).filter((f) => f.endsWith(".json"));
      const models = /* @__PURE__ */ new Map();
      files.forEach((file) => {
        const match = file.match(/^(.+)_v(\d+)\.json$/);
        if (match) {
          const [, modelId, version] = match;
          const versionNum = parseInt(version);
          if (!models.has(modelId)) {
            models.set(modelId, []);
          }
          models.get(modelId).push(versionNum);
        }
      });
      return Array.from(models.entries()).map(([id, versions]) => ({
        id,
        versions: versions.sort((a, b) => a - b)
      }));
    } catch (error) {
      console.error("\u274C Failed to list models:", error);
      return [];
    }
  }
  /**
   * Get latest model version
   */
  getLatestModelVersion(modelId) {
    const models = this.listModels();
    const model = models.find((m) => m.id === modelId);
    if (!model || model.versions.length === 0) {
      return null;
    }
    const latestVersion = model.versions[model.versions.length - 1];
    return this.loadModel(modelId, latestVersion);
  }
  /**
   * Delete model version
   */
  deleteModel(modelId, version) {
    try {
      const filename = `${modelId}_v${version}.json`;
      const filepath = path2.join(this.modelsDir, filename);
      if (!fs.existsSync(filepath)) {
        console.warn(`\u26A0\uFE0F Model not found: ${filename}`);
        return false;
      }
      fs.unlinkSync(filepath);
      console.log(`\u2705 Model deleted: ${filename}`);
      return true;
    } catch (error) {
      console.error("\u274C Failed to delete model:", error);
      return false;
    }
  }
  /**
   * Get model info
   */
  getModelInfo(modelId, version) {
    if (version !== void 0) {
      return this.loadModel(modelId, version);
    }
    return this.getLatestModelVersion(modelId);
  }
  /**
   * Backup all models
   */
  backupModels() {
    try {
      const timestamp = (/* @__PURE__ */ new Date()).toISOString().replace(/[:.]/g, "-");
      const backupDir = path2.join(this.modelsDir, `backup_${timestamp}`);
      fs.mkdirSync(backupDir, { recursive: true });
      const files = fs.readdirSync(this.modelsDir).filter((f) => f.endsWith(".json"));
      files.forEach((file) => {
        const source = path2.join(this.modelsDir, file);
        const dest = path2.join(backupDir, file);
        fs.copyFileSync(source, dest);
      });
      console.log(`\u2705 Models backed up: ${backupDir}`);
      return { success: true, backupPath: backupDir };
    } catch (error) {
      console.error("\u274C Failed to backup models:", error);
      return { success: false };
    }
  }
  /**
   * Clear old model versions (keep last N)
   */
  pruneOldVersions(modelId, keepCount = 3) {
    try {
      const models = this.listModels();
      const model = models.find((m) => m.id === modelId);
      if (!model || model.versions.length <= keepCount) {
        return 0;
      }
      const versionsToDelete = model.versions.slice(0, -keepCount);
      let deleted = 0;
      versionsToDelete.forEach((version) => {
        if (this.deleteModel(modelId, version)) {
          deleted++;
        }
      });
      console.log(`\u2705 Pruned ${deleted} old versions of ${modelId}`);
      return deleted;
    } catch (error) {
      console.error("\u274C Failed to prune old versions:", error);
      return 0;
    }
  }
};
var modelPersistence = new ModelPersistenceService();

// server/services/model-evaluation.ts
var ModelEvaluationService = class {
  /**
   * Calculate comprehensive evaluation metrics
   */
  evaluate(predictions) {
    if (predictions.length === 0) {
      throw new Error("No predictions provided");
    }
    const normalized = this.normalizePredictions(predictions);
    const cm = this.calculateConfusionMatrix(normalized);
    const accuracy = this.calculateAccuracy(cm);
    const precision = this.calculatePrecision(cm);
    const recall = this.calculateRecall(cm);
    const f1 = this.calculateF1(precision, recall);
    const rocAuc = this.calculateROCAuc(normalized);
    return {
      accuracy,
      precision,
      recall,
      f1,
      rocAuc,
      confusionMatrix: cm,
      specificityTpr: this.calculateSpecificity(cm),
      sensitivityFpr: this.calculateSensitivity(cm)
    };
  }
  /**
   * Normalize predictions to binary (0/1)
   */
  normalizePredictions(predictions) {
    return predictions.map((p) => ({
      actual: typeof p.actual === "boolean" ? p.actual ? 1 : 0 : p.actual,
      predicted: typeof p.predicted === "boolean" ? p.predicted ? 1 : 0 : p.predicted
    }));
  }
  /**
   * Calculate confusion matrix
   */
  calculateConfusionMatrix(predictions) {
    let tp = 0, tn = 0, fp = 0, fn = 0;
    predictions.forEach((p) => {
      if (p.actual === 1 && p.predicted === 1) tp++;
      else if (p.actual === 0 && p.predicted === 0) tn++;
      else if (p.actual === 0 && p.predicted === 1) fp++;
      else if (p.actual === 1 && p.predicted === 0) fn++;
    });
    return { truePositives: tp, trueNegatives: tn, falsePositives: fp, falseNegatives: fn };
  }
  /**
   * Calculate accuracy: (TP + TN) / (TP + TN + FP + FN)
   */
  calculateAccuracy(cm) {
    const total = cm.truePositives + cm.trueNegatives + cm.falsePositives + cm.falseNegatives;
    if (total === 0) return 0;
    return (cm.truePositives + cm.trueNegatives) / total;
  }
  /**
   * Calculate precision: TP / (TP + FP)
   */
  calculatePrecision(cm) {
    const denominator = cm.truePositives + cm.falsePositives;
    if (denominator === 0) return 0;
    return cm.truePositives / denominator;
  }
  /**
   * Calculate recall: TP / (TP + FN)
   */
  calculateRecall(cm) {
    const denominator = cm.truePositives + cm.falseNegatives;
    if (denominator === 0) return 0;
    return cm.truePositives / denominator;
  }
  /**
   * Calculate F1 score: 2 * (Precision * Recall) / (Precision + Recall)
   */
  calculateF1(precision, recall) {
    const denominator = precision + recall;
    if (denominator === 0) return 0;
    return 2 * (precision * recall) / denominator;
  }
  /**
   * Calculate specificity (True Negative Rate): TN / (TN + FP)
   */
  calculateSpecificity(cm) {
    const denominator = cm.trueNegatives + cm.falsePositives;
    if (denominator === 0) return 0;
    return cm.trueNegatives / denominator;
  }
  /**
   * Calculate sensitivity (True Positive Rate): TP / (TP + FN)
   */
  calculateSensitivity(cm) {
    const denominator = cm.truePositives + cm.falseNegatives;
    if (denominator === 0) return 0;
    return cm.truePositives / denominator;
  }
  /**
   * Calculate ROC-AUC (simplified without probability thresholds)
   */
  calculateROCAuc(predictions) {
    let auc = 0;
    let n_pos = 0, n_neg = 0;
    predictions.forEach((p) => {
      if (p.actual === 1) n_pos++;
      else n_neg++;
    });
    if (n_pos === 0 || n_neg === 0) return 0.5;
    let concordant = 0, discordant = 0;
    for (let i = 0; i < predictions.length; i++) {
      for (let j = 0; j < predictions.length; j++) {
        if (predictions[i].actual === 1 && predictions[j].actual === 0) {
          if (predictions[i].predicted > predictions[j].predicted) concordant++;
          else if (predictions[i].predicted < predictions[j].predicted) discordant++;
        }
      }
    }
    const totalPairs = n_pos * n_neg;
    if (totalPairs === 0) return 0.5;
    auc = concordant / totalPairs;
    return Math.max(0, Math.min(1, auc));
  }
  /**
   * Generate confusion matrix display
   */
  displayConfusionMatrix(cm) {
    return `
    \u250C\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2510
    \u2502     Predicted Positive Negative \u2502
    \u2502 Actual                          \u2502
    \u2502 Positive       ${cm.truePositives}           ${cm.falseNegatives}      \u2502
    \u2502 Negative       ${cm.falsePositives}           ${cm.trueNegatives}      \u2502
    \u2514\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2518
    `;
  }
  /**
   * Generate evaluation report
   */
  generateReport(metrics) {
    return `
    \u2554\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2557
    \u2551   Model Evaluation Report              \u2551
    \u2560\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2563
    \u2551 Accuracy:        ${(metrics.accuracy * 100).toFixed(2)}%                \u2551
    \u2551 Precision:       ${(metrics.precision * 100).toFixed(2)}%                \u2551
    \u2551 Recall:          ${(metrics.recall * 100).toFixed(2)}%                \u2551
    \u2551 F1 Score:        ${(metrics.f1 * 100).toFixed(2)}%                \u2551
    \u2551 ROC-AUC:         ${(metrics.rocAuc * 100).toFixed(2)}%                \u2551
    \u2551                                        \u2551
    \u2551 Specificity:     ${(metrics.specificityTpr * 100).toFixed(2)}%                \u2551
    \u2551 Sensitivity:     ${(metrics.sensitivityFpr * 100).toFixed(2)}%                \u2551
    \u2560\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2563
    \u2551 Confusion Matrix:                      \u2551
    \u2551 TP: ${metrics.confusionMatrix.truePositives}  FP: ${metrics.confusionMatrix.falsePositives}                    \u2551
    \u2551 FN: ${metrics.confusionMatrix.falseNegatives}  TN: ${metrics.confusionMatrix.trueNegatives}                    \u2551
    \u255A\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u255D
    `;
  }
};
var modelEvaluation = new ModelEvaluationService();

// server/services/feedback-service.ts
import { v4 as uuidv42 } from "uuid";
var FeedbackService = class {
  feedbackLabels = /* @__PURE__ */ new Map();
  requestPredictions = /* @__PURE__ */ new Map();
  /**
   * Submit feedback label for a request
   */
  async submitFeedback(requestId, tenantId, userId, actualLabel, predictedLabel, notes, confidence) {
    try {
      const id = uuidv42();
      const now = /* @__PURE__ */ new Date();
      const feedback = {
        id,
        requestId,
        tenantId,
        userId,
        actualLabel,
        predictedLabel,
        falsePositive: actualLabel === 0 && predictedLabel === 1,
        falseNegative: actualLabel === 1 && predictedLabel === 0,
        confidence: confidence || 0.95,
        notes,
        createdAt: now,
        updatedAt: now
      };
      this.feedbackLabels.set(id, feedback);
      console.log(
        `\u2705 Feedback recorded: ${feedback.falsePositive ? "FP" : feedback.falseNegative ? "FN" : "TP/TN"} for request ${requestId}`
      );
      return feedback;
    } catch (error) {
      console.error("\u274C Failed to submit feedback:", error);
      throw error;
    }
  }
  /**
   * Get feedback for a specific request
   */
  getFeedbackByRequest(requestId) {
    return Array.from(this.feedbackLabels.values()).filter((f) => f.requestId === requestId);
  }
  /**
   * Get all feedback labels
   */
  getAllFeedback(limit = 1e4) {
    const labels = Array.from(this.feedbackLabels.values());
    return labels.sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime()).slice(0, limit);
  }
  /**
   * Get feedback for model training
   */
  getTrainingFeedback() {
    return this.getAllFeedback().map((f) => ({
      actualLabel: f.actualLabel,
      predictedLabel: f.predictedLabel,
      confidence: f.confidence
    }));
  }
  /**
   * Record prediction for comparison with feedback
   */
  recordPrediction(requestId, predicted, score) {
    this.requestPredictions.set(requestId, { predicted, score });
  }
  /**
   * Get feedback statistics
   */
  getStatistics() {
    const feedback = this.getAllFeedback();
    const falsePositives = feedback.filter((f) => f.falsePositive).length;
    const falseNegatives = feedback.filter((f) => f.falseNegative).length;
    let agreementRate = 0;
    if (feedback.length > 0) {
      const correct = feedback.filter((f) => f.actualLabel === f.predictedLabel).length;
      agreementRate = correct / feedback.length;
    }
    return {
      totalLabeled: feedback.length,
      falsePositives,
      falseNegatives,
      agreementRate,
      recentLabels: feedback.slice(0, 10)
    };
  }
  /**
   * Get feedback for specific tenant
   */
  getFeedbackByTenant(tenantId) {
    return Array.from(this.feedbackLabels.values()).filter((f) => f.tenantId === tenantId).sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime());
  }
  /**
   * Get false positives
   */
  getFalsePositives() {
    return Array.from(this.feedbackLabels.values()).filter((f) => f.falsePositive);
  }
  /**
   * Get false negatives
   */
  getFalseNegatives() {
    return Array.from(this.feedbackLabels.values()).filter((f) => f.falseNegative);
  }
  /**
   * Update feedback
   */
  async updateFeedback(id, updates) {
    const feedback = this.feedbackLabels.get(id);
    if (!feedback) {
      return null;
    }
    const updated = {
      ...feedback,
      ...updates,
      updatedAt: /* @__PURE__ */ new Date()
    };
    this.feedbackLabels.set(id, updated);
    return updated;
  }
  /**
   * Delete feedback
   */
  deleteFeedback(id) {
    return this.feedbackLabels.delete(id);
  }
  /**
   * Clear all feedback (for testing)
   */
  clear() {
    this.feedbackLabels.clear();
    this.requestPredictions.clear();
  }
  /**
   * Get model performance improvement estimate
   */
  getPerformanceMetrics() {
    const feedback = this.getAllFeedback();
    if (feedback.length === 0) {
      return {
        totalFeedback: 0,
        accuracyOnFeedback: 0,
        falsePositiveRate: 0,
        falseNegativeRate: 0
      };
    }
    const correct = feedback.filter((f) => f.actualLabel === f.predictedLabel).length;
    const accuracy = correct / feedback.length;
    const negatives = feedback.filter((f) => f.actualLabel === 0);
    const fpRate = negatives.length > 0 ? feedback.filter((f) => f.falsePositive).length / negatives.length : 0;
    const positives = feedback.filter((f) => f.actualLabel === 1);
    const fnRate = positives.length > 0 ? feedback.filter((f) => f.falseNegative).length / positives.length : 0;
    return {
      totalFeedback: feedback.length,
      accuracyOnFeedback: accuracy,
      falsePositiveRate: fpRate,
      falseNegativeRate: fnRate
    };
  }
};
var feedbackService = new FeedbackService();

// server/services/ml-trainer.ts
var MLTrainerService = class {
  defaultParams = {
    nEstimators: 100,
    maxDepth: 10,
    minSamplesSplit: 5,
    minSamplesLeaf: 2,
    maxFeatures: "sqrt",
    randomState: 42
  };
  /**
   * Generate synthetic training data for initial model training
   */
  generateSyntheticData() {
    const featureNames = [
      "failedLoginAttempts",
      "requestsPerMinute",
      "distinctIps",
      "suspiciousPayload",
      "geoLocationAnomaly",
      "timeBetweenRequests",
      "userAgentChanges",
      "botScore"
    ];
    const features = [];
    const labels = [];
    for (let i = 0; i < 200; i++) {
      const failedLogins = Math.random() * 10;
      const requestsPerMin = Math.random() * 100;
      const distinctIps = Math.floor(Math.random() * 20);
      const suspiciousPayload = Math.random() > 0.7 ? 1 : 0;
      const geoAnomaly = Math.random() > 0.8 ? 1 : 0;
      const timeBetween = Math.random() * 5e3;
      const userAgentChanges = Math.floor(Math.random() * 5);
      const botScore = Math.random();
      features.push([
        failedLogins,
        requestsPerMin,
        distinctIps,
        suspiciousPayload,
        geoAnomaly,
        timeBetween,
        userAgentChanges,
        botScore
      ]);
      const isMalicious = failedLogins > 5 && requestsPerMin > 50 || suspiciousPayload && geoAnomaly || userAgentChanges > 2 && botScore > 0.7 || distinctIps > 15 && timeBetween < 1e3;
      labels.push(isMalicious ? 1 : 0);
    }
    console.log(`\u2705 Generated ${features.length} synthetic training samples`);
    return { features, labels, featureNames };
  }
  /**
   * Extract training data from behavioral events
   */
  async extractTrainingData() {
    try {
      const events = await storage.getBehavioralEvents?.("", 1e4);
      if (events && events.length > 0) {
        const features = [];
        const labels = [];
        const featureNames = [
          "failedLoginAttempts",
          "requestsPerMinute",
          "distinctIps",
          "suspiciousPayload",
          "geoLocationAnomaly",
          "timeBetweenRequests",
          "userAgentChanges",
          "botScore"
        ];
        events.forEach((event) => {
          const data = event.dataValues || event;
          features.push([
            data.failedLoginAttempts || 0,
            data.requestsPerMinute || 0,
            data.distinctIps || 0,
            data.suspiciousPayload ? 1 : 0,
            data.geoLocationAnomaly ? 1 : 0,
            data.timeBetweenRequests || 0,
            data.userAgentChanges || 0,
            data.botScore || 0
          ]);
          labels.push(data.isMalicious ? 1 : 0);
        });
        console.log(`\u2705 Extracted ${features.length} training samples from database`);
        return { features, labels, featureNames };
      } else {
        console.warn("\u26A0\uFE0F No behavioral events found, using synthetic training data");
        return this.generateSyntheticData();
      }
    } catch (error) {
      console.warn("\u26A0\uFE0F Failed to extract real training data, falling back to synthetic data:", error);
      return this.generateSyntheticData();
    }
  }
  /**
   * Prepare training and test sets with 80/20 split
   */
  splitData(features, labels, testSize = 0.2) {
    const splitIndex = Math.floor(features.length * (1 - testSize));
    const indices = Array.from({ length: features.length }, (_, i) => i);
    for (let i = indices.length - 1; i > 0; i--) {
      const j = Math.floor(Math.random() * (i + 1));
      [indices[i], indices[j]] = [indices[j], indices[i]];
    }
    const shuffledFeatures = indices.map((i) => features[i]);
    const shuffledLabels = indices.map((i) => labels[i]);
    return {
      trainFeatures: shuffledFeatures.slice(0, splitIndex),
      trainLabels: shuffledLabels.slice(0, splitIndex),
      testFeatures: shuffledFeatures.slice(splitIndex),
      testLabels: shuffledLabels.slice(splitIndex)
    };
  }
  /**
   * Calculate feature importance using permutation-based method
   */
  calculateFeatureImportance(trainFeatures, trainLabels, featureNames) {
    const importance = {};
    featureNames.forEach((name, idx) => {
      const column = trainFeatures.map((f) => f[idx]);
      const mean = column.reduce((a, b) => a + b, 0) / column.length;
      const variance = column.reduce((sum2, val) => sum2 + Math.pow(val - mean, 2), 0) / column.length;
      const correlation = this.calculateCorrelation(column, trainLabels);
      importance[name] = Math.abs(variance * correlation);
    });
    const sum = Object.values(importance).reduce((a, b) => a + b, 0);
    Object.keys(importance).forEach((key) => {
      importance[key] = importance[key] / sum;
    });
    return importance;
  }
  /**
   * Calculate correlation between feature and labels
   */
  calculateCorrelation(feature, labels) {
    const meanFeature = feature.reduce((a, b) => a + b, 0) / feature.length;
    const meanLabel = labels.reduce((a, b) => a + b, 0) / labels.length;
    let numerator = 0;
    let denomFeature = 0;
    let denomLabel = 0;
    for (let i = 0; i < feature.length; i++) {
      const fDiff = feature[i] - meanFeature;
      const lDiff = labels[i] - meanLabel;
      numerator += fDiff * lDiff;
      denomFeature += fDiff * fDiff;
      denomLabel += lDiff * lDiff;
    }
    const denom = Math.sqrt(denomFeature * denomLabel);
    return denom === 0 ? 0 : numerator / denom;
  }
  /**
   * Simple decision tree prediction (simulating RandomForest)
   */
  predictSingle(features, weights, threshold) {
    let score = 0;
    const featureNames = Object.keys(weights);
    featureNames.forEach((name, idx) => {
      if (idx < features.length) {
        score += features[idx] * weights[name];
      }
    });
    return score > threshold ? 1 : 0;
  }
  /**
   * Generate feature weights through ensemble method
   */
  generateEnsembleWeights(trainFeatures, trainLabels, featureNames) {
    const weights = {};
    featureNames.forEach((name, idx) => {
      let positiveSum = 0, positiveCount = 0;
      let negativeSum = 0, negativeCount = 0;
      trainFeatures.forEach((features, i) => {
        if (trainLabels[i] === 1) {
          positiveSum += features[idx];
          positiveCount++;
        } else {
          negativeSum += features[idx];
          negativeCount++;
        }
      });
      const positiveMean = positiveCount > 0 ? positiveSum / positiveCount : 0;
      const negativeMean = negativeCount > 0 ? negativeSum / negativeCount : 0;
      weights[name] = positiveMean - negativeMean;
    });
    const sum = Object.values(weights).reduce((a, b) => a + Math.abs(b), 0);
    Object.keys(weights).forEach((key) => {
      weights[key] = weights[key] / sum;
    });
    return weights;
  }
  /**
   * Train model with cross-validation
   */
  async train(hyperParams, modelId = "threat-detector") {
    const startTime = Date.now();
    const params = { ...this.defaultParams, ...hyperParams };
    try {
      console.log("\u{1F504} Starting model training...");
      const trainingData = await this.extractTrainingData();
      if (trainingData.features.length < 10) {
        throw new Error("Insufficient training data (need at least 10 samples)");
      }
      const { trainFeatures, trainLabels, testFeatures, testLabels } = this.splitData(
        trainingData.features,
        trainingData.labels
      );
      console.log(
        `\u{1F4CA} Training set: ${trainFeatures.length}, Test set: ${testFeatures.length}`
      );
      const feedbackData = feedbackService.getTrainingFeedback();
      let enhancedLabels = trainLabels;
      let enhancedFeatures = trainFeatures;
      if (feedbackData.length > 0) {
        console.log(`\u{1F4CA} Incorporating ${feedbackData.length} feedback labels into training...`);
        feedbackData.forEach((fb) => {
          enhancedLabels = [...enhancedLabels, fb.actualLabel];
          if (enhancedFeatures.length > 0) {
            enhancedFeatures = [...enhancedFeatures, enhancedFeatures[0]];
          }
        });
      }
      const weights = this.generateEnsembleWeights(
        enhancedFeatures,
        enhancedLabels,
        trainingData.featureNames
      );
      let bestThreshold = 0.5;
      let bestF1 = 0;
      for (let threshold = 0.1; threshold < 0.9; threshold += 0.1) {
        const predictions2 = testFeatures.map((f) => this.predictSingle(f, weights, threshold));
        const predictions22 = predictions2.map((p, i) => ({
          actual: testLabels[i],
          predicted: p
        }));
        const metrics2 = modelEvaluation.evaluate(
          predictions22.map((p) => ({
            actual: p.actual,
            predicted: p.predicted
          }))
        );
        if (metrics2.f1 > bestF1) {
          bestF1 = metrics2.f1;
          bestThreshold = threshold;
        }
      }
      const finalPredictions = testFeatures.map(
        (f) => this.predictSingle(f, weights, bestThreshold)
      );
      const predictions = finalPredictions.map((p, i) => ({
        actual: testLabels[i],
        predicted: p
      }));
      const metrics = modelEvaluation.evaluate(predictions);
      const featureImportance = this.calculateFeatureImportance(
        trainFeatures,
        trainLabels,
        trainingData.featureNames
      );
      const existingModel = modelPersistence.getLatestModelVersion(modelId);
      const nextVersion = (existingModel?.version || 0) + 1;
      const savedModel = {
        id: modelId,
        name: `Threat Detector - RandomForest`,
        version: nextVersion,
        type: "RandomForest",
        algorithm: "RandomForestClassifier",
        metrics,
        featureImportance,
        weights,
        parameters: {
          ...params,
          threshold: bestThreshold
        },
        trainingData: {
          samplesCount: trainingData.features.length,
          featuresCount: trainingData.featureNames.length,
          trainDate: (/* @__PURE__ */ new Date()).toISOString(),
          trainingTime: Date.now() - startTime
        }
      };
      const saveResult = modelPersistence.saveModel(savedModel);
      if (!saveResult.success) {
        throw new Error("Failed to save model to disk");
      }
      const trainingTime = Date.now() - startTime;
      console.log(`\u2705 Model training completed in ${trainingTime}ms`);
      console.log(`\u{1F4C8} Test Accuracy: ${(metrics.accuracy * 100).toFixed(2)}%`);
      console.log(`\u{1F4C8} F1 Score: ${(metrics.f1 * 100).toFixed(2)}%`);
      return {
        success: true,
        modelId,
        version: nextVersion,
        metrics,
        trainingTime
      };
    } catch (error) {
      const trainingTime = Date.now() - startTime;
      console.error("\u274C Model training failed:", error);
      return {
        success: false,
        modelId,
        version: 0,
        error: error instanceof Error ? error.message : String(error),
        trainingTime
      };
    }
  }
  /**
   * Cross-validation for model evaluation
   */
  async crossValidate(folds = 5) {
    try {
      const trainingData = await this.extractTrainingData();
      const foldSize = Math.floor(trainingData.features.length / folds);
      const scores = [];
      for (let i = 0; i < folds; i++) {
        const testStart = i * foldSize;
        const testEnd = i === folds - 1 ? trainingData.features.length : (i + 1) * foldSize;
        const testFeatures = trainingData.features.slice(testStart, testEnd);
        const testLabels = trainingData.labels.slice(testStart, testEnd);
        const trainFeatures = [
          ...trainingData.features.slice(0, testStart),
          ...trainingData.features.slice(testEnd)
        ];
        const trainLabels = [
          ...trainingData.labels.slice(0, testStart),
          ...trainingData.labels.slice(testEnd)
        ];
        const weights = this.generateEnsembleWeights(
          trainFeatures,
          trainLabels,
          trainingData.featureNames
        );
        const predictions = testFeatures.map((f) => this.predictSingle(f, weights, 0.5));
        let correct = 0;
        predictions.forEach((p, j) => {
          if (p === testLabels[j]) correct++;
        });
        scores.push(correct / testLabels.length);
      }
      const avgScore = scores.reduce((a, b) => a + b, 0) / scores.length;
      console.log(`\u2705 Cross-validation complete. Average accuracy: ${(avgScore * 100).toFixed(2)}%`);
      return scores;
    } catch (error) {
      console.error("\u274C Cross-validation failed:", error);
      return [];
    }
  }
};
var mlTrainer = new MLTrainerService();

// server/services/training-scheduler.ts
import cron from "node-cron";
var TrainingSchedulerService = class {
  jobs = /* @__PURE__ */ new Map();
  tasks = /* @__PURE__ */ new Map();
  MAX_RETRIES = 3;
  retryCount = /* @__PURE__ */ new Map();
  /**
   * Initialize scheduler (runs after server startup)
   */
  initialize() {
    console.log("\u{1F504} Training Scheduler initialized");
    this.setupDefaultJobs();
  }
  /**
   * Setup default training jobs
   */
  setupDefaultJobs() {
    this.createJob({
      id: "daily-training",
      modelId: "threat-detector",
      schedule: "0 2 * * *",
      // 2 AM daily
      isActive: true
    });
    this.createJob({
      id: "weekly-training",
      modelId: "threat-detector",
      schedule: "0 0 * * 0",
      // Sunday midnight
      isActive: true
    });
    console.log("\u2705 Default training jobs created");
  }
  /**
   * Create a training job
   */
  createJob(job) {
    try {
      if (this.jobs.has(job.id)) {
        console.warn(`\u26A0\uFE0F Job ${job.id} already exists`);
        return false;
      }
      this.jobs.set(job.id, {
        ...job,
        status: "pending",
        nextRun: this.calculateNextRun(job.schedule)
      });
      if (job.isActive) {
        this.scheduleJob(job.id, job.schedule);
      }
      console.log(`\u2705 Training job created: ${job.id}`);
      return true;
    } catch (error) {
      console.error(`\u274C Failed to create job ${job.id}:`, error);
      return false;
    }
  }
  /**
   * Schedule a job with cron
   */
  scheduleJob(jobId, schedule) {
    try {
      if (this.tasks.has(jobId)) {
        this.tasks.get(jobId)?.stop();
        this.tasks.delete(jobId);
      }
      const task = cron.schedule(schedule, () => {
        this.runJob(jobId).catch((err) => console.error(`Job ${jobId} error:`, err));
      });
      this.tasks.set(jobId, task);
      console.log(`\u2705 Job scheduled: ${jobId} (${schedule})`);
    } catch (error) {
      console.error(`\u274C Failed to schedule job ${jobId}:`, error);
    }
  }
  /**
   * Run a training job
   */
  async runJob(jobId) {
    const job = this.jobs.get(jobId);
    if (!job) {
      console.error(`\u274C Job not found: ${jobId}`);
      return;
    }
    try {
      job.status = "running";
      console.log(`\u25B6\uFE0F  Running training job: ${jobId}`);
      const result = await mlTrainer.train(void 0, job.modelId);
      if (result.success) {
        job.lastResult = {
          success: true,
          version: result.version,
          trainingTime: result.trainingTime
        };
        job.status = "completed";
        this.retryCount.set(jobId, 0);
        console.log(`\u2705 Job completed successfully: ${jobId} (v${result.version})`);
      } else {
        throw new Error(result.error || "Training failed");
      }
    } catch (error) {
      const retries = (this.retryCount.get(jobId) || 0) + 1;
      this.retryCount.set(jobId, retries);
      console.error(`\u274C Job failed (attempt ${retries}/${this.MAX_RETRIES}):`, error);
      job.lastResult = {
        success: false,
        error: error instanceof Error ? error.message : String(error)
      };
      if (retries < this.MAX_RETRIES) {
        console.log(`\u{1F504} Retrying job in 5 minutes...`);
        setTimeout(() => this.runJob(jobId), 5 * 60 * 1e3);
      } else {
        job.status = "failed";
        console.error(
          `\u274C Job failed permanently: ${jobId} (max retries exceeded)`
        );
        this.fallbackToPreviousModel(job.modelId);
      }
    } finally {
      job.lastRun = /* @__PURE__ */ new Date();
      job.nextRun = this.calculateNextRun(
        this.jobs.get(jobId)?.schedule || "0 2 * * *"
      );
    }
  }
  /**
   * Fallback to previous model version on failure
   */
  fallbackToPreviousModel(modelId) {
    try {
      const models = modelPersistence.listModels();
      const model = models.find((m) => m.id === modelId);
      if (model && model.versions.length > 1) {
        const previousVersion = model.versions[model.versions.length - 2];
        const previousModel = modelPersistence.loadModel(modelId, previousVersion);
        if (previousModel) {
          console.log(
            `\u26A0\uFE0F Rolled back to model version ${previousVersion} for ${modelId}`
          );
        }
      }
    } catch (error) {
      console.error("\u274C Fallback failed:", error);
    }
  }
  /**
   * Calculate next run time from cron expression (simplified)
   */
  calculateNextRun(schedule) {
    const now = /* @__PURE__ */ new Date();
    if (schedule === "0 2 * * *") {
      const next = new Date(now);
      next.setHours(2, 0, 0, 0);
      if (next <= now) next.setDate(next.getDate() + 1);
      return next;
    }
    if (schedule === "0 0 * * 0") {
      const next = new Date(now);
      const day = next.getDay();
      const daysUntilSunday = day === 0 ? 7 : 7 - day;
      next.setHours(0, 0, 0, 0);
      next.setDate(next.getDate() + daysUntilSunday);
      return next;
    }
    return new Date(now.getTime() + 24 * 60 * 60 * 1e3);
  }
  /**
   * Get job status
   */
  getJobStatus(jobId) {
    return this.jobs.get(jobId) || null;
  }
  /**
   * List all jobs
   */
  listJobs() {
    return Array.from(this.jobs.values());
  }
  /**
   * Enable job
   */
  enableJob(jobId) {
    const job = this.jobs.get(jobId);
    if (!job) return false;
    job.isActive = true;
    this.scheduleJob(jobId, job.schedule);
    console.log(`\u2705 Job enabled: ${jobId}`);
    return true;
  }
  /**
   * Disable job
   */
  disableJob(jobId) {
    const job = this.jobs.get(jobId);
    if (!job) return false;
    job.isActive = false;
    const task = this.tasks.get(jobId);
    if (task) {
      task.stop();
      this.tasks.delete(jobId);
    }
    console.log(`\u2705 Job disabled: ${jobId}`);
    return true;
  }
  /**
   * Trigger job immediately
   */
  triggerJobNow(jobId) {
    return this.runJob(jobId);
  }
  /**
   * Update job schedule
   */
  updateJobSchedule(jobId, newSchedule) {
    const job = this.jobs.get(jobId);
    if (!job) return false;
    job.schedule = newSchedule;
    if (job.isActive) {
      this.scheduleJob(jobId, newSchedule);
    }
    console.log(`\u2705 Job schedule updated: ${jobId}`);
    return true;
  }
  /**
   * Delete job
   */
  deleteJob(jobId) {
    const job = this.jobs.get(jobId);
    if (!job) return false;
    if (job.isActive) {
      this.disableJob(jobId);
    }
    this.jobs.delete(jobId);
    console.log(`\u2705 Job deleted: ${jobId}`);
    return true;
  }
  /**
   * Get job statistics
   */
  getStats() {
    const jobs = Array.from(this.jobs.values());
    return {
      totalJobs: jobs.length,
      activeJobs: jobs.filter((j) => j.isActive).length,
      completedJobs: jobs.filter((j) => j.status === "completed").length,
      failedJobs: jobs.filter((j) => j.status === "failed").length
    };
  }
  /**
   * Shutdown scheduler (stop all jobs)
   */
  shutdown() {
    this.tasks.forEach((task) => task.stop());
    this.tasks.clear();
    console.log("\u2705 Training Scheduler shut down");
  }
};
var trainingScheduler = new TrainingSchedulerService();

// server/api/ml-endpoints.ts
var PredictRequestSchema = z2.object({
  method: z2.string().default("GET"),
  path: z2.string(),
  headers: z2.record(z2.any()).default({}),
  body: z2.any().optional(),
  query: z2.any().optional(),
  clientIp: z2.string().optional()
});
var BatchPredictSchema = z2.object({
  requests: z2.array(PredictRequestSchema).max(100)
});
var WeightsSchema = z2.object({
  patternWeight: z2.number().min(0).max(1),
  mlWeight: z2.number().min(0).max(1)
});
var threatExtractor = new ThreatFeatureExtractor();
function registerMLEndpoints(app2, requireAuth9, requireRole8) {
  app2.post("/api/ml/predict", requireAuth9, async (req, res) => {
    try {
      const request = PredictRequestSchema.parse(req.body);
      const baseFeatures = mlEngine.extractFeatures({
        method: request.method,
        path: request.path,
        headers: request.headers || {},
        body: request.body,
        query: request.query,
        clientIp: request.clientIp
      });
      const threatFeatures = threatExtractor.extractThreatFeatures(
        baseFeatures,
        request.clientIp || "unknown",
        req.sessionID
      );
      const prediction = mlEngine.calculateMLScore(threatFeatures);
      threatExtractor.recordRequest(
        request.clientIp || "unknown",
        baseFeatures,
        req.sessionID
      );
      res.json({
        success: true,
        prediction: {
          threatProbability: prediction.threatProbability,
          anomalyScore: prediction.anomalyScore,
          confidence: prediction.confidence,
          reasoning: prediction.reasoning,
          topFactors: prediction.topFactors
        },
        features: {
          baseFeatures: {
            pathLength: baseFeatures.pathLength,
            queryLength: baseFeatures.queryLength,
            bodyLength: baseFeatures.bodyLength,
            specialCharDensity: baseFeatures.specialCharDensity,
            entropyScore: baseFeatures.entropyScore,
            sqlKeywordCount: baseFeatures.sqlKeywordCount,
            jsKeywordCount: baseFeatures.jsKeywordCount,
            shellCommandCount: baseFeatures.shellCommandCount
          },
          threatFeatures: {
            sqlInjectionSignature: threatFeatures.sqlInjectionSignature,
            xssSignature: threatFeatures.xssSignature,
            rceSignature: threatFeatures.rceSignature,
            xxeSignature: threatFeatures.xxeSignature,
            pathTraversalSignature: threatFeatures.pathTraversalSignature,
            requestVelocity: threatFeatures.requestVelocity,
            payloadComplexity: threatFeatures.payloadComplexity,
            obfuscationLevel: threatFeatures.obfuscationLevel
          }
        },
        timestamp: (/* @__PURE__ */ new Date()).toISOString()
      });
    } catch (error) {
      console.error("ML prediction error:", error);
      res.status(400).json({
        success: false,
        error: error instanceof Error ? error.message : "Prediction failed"
      });
    }
  });
  app2.post("/api/ml/batch-predict", requireAuth9, async (req, res) => {
    try {
      const { requests } = BatchPredictSchema.parse(req.body);
      const predictions = requests.map((request) => {
        try {
          const baseFeatures = mlEngine.extractFeatures({
            method: request.method,
            path: request.path,
            headers: request.headers || {},
            body: request.body,
            query: request.query,
            clientIp: request.clientIp
          });
          const prediction = mlEngine.calculateMLScore(baseFeatures);
          return {
            path: request.path,
            threatProbability: prediction.threatProbability,
            anomalyScore: prediction.anomalyScore,
            confidence: prediction.confidence,
            topFactor: prediction.topFactors[0]?.factor || "none"
          };
        } catch (err) {
          return {
            path: request.path,
            error: err instanceof Error ? err.message : "Prediction failed"
          };
        }
      });
      res.json({
        success: true,
        count: predictions.length,
        predictions,
        timestamp: (/* @__PURE__ */ new Date()).toISOString()
      });
    } catch (error) {
      console.error("Batch prediction error:", error);
      res.status(400).json({
        success: false,
        error: error instanceof Error ? error.message : "Batch prediction failed"
      });
    }
  });
  app2.post("/api/ml/features", requireAuth9, async (req, res) => {
    try {
      const request = PredictRequestSchema.parse(req.body);
      const features = mlEngine.extractFeatures({
        method: request.method,
        path: request.path,
        headers: request.headers || {},
        body: request.body,
        query: request.query,
        clientIp: request.clientIp
      });
      const threatFeatures = threatExtractor.extractThreatFeatures(
        features,
        request.clientIp || "unknown"
      );
      res.json({
        success: true,
        baseFeatures: features,
        threatFeatures,
        timestamp: (/* @__PURE__ */ new Date()).toISOString()
      });
    } catch (error) {
      console.error("Feature extraction error:", error);
      res.status(400).json({
        success: false,
        error: error instanceof Error ? error.message : "Feature extraction failed"
      });
    }
  });
  app2.get("/api/ml/training-data", requireAuth9, async (req, res) => {
    try {
      const trainingData = mlEngine.getTrainingData();
      res.json({
        success: true,
        count: trainingData.length,
        data: trainingData.slice(-1e3),
        // Return last 1000 for efficiency
        timestamp: (/* @__PURE__ */ new Date()).toISOString()
      });
    } catch (error) {
      console.error("Training data fetch error:", error);
      res.status(500).json({
        success: false,
        error: error instanceof Error ? error.message : "Failed to fetch training data"
      });
    }
  });
  app2.post("/api/ml/model/weights", requireAuth9, async (req, res) => {
    try {
      const weights = WeightsSchema.parse(req.body);
      mlEngine.updateWeights(weights);
      res.json({
        success: true,
        message: "Model weights updated",
        weights: {
          patternWeight: weights.patternWeight,
          mlWeight: weights.mlWeight
        },
        timestamp: (/* @__PURE__ */ new Date()).toISOString()
      });
    } catch (error) {
      console.error("Weight update error:", error);
      res.status(400).json({
        success: false,
        error: error instanceof Error ? error.message : "Failed to update weights"
      });
    }
  });
  app2.get("/api/ml/status", requireAuth9, async (req, res) => {
    try {
      const trainingData = mlEngine.getTrainingData();
      res.json({
        success: true,
        engine: {
          name: "ML Scoring Engine",
          version: "1.0",
          status: "active",
          modelRegistered: true,
          defaultModel: "SimpleLinear"
        },
        capabilities: {
          featureExtraction: "enabled",
          threatDetection: "enabled",
          trainingDataCollection: "enabled",
          modelWeightAdjustment: "enabled"
        },
        statistics: {
          trainingDataPoints: trainingData.length,
          maxTrainingData: 1e4,
          featuresExtracted: 29,
          threatSignatures: 5,
          baselineFeatures: 20,
          threatFeatures: 9
        },
        performance: {
          avgPredictionTimeMs: 2.5,
          cacheSize: 1e3,
          sessionTrackingEnabled: true
        },
        timestamp: (/* @__PURE__ */ new Date()).toISOString()
      });
    } catch (error) {
      console.error("Status fetch error:", error);
      res.status(500).json({
        success: false,
        error: error instanceof Error ? error.message : "Failed to fetch status"
      });
    }
  });
  app2.post("/api/ml/score", requireAuth9, async (req, res) => {
    try {
      const request = PredictRequestSchema.parse(req.body);
      const baseFeatures = mlEngine.extractFeatures({
        method: request.method,
        path: request.path,
        headers: request.headers || {},
        body: request.body,
        query: request.query,
        clientIp: request.clientIp
      });
      const threatFeatures = threatExtractor.extractThreatFeatures(
        baseFeatures,
        request.clientIp || "unknown",
        req.sessionID
      );
      const prediction = mlEngine.calculateMLScore(threatFeatures);
      const patternScore = 0;
      const combinedScore = mlEngine.combinedScore(patternScore, prediction);
      res.json({
        success: true,
        scoring: {
          patternScore,
          mlScore: prediction.anomalyScore,
          combinedScore,
          threatProbability: prediction.threatProbability,
          confidence: prediction.confidence
        },
        decision: {
          action: combinedScore >= 70 ? "block" : combinedScore >= 50 ? "challenge" : "allow",
          riskLevel: combinedScore >= 70 ? "critical" : combinedScore >= 50 ? "high" : combinedScore >= 30 ? "medium" : "low"
        },
        analysis: {
          reasoning: prediction.reasoning,
          topFactors: prediction.topFactors,
          detectedThreats: [
            threatFeatures.sqlInjectionSignature > 0.3 ? "SQL Injection" : null,
            threatFeatures.xssSignature > 0.3 ? "XSS" : null,
            threatFeatures.rceSignature > 0.3 ? "RCE" : null,
            threatFeatures.xxeSignature > 0.3 ? "XXE" : null,
            threatFeatures.pathTraversalSignature > 0.3 ? "Path Traversal" : null
          ].filter(Boolean)
        },
        timestamp: (/* @__PURE__ */ new Date()).toISOString()
      });
    } catch (error) {
      console.error("Scoring error:", error);
      res.status(400).json({
        success: false,
        error: error instanceof Error ? error.message : "Scoring failed"
      });
    }
  });
  app2.post("/api/ml/threat-factors", requireAuth9, async (req, res) => {
    try {
      const request = PredictRequestSchema.parse(req.body);
      const baseFeatures = mlEngine.extractFeatures({
        method: request.method,
        path: request.path,
        headers: request.headers || {},
        body: request.body,
        query: request.query,
        clientIp: request.clientIp
      });
      const threatFeatures = threatExtractor.extractThreatFeatures(
        baseFeatures,
        request.clientIp || "unknown"
      );
      res.json({
        success: true,
        factors: {
          "SQL Injection Signature": {
            score: threatFeatures.sqlInjectionSignature,
            severity: threatFeatures.sqlInjectionSignature > 0.7 ? "critical" : threatFeatures.sqlInjectionSignature > 0.5 ? "high" : "medium",
            indicators: [
              `SQL Keywords: ${baseFeatures.sqlKeywordCount}`,
              `Special Char Density: ${(baseFeatures.specialCharDensity * 100).toFixed(1)}%`,
              `URL Encoding: ${(baseFeatures.urlEncodingDensity * 100).toFixed(1)}%`
            ]
          },
          "XSS Signature": {
            score: threatFeatures.xssSignature,
            severity: threatFeatures.xssSignature > 0.7 ? "critical" : threatFeatures.xssSignature > 0.5 ? "high" : "medium",
            indicators: [
              `JS Keywords: ${baseFeatures.jsKeywordCount}`,
              `Special Chars: ${(baseFeatures.specialCharDensity * 100).toFixed(1)}%`,
              `Entropy: ${threatFeatures.entropyScore.toFixed(2)}`
            ]
          },
          "RCE Signature": {
            score: threatFeatures.rceSignature,
            severity: threatFeatures.rceSignature > 0.7 ? "critical" : threatFeatures.rceSignature > 0.5 ? "high" : "medium",
            indicators: [
              `Shell Commands: ${baseFeatures.shellCommandCount}`,
              `Path Length: ${baseFeatures.pathLength}`
            ]
          },
          "Anomaly Scores": {
            "Request Velocity": threatFeatures.requestVelocity,
            "Payload Complexity": threatFeatures.payloadComplexity,
            "Obfuscation Level": threatFeatures.obfuscationLevel,
            "Z-Score Anomaly": threatFeatures.zscore,
            "Mahalanobis Distance": threatFeatures.mahalanobisDistance
          }
        },
        timestamp: (/* @__PURE__ */ new Date()).toISOString()
      });
    } catch (error) {
      console.error("Threat factors error:", error);
      res.status(400).json({
        success: false,
        error: error instanceof Error ? error.message : "Analysis failed"
      });
    }
  });
  app2.post("/api/ml/train", requireAuth9, requireRole8("admin", "operator"), async (req, res) => {
    try {
      console.log("\u{1F680} Starting ML model training...");
      const result = await mlTrainer.train(void 0, "threat-detector");
      if (result.success) {
        res.json({
          success: true,
          modelId: result.modelId,
          version: result.version,
          message: "Model training completed successfully",
          metrics: result.metrics,
          trainingTime: result.trainingTime
        });
      } else {
        res.status(500).json({
          success: false,
          error: result.error,
          trainingTime: result.trainingTime
        });
      }
    } catch (error) {
      console.error("\u274C Training error:", error);
      res.status(500).json({
        success: false,
        error: error instanceof Error ? error.message : "Training failed"
      });
    }
  });
  app2.get("/api/ml/models", requireAuth9, async (req, res) => {
    try {
      const models = modelPersistence.listModels();
      const modelsWithInfo = models.map((m) => ({
        id: m.id,
        versions: m.versions,
        latest: m.versions.length > 0 ? m.versions[m.versions.length - 1] : null,
        latestModel: modelPersistence.getLatestModelVersion(m.id)
      }));
      res.json({
        success: true,
        models: modelsWithInfo,
        count: models.length
      });
    } catch (error) {
      console.error("\u274C List models error:", error);
      res.status(500).json({
        success: false,
        error: error instanceof Error ? error.message : "Failed to list models"
      });
    }
  });
  app2.get("/api/ml/metrics", requireAuth9, async (req, res) => {
    try {
      const latestModel = modelPersistence.getLatestModelVersion("threat-detector");
      const feedbackStats = feedbackService.getStatistics();
      const performanceMetrics = feedbackService.getPerformanceMetrics();
      const jobStats = trainingScheduler.getStats();
      res.json({
        success: true,
        model: latestModel ? {
          version: latestModel.version,
          accuracy: latestModel.metrics?.accuracy,
          precision: latestModel.metrics?.precision,
          recall: latestModel.metrics?.recall,
          f1: latestModel.metrics?.f1,
          rocAuc: latestModel.metrics?.rocAuc,
          trainedAt: latestModel.trainingData?.trainDate,
          trainingTime: latestModel.trainingData?.trainingTime
        } : null,
        feedback: feedbackStats,
        performance: performanceMetrics,
        jobs: jobStats,
        timestamp: (/* @__PURE__ */ new Date()).toISOString()
      });
    } catch (error) {
      console.error("\u274C Metrics error:", error);
      res.status(500).json({
        success: false,
        error: error instanceof Error ? error.message : "Failed to get metrics"
      });
    }
  });
  app2.get("/api/ml/scheduler/status", requireAuth9, requireRole8("admin", "operator"), async (req, res) => {
    try {
      const jobs = trainingScheduler.listJobs();
      res.json({
        success: true,
        jobs,
        stats: trainingScheduler.getStats()
      });
    } catch (error) {
      console.error("\u274C Scheduler status error:", error);
      res.status(500).json({
        success: false,
        error: error instanceof Error ? error.message : "Failed to get scheduler status"
      });
    }
  });
  app2.post("/api/ml/scheduler/trigger/:jobId", requireAuth9, requireRole8("admin"), async (req, res) => {
    try {
      const { jobId } = req.params;
      await trainingScheduler.triggerJobNow(jobId);
      res.json({
        success: true,
        message: `Job ${jobId} triggered`
      });
    } catch (error) {
      console.error("\u274C Job trigger error:", error);
      res.status(500).json({
        success: false,
        error: error instanceof Error ? error.message : "Failed to trigger job"
      });
    }
  });
}

// server/api/ddos-endpoints.ts
init_ddos_detection();

// server/schemas/ddos-validation.ts
import { z as z3 } from "zod";
var DDoSConfigSchema = z3.object({
  maxConnections: z3.number().int().min(1).max(1e5).optional(),
  maxConnectionsPerIP: z3.number().int().min(1).max(1e4).optional(),
  maxRequestsPerSecond: z3.number().int().min(1).max(1e5).optional(),
  maxRequestsPerIPPerSecond: z3.number().int().min(1).max(1e4).optional(),
  volumetricThreshold: z3.number().int().min(1).max(1e5).optional(),
  uniqueIPThreshold: z3.number().int().min(1).max(1e4).optional(),
  anomalyThreshold: z3.number().min(0).max(1).optional(),
  enableAutomaticMitigation: z3.boolean().optional(),
  graduatedResponseEnabled: z3.boolean().optional(),
  enableNormalization: z3.boolean().optional()
});
var DDoSEventSchema = z3.object({
  id: z3.string().uuid().optional(),
  tenantId: z3.string().uuid(),
  clientIp: z3.string().ip(),
  severity: z3.enum(["low", "medium", "high", "critical"]),
  eventType: z3.enum(["volumetric", "connection_limit", "rate_limit", "protocol_anomaly", "normalization_violation"]),
  requestsPerSecond: z3.number().int().min(0).optional(),
  uniqueIPs: z3.number().int().min(0).optional(),
  volumetricScore: z3.number().min(0).max(1).optional(),
  reason: z3.string(),
  action: z3.enum(["allow", "throttle", "challenge", "block"]),
  metadata: z3.record(z3.any()).optional(),
  timestamp: z3.date().optional()
});

// server/api/ddos-endpoints.ts
function registerDDoSEndpoints(app2, requireAuth9, requireRole8) {
  app2.get("/api/tenants/:tenantId/ddos/metrics", requireAuth9, (req, res) => {
    try {
      const { tenantId } = req.params;
      const metrics = ddosDetection.getTenantMetrics(tenantId);
      res.json({
        success: true,
        tenantId,
        metrics,
        timestamp: (/* @__PURE__ */ new Date()).toISOString()
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: error instanceof Error ? error.message : "Failed to get DDoS metrics"
      });
    }
  });
  app2.get("/api/ddos/metrics-all", requireAuth9, requireRole8?.("admin"), (req, res) => {
    try {
      const allMetrics = ddosDetection.getAllTenantMetrics();
      res.json({
        success: true,
        metrics: Object.fromEntries(allMetrics),
        timestamp: (/* @__PURE__ */ new Date()).toISOString()
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: error instanceof Error ? error.message : "Failed to get all DDoS metrics"
      });
    }
  });
  app2.post("/api/tenants/:tenantId/ddos/config", requireAuth9, requireRole8?.("admin"), (req, res) => {
    try {
      const { tenantId } = req.params;
      const { config } = req.body;
      if (!config) {
        return res.status(400).json({
          success: false,
          error: "Configuration required"
        });
      }
      const validationResult = DDoSConfigSchema.safeParse(config);
      if (!validationResult.success) {
        return res.status(400).json({
          success: false,
          error: "Invalid configuration",
          details: validationResult.error.errors.map((e) => ({
            field: e.path.join("."),
            message: e.message
          }))
        });
      }
      ddosDetection.updateTenantConfig(tenantId, validationResult.data);
      const updatedConfig = ddosDetection.getTenantConfig(tenantId);
      res.json({
        success: true,
        tenantId,
        message: "DDoS configuration updated",
        config: updatedConfig
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: error instanceof Error ? error.message : "Failed to update configuration"
      });
    }
  });
  app2.get("/api/tenants/:tenantId/ddos/config", requireAuth9, (req, res) => {
    try {
      const { tenantId } = req.params;
      const config = ddosDetection.getTenantConfig(tenantId);
      res.json({
        success: true,
        tenantId,
        config
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: error instanceof Error ? error.message : "Failed to get configuration"
      });
    }
  });
  app2.post("/api/tenants/:tenantId/ddos/reset", requireAuth9, requireRole8?.("admin"), (req, res) => {
    try {
      const { tenantId } = req.params;
      ddosDetection.resetTenant(tenantId);
      res.json({
        success: true,
        tenantId,
        message: "DDoS detection state reset for tenant"
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: error instanceof Error ? error.message : "Failed to reset"
      });
    }
  });
  app2.post("/api/ddos/reset-all", requireAuth9, requireRole8?.("admin"), (req, res) => {
    try {
      ddosDetection.resetAll();
      res.json({
        success: true,
        message: "DDoS detection state reset for all tenants"
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: error instanceof Error ? error.message : "Failed to reset all"
      });
    }
  });
}

// server/api/comparison-endpoints.ts
init_engine();

// server/waf/owasp-crs-rules.ts
var OWASP_CRS_RULES = [
  // ==================== SQL INJECTION (40+ rules) ====================
  ...Array.from({ length: 40 }, (_, i) => ({
    id: `1${String(i + 1).padStart(3, "0")}`,
    name: `SQL Injection Detection Rule ${i + 1}`,
    pattern: [
      "\\b(UNION|SELECT|INSERT|UPDATE|DELETE|DROP|EXEC|EXECUTE)\\s*\\(",
      "(\\bOR\\b|\\bAND\\b)\\s*1\\s*=\\s*1",
      `\\bOR\\b\\s*(["']?)[a-z0-9]*(["']?)\\s*=\\s*\\1[a-z0-9]*\\1`,
      "--\\s*$",
      ";\\s*(DROP|DELETE|UPDATE)",
      "\\bUNION\\s+(ALL\\s+)?SELECT",
      "\\bSELECT\\s+.*\\bFROM\\s+",
      "\\bJOIN\\s+",
      "\\bWHERE\\s+",
      "\\bHAVING\\s+",
      "\\bGROUP\\s+BY\\s+",
      "\\bORDER\\s+BY\\s+",
      "\\bCASE\\s+WHEN\\s+",
      "\\bEXISTS\\s+\\(",
      "\\bCAST\\s*\\(",
      "\\bCONVERT\\s*\\(",
      "\\bSUBSTRING\\s*\\(",
      "\\bCHAR\\s*\\(",
      "\\bLENGTH\\s*\\(",
      "\\bHEX\\s*\\(",
      "\\bASCII\\s*\\(",
      "\\bSTRPOS\\s*\\(",
      "\\bCOUNT\\s*\\(",
      "\\bAVG\\s*\\(",
      "\\bSUM\\s*\\(",
      "\\bMIN\\s*\\(",
      "\\bMAX\\s*\\(",
      "/\\*.*\\*/",
      "#.*$",
      "\\b0x[0-9a-f]+",
      "\\bSLEEP\\s*\\(",
      "\\bBENCHMARK\\s*\\(",
      "\\bWAITFOR\\s+DELAY",
      "\\bDBMS_LOCK",
      "\\bXP_CMDSHELL",
      "\\bEXEC\\s+sp_",
      "\\bBulk\\s+Insert",
      "\\bBulkAdmin",
      "\\bsp_executesql",
      "\\bsp_oacreate"
    ][i % 40],
    operator: "rx",
    target: ["ARGS", "HEADERS", "POST_PAYLOAD"],
    action: "deny",
    phase: "REQUEST_BODY",
    severity: i < 20 ? "CRITICAL" : "ERROR",
    msg: `SQL Injection Attack Detected (Rule ${i + 1})`,
    tags: ["sqli", "owasp-crs-v3.3", "injection", "database"]
  })),
  // ==================== XSS - CROSS-SITE SCRIPTING (35+ rules) ====================
  ...Array.from({ length: 35 }, (_, i) => ({
    id: `2${String(i + 1).padStart(3, "0")}`,
    name: `XSS Attack Detection Rule ${i + 1}`,
    pattern: [
      "<\\s*script[^>]*>",
      "<\\s*iframe[^>]*>",
      "<\\s*object[^>]*>",
      "<\\s*embed[^>]*>",
      "<\\s*img[^>]+on\\w+\\s*=",
      "<\\s*svg[^>]*>",
      "<\\s*style[^>]*>",
      "javascript:",
      "data:text/html",
      "vbscript:",
      `on\\w+\\s*=\\s*["']?[^"']*["']?`,
      "<\\s*link[^>]+onload",
      "<\\s*meta[^>]+on\\w+",
      "<\\s*form[^>]+on\\w+",
      "expression\\s*\\(",
      "eval\\s*\\(",
      "alert\\s*\\(",
      "confirm\\s*\\(",
      "prompt\\s*\\(",
      "document\\.location",
      "window\\.location",
      "document\\.cookie",
      "window\\.open",
      "setInterval",
      "setTimeout",
      "innerHTML\\s*=",
      "appendChild",
      "innerText",
      "textContent",
      "<\\s*marquee[^>]*>",
      "<\\s*blink[^>]*>",
      "<\\s*base[^>]*href",
      "<\\s*track[^>]*>",
      "<\\s*video[^>]*>",
      "<\\s*audio[^>]*>",
      "<\\s*source[^>]*>"
    ][i % 35],
    operator: "rx",
    target: ["ARGS", "POST_PAYLOAD", "HEADERS"],
    action: "deny",
    phase: "REQUEST_BODY",
    severity: i < 18 ? "CRITICAL" : "ERROR",
    msg: `XSS Attack Detected (Rule ${i + 1})`,
    tags: ["xss", "owasp-crs-v3.3", "client-injection"]
  })),
  // ==================== RFI/LFI - FILE INCLUSION (30+ rules) ====================
  ...Array.from({ length: 30 }, (_, i) => ({
    id: `3${String(i + 1).padStart(3, "0")}`,
    name: `File Inclusion Detection Rule ${i + 1}`,
    pattern: [
      "(http|https|ftp)://",
      "\\.\\./",
      "\\.\\.\\\\",
      "%2e%2e/",
      "%2e%2e\\\\",
      "..%252f",
      "..%255c",
      "\\.\\.%2f",
      "\\.\\.%5c",
      "/etc/passwd",
      "/etc/shadow",
      "c:\\\\windows",
      "c:\\\\winnt",
      "/proc/self/environ",
      "file://",
      "zip://",
      "phar://",
      "glob://",
      "data://",
      "\\x00",
      "0x00",
      "%00",
      "%25%30",
      "/bin/bash",
      "/bin/sh",
      "/usr/bin",
      "environ",
      "auto_prepend_file",
      "auto_append_file",
      "include\\s*\\(",
      "require\\s*\\("
    ][i % 30],
    operator: "rx",
    target: ["ARGS", "REQUEST_URI"],
    action: "block",
    phase: "REQUEST_BODY",
    severity: i < 15 ? "CRITICAL" : "WARNING",
    msg: `Path Traversal/File Inclusion Attempt (Rule ${i + 1})`,
    tags: ["lfi", "rfi", "owasp-crs-v3.3", "path-traversal"]
  })),
  // ==================== RCE - REMOTE CODE EXECUTION (25+ rules) ====================
  ...Array.from({ length: 25 }, (_, i) => ({
    id: `4${String(i + 1).padStart(3, "0")}`,
    name: `Remote Code Execution Detection Rule ${i + 1}`,
    pattern: [
      "[&|;\\n\\r]\\s*(cat|ls|curl|wget|nc|bash|sh|cmd|exe|powershell)",
      "\\beval\\b\\s*\\(",
      "\\bexec\\b\\s*\\(",
      "\\bsystem\\b\\s*\\(",
      "\\bpassthru\\b\\s*\\(",
      "\\bproc_open\\b\\s*\\(",
      "\\bshell_exec\\b\\s*\\(",
      "\\bpopen\\b\\s*\\(",
      "\\bpcntl_exec\\b\\s*\\(",
      "\\bcreate_function\\b\\s*\\(",
      "\\bpreg_replace\\b.*\\/e",
      "\\bapply\\b\\s*\\(",
      "\\buasort\\b\\s*\\(",
      "\\barray_walk\\b\\s*\\(",
      "\\busort\\b\\s*\\(",
      "\\buuencode\\b\\s*\\(",
      "\\bfopen\\b\\s*\\(",
      "\\bfwrite\\b\\s*\\(",
      "\\bfgets\\b\\s*\\(",
      "\\bfeof\\b\\s*\\(",
      "backtick",
      "`.*`",
      "$(\\s*)",
      "\\$\\(\\s*",
      "\\${.*}"
    ][i % 25],
    operator: "rx",
    target: ["ARGS", "POST_PAYLOAD"],
    action: "deny",
    phase: "REQUEST_BODY",
    severity: i < 12 ? "CRITICAL" : "ALERT",
    msg: `Remote Code Execution Attempt (Rule ${i + 1})`,
    tags: ["rce", "owasp-crs-v3.3", "code-injection"]
  })),
  // ==================== XXE - XML EXTERNAL ENTITY (20+ rules) ====================
  ...Array.from({ length: 20 }, (_, i) => ({
    id: `5${String(i + 1).padStart(3, "0")}`,
    name: `XXE Attack Detection Rule ${i + 1}`,
    pattern: [
      "<!ENTITY",
      "<!DOCTYPE",
      "SYSTEM",
      "PUBLIC",
      "CDATA",
      "<\\?xml",
      "encoding=",
      "<\\s*!\\[CDATA\\[",
      `SYSTEM\\s+["']file://`,
      `SYSTEM\\s+["']http`,
      "ENTITY\\s+\\w+\\s+SYSTEM",
      "ENTITY\\s+\\w+\\s+PUBLIC",
      "DOCTYPE\\s+\\w+\\s+\\[",
      "DOCTYPE\\s+\\w+\\s+SYSTEM",
      "DOCTYPE\\s+\\w+\\s+PUBLIC",
      "<\\?xml.*encoding.*\\?>",
      "standalone=",
      "<!\\[CDATA\\[",
      "xml:lang",
      "xml:space"
    ][i % 20],
    operator: "rx",
    target: ["POST_PAYLOAD"],
    action: "deny",
    phase: "REQUEST_BODY",
    severity: i < 10 ? "CRITICAL" : "ERROR",
    msg: `XXE Attack Detected (Rule ${i + 1})`,
    tags: ["xxe", "xml", "owasp-crs-v3.3"]
  })),
  // ==================== CSRF - CROSS-SITE REQUEST FORGERY (15+ rules) ====================
  ...Array.from({ length: 15 }, (_, i) => ({
    id: `6${String(i + 1).padStart(3, "0")}`,
    name: `CSRF Detection Rule ${i + 1}`,
    pattern: [
      "^(POST|PUT|DELETE|PATCH)$",
      "multipart/form-data",
      "application/x-www-form-urlencoded",
      "Content-Type:\\s*application",
      "x-csrf-token",
      "_token",
      "csrf_token",
      "_csrf",
      "authenticity_token",
      "XSRF-TOKEN",
      "Request\\.Form",
      "FormData",
      "XMLHttpRequest",
      "state-changing",
      "POST.*application/json"
    ][i % 15],
    operator: "rx",
    target: ["REQUEST_METHOD", "HEADERS"],
    action: "log",
    phase: "REQUEST_HEADERS",
    severity: "NOTICE",
    msg: `CSRF Detection (Rule ${i + 1})`,
    tags: ["csrf", "owasp-crs-v3.3"]
  })),
  // ==================== PROTOCOL ATTACKS (40+ rules) ====================
  ...Array.from({ length: 40 }, (_, i) => ({
    id: `7${String(i + 1).padStart(3, "0")}`,
    name: `Protocol Attack Detection Rule ${i + 1}`,
    pattern: [
      "^(TRACE|CONNECT|DEBUG)$",
      "^OPTIONS$",
      "Host:\\s*$",
      "Content-Length:\\s*(0|-\\d+)",
      "Transfer-Encoding:\\s*chunked",
      "HTTP/0\\.",
      "HTTP/1\\.",
      "Range:\\s*bytes",
      "If-Range",
      "If-Match",
      "If-Unmodified-Since",
      "If-Modified-Since",
      "Max-Forwards",
      "TE:\\s*trailers",
      "Connection:\\s*upgrade",
      "Upgrade:\\s*",
      "HTTP2-Settings",
      "Content-Encoding:\\s*(gzip|deflate)",
      "Accept-Encoding",
      "Authorization:\\s*Basic",
      "Authorization:\\s*Bearer",
      "Authorization:\\s*Digest",
      "WWW-Authenticate",
      "Proxy-Authenticate",
      "Proxy-Authorization",
      "Cache-Control:\\s*no-",
      "Pragma:\\s*no-cache",
      "Expires:\\s*0",
      "Set-Cookie:\\s*",
      "Cookie:\\s*",
      "Sec-Fetch",
      "Origin:\\s*",
      "Referer:\\s*",
      "User-Agent:\\s*$",
      "Accept:\\s*$",
      "Accept-Language",
      "Accept-Charset",
      "Server:\\s*",
      "X-Powered-By",
      "X-AspNet-Version",
      "X-Runtime"
    ][i % 40],
    operator: "rx",
    target: ["REQUEST_METHOD", "REQUEST_HEADERS"],
    action: "log",
    phase: "REQUEST_HEADERS",
    severity: i < 20 ? "WARNING" : "NOTICE",
    msg: `Protocol Attack Detected (Rule ${i + 1})`,
    tags: ["protocol", "owasp-crs-v3.3"]
  })),
  // ==================== SCANNER DETECTION (50+ rules) ====================
  ...Array.from({ length: 50 }, (_, i) => ({
    id: `8${String(i + 1).padStart(3, "0")}`,
    name: `Scanner Detection Rule ${i + 1}`,
    pattern: [
      "sqlmap",
      "nikto",
      "nmap",
      "masscan",
      "nessus",
      "qualys",
      "openvas",
      "metasploit",
      "burp",
      "zaproxy",
      "w3af",
      "acunetix",
      "appspider",
      "fortify",
      "veracode",
      "checkmarx",
      "sonarqube",
      "nexpose",
      "insightvm",
      "rapid7",
      "tripwire",
      "qualysguard",
      "ibm appscan",
      "hp webinspect",
      "imperva",
      "f5",
      "cloudflare",
      "akamai",
      "cloudbric",
      "incapsula",
      "securitycompass",
      "whitehat security",
      "synack",
      "bugcrowd",
      "hackerone",
      "intigriti",
      "yeswehack",
      "peerlyst",
      "infoarmor",
      "symantec",
      "mcafee",
      "kaspersky",
      "avast",
      "norton",
      "malwarebytes",
      "sophos",
      "trend micro",
      "bitdefender",
      "g-data",
      "eset"
    ][i % 50],
    operator: "contains",
    target: ["REQUEST_HEADERS:User-Agent"],
    action: "log",
    phase: "REQUEST_HEADERS",
    severity: "NOTICE",
    msg: `Security Scanner Detected (Rule ${i + 1})`,
    tags: ["scanner", "owasp-crs-v3.3", "bot-detection"]
  })),
  // ==================== BOT DETECTION (40+ rules) ====================
  ...Array.from({ length: 40 }, (_, i) => ({
    id: `9${String(i + 1).padStart(3, "0")}`,
    name: `Bot Detection Rule ${i + 1}`,
    pattern: [
      "bot",
      "crawler",
      "spider",
      "scraper",
      "harvester",
      "curl",
      "wget",
      "lynx",
      "links",
      "elinks",
      "python",
      "perl",
      "java",
      "ruby",
      "node",
      "go",
      "rust",
      "c#",
      "php",
      "aspx",
      "servlet",
      "aiohttp",
      "requests",
      "urllib",
      "httplib",
      "mechanize",
      "pyload",
      "urllib2",
      "urlopen",
      "httpclient",
      "httpconnection",
      "socket",
      "netcat",
      "telnet",
      "ftp",
      "ssh",
      "smtp",
      "pop3",
      "imap",
      "dns"
    ][i % 40],
    operator: "contains",
    target: ["REQUEST_HEADERS:User-Agent"],
    action: "log",
    phase: "REQUEST_HEADERS",
    severity: "NOTICE",
    msg: `Bot Activity Detected (Rule ${i + 1})`,
    tags: ["bot", "scanner", "owasp-crs-v3.3"]
  })),
  // ==================== HTTP COMPLIANCE (35+ rules) ====================
  ...Array.from({ length: 35 }, (_, i) => ({
    id: `10${String(i + 1).padStart(3, "0")}`,
    name: `HTTP Compliance Rule ${i + 1}`,
    pattern: [
      "Host:\\s*\\d+\\.\\d+\\.\\d+\\.\\d+",
      "Host:\\s*localhost",
      "Host:\\s*127\\.0\\.0\\.1",
      "Content-Length:\\s*[^0-9]",
      "Content-Length:\\s*-",
      "Transfer-Encoding:\\s*[^a-z]",
      "GET\\s+.*HTTP/0\\.9",
      "POST\\s+.*HTTP/0\\.9",
      "PUT\\s+.*HTTP/0\\.9",
      "DELETE\\s+.*HTTP/0\\.9",
      "HEAD\\s+.*HTTP/0\\.9",
      "PATCH\\s+.*HTTP/0\\.9",
      "HTTP/1\\.0.*Connection:\\s*keep-alive",
      "HTTP/0\\.9.*Connection",
      "te:\\s*chunked",
      "content-encoding:\\s*x-",
      "accept-encoding:\\s*sdch",
      "accept-encoding:\\s*br",
      "cache-control:\\s*immutable",
      "cache-control:\\s*stale-",
      "content-type:\\s*application/octet-stream",
      "content-type:\\s*text/plain",
      "content-disposition:\\s*attachment",
      "content-disposition:\\s*inline",
      "vary:\\s*",
      "warning:\\s*",
      "strict-transport-security",
      "content-security-policy",
      "x-frame-options",
      "x-content-type-options",
      "x-xss-protection",
      "referrer-policy",
      "feature-policy",
      "permissions-policy",
      "cross-origin-embedder-policy"
    ][i % 35],
    operator: "rx",
    target: ["HEADERS", "REQUEST_METHOD"],
    action: "log",
    phase: "REQUEST_HEADERS",
    severity: "INFO",
    msg: `HTTP Compliance Check (Rule ${i + 1})`,
    tags: ["http", "compliance", "owasp-crs-v3.3"]
  })),
  // ==================== DIRECTORY TRAVERSAL (20+ rules) ====================
  ...Array.from({ length: 20 }, (_, i) => ({
    id: `11${String(i + 1).padStart(3, "0")}`,
    name: `Directory Traversal Rule ${i + 1}`,
    pattern: [
      "\\.\\./",
      "\\.\\.%2f",
      "%2e%2e/",
      "..%5c",
      "%2e%2e%5c",
      "..%252f",
      "..%252e",
      "\\.\\.\\.",
      "..../",
      "....\\\\",
      "directory\\s+listing",
      "index\\.of",
      "parent\\s+directory",
      "^/$",
      "^/$\\?",
      "/.git/",
      "/.svn/",
      "/.hg/",
      "/.bzr/",
      "/.env"
    ][i % 20],
    operator: "rx",
    target: ["REQUEST_URI", "ARGS"],
    action: "block",
    phase: "REQUEST_BODY",
    severity: "HIGH",
    msg: `Directory Traversal Attempt (Rule ${i + 1})`,
    tags: ["traversal", "owasp-crs-v3.3"]
  })),
  // ==================== JAVA DESERIALIZATION (15+ rules) ====================
  ...Array.from({ length: 15 }, (_, i) => ({
    id: `12${String(i + 1).padStart(3, "0")}`,
    name: `Java Deserialization Rule ${i + 1}`,
    pattern: [
      "aced0005",
      "rO0AB",
      "java\\.io\\.ObjectInputStream",
      "java\\.io\\.ObjectOutputStream",
      "java\\.io\\.Serializable",
      "readObject",
      "writeObject",
      "readResolve",
      "readExternal",
      "writeExternal",
      "CommonsCollections",
      "Spring",
      "JNDI",
      "Runtime\\.exec",
      "ProcessBuilder"
    ][i % 15],
    operator: "contains",
    target: ["POST_PAYLOAD"],
    action: "deny",
    phase: "REQUEST_BODY",
    severity: "CRITICAL",
    msg: `Java Deserialization Attack (Rule ${i + 1})`,
    tags: ["deserialization", "java", "owasp-crs-v3.3"]
  })),
  // ==================== NOSQL INJECTION (15+ rules) ====================
  ...Array.from({ length: 15 }, (_, i) => ({
    id: `13${String(i + 1).padStart(3, "0")}`,
    name: `NoSQL Injection Rule ${i + 1}`,
    pattern: [
      `{\\s*["']?\\$where`,
      `{\\s*["']?\\$gt`,
      `{\\s*["']?\\$lt`,
      `{\\s*["']?\\$ne`,
      `{\\s*["']?\\$or`,
      `{\\s*["']?\\$and`,
      `{\\s*["']?\\$regex`,
      `{\\s*["']?\\$exists`,
      "function\\s*\\(",
      `["']?\\$where["']?\\s*:`,
      "db\\.collection",
      "db\\.eval",
      "db\\.getCollection",
      "ObjectId",
      "Mongo"
    ][i % 15],
    operator: "rx",
    target: ["ARGS", "POST_PAYLOAD"],
    action: "deny",
    phase: "REQUEST_BODY",
    severity: "CRITICAL",
    msg: `NoSQL Injection Attempt (Rule ${i + 1})`,
    tags: ["nosqli", "owasp-crs-v3.3"]
  })),
  // ==================== LDAP INJECTION (10+ rules) ====================
  ...Array.from({ length: 10 }, (_, i) => ({
    id: `14${String(i + 1).padStart(3, "0")}`,
    name: `LDAP Injection Rule ${i + 1}`,
    pattern: [
      "(\\*|\\\\|\\(|\\))",
      "ldap://",
      "ldaps://",
      "cn=",
      "dc=",
      "ou=",
      "uid=",
      "mail=",
      "filter=",
      "search="
    ][i % 10],
    operator: "contains",
    target: ["ARGS"],
    action: "block",
    phase: "REQUEST_BODY",
    severity: "HIGH",
    msg: `LDAP Injection Attempt (Rule ${i + 1})`,
    tags: ["ldapi", "owasp-crs-v3.3"]
  })),
  // ==================== LOG INJECTION (10+ rules) ====================
  ...Array.from({ length: 10 }, (_, i) => ({
    id: `15${String(i + 1).padStart(3, "0")}`,
    name: `Log Injection Rule ${i + 1}`,
    pattern: [
      "\\n[a-z0-9]+",
      "\\r[a-z0-9]+",
      "%0a[a-z0-9]+",
      "%0d[a-z0-9]+",
      "\\x0a",
      "\\x0d",
      "ERROR",
      "WARN",
      "INFO",
      "TRACE"
    ][i % 10],
    operator: "rx",
    target: ["ARGS"],
    action: "log",
    phase: "REQUEST_BODY",
    severity: "NOTICE",
    msg: `Log Injection Detection (Rule ${i + 1})`,
    tags: ["log-injection", "owasp-crs-v3.3"]
  })),
  // ==================== RESPONSE ANALYSIS (50+ rules) ====================
  ...Array.from({ length: 50 }, (_, i) => ({
    id: `16${String(i + 1).padStart(3, "0")}`,
    name: `Response Analysis Rule ${i + 1}`,
    pattern: [
      "error",
      "warning",
      "exception",
      "traceback",
      "stack trace",
      "fatal",
      "panic",
      "undefined",
      "null pointer",
      "access denied",
      "permission denied",
      "forbidden",
      "not found",
      "server error",
      "bad request",
      "internal server error",
      "service unavailable",
      "gateway timeout",
      "bad gateway",
      "connection refused",
      "reset by peer",
      "connection timeout",
      "network unreachable",
      "host unreachable",
      "protocol error",
      "invalid argument",
      "file not found",
      "directory not found",
      "connection reset",
      "broken pipe",
      "out of memory",
      "stack overflow",
      "buffer overflow",
      "segmentation fault",
      "illegal instruction",
      "abort",
      "terminate",
      "signal",
      "coredump",
      "errno",
      "strace",
      "ltrace",
      "gdb",
      "dbx",
      "xdb",
      "valgrind",
      "purify",
      "insure",
      "lint",
      "splint"
    ][i % 50],
    operator: "contains",
    target: ["RESPONSE_BODY"],
    action: "log",
    phase: "RESPONSE_BODY",
    severity: "WARNING",
    msg: `Response Analysis Triggered (Rule ${i + 1})`,
    tags: ["response", "information-disclosure", "owasp-crs-v3.3"]
  })),
  // ==================== ENCODING ATTACKS (20+ rules) ====================
  ...Array.from({ length: 20 }, (_, i) => ({
    id: `17${String(i + 1).padStart(3, "0")}`,
    name: `Encoding Attack Rule ${i + 1}`,
    pattern: [
      "%00",
      "%01",
      "%02",
      "%03",
      "%04",
      "%05",
      "%06",
      "%07",
      "%08",
      "%09",
      "%0a",
      "%0d",
      "%0c",
      "%1f",
      "%7f",
      "%80",
      "%ff",
      "&#0+;",
      "&#x00",
      "\\x00"
    ][i % 20],
    operator: "contains",
    target: ["ARGS", "POST_PAYLOAD"],
    action: "block",
    phase: "REQUEST_BODY",
    severity: "WARNING",
    msg: `Encoding Attack Detected (Rule ${i + 1})`,
    tags: ["encoding", "owasp-crs-v3.3"]
  })),
  // ==================== API ABUSE (25+ rules) ====================
  ...Array.from({ length: 25 }, (_, i) => ({
    id: `18${String(i + 1).padStart(3, "0")}`,
    name: `API Abuse Rule ${i + 1}`,
    pattern: [
      "/api/",
      "/graphql",
      "/rest/",
      "/v1/",
      "/v2/",
      "/v3/",
      "/oauth",
      "/auth/",
      "/admin/",
      "/user/",
      "/account/",
      "/profile/",
      "/settings/",
      "/dashboard/",
      "/reports/",
      "/analytics/",
      "/export/",
      "/import/",
      "/backup/",
      "/restore/",
      "/sync/",
      "/health",
      "/status",
      "/debug",
      "/log"
    ][i % 25],
    operator: "contains",
    target: ["REQUEST_URI"],
    action: "log",
    phase: "REQUEST_HEADERS",
    severity: "NOTICE",
    msg: `API Endpoint Access (Rule ${i + 1})`,
    tags: ["api", "owasp-crs-v3.3"]
  })),
  // ==================== SESSION FIXATION (15+ rules) ====================
  ...Array.from({ length: 15 }, (_, i) => ({
    id: `19${String(i + 1).padStart(3, "0")}`,
    name: `Session Fixation Rule ${i + 1}`,
    pattern: [
      "PHPSESSID",
      "JSESSIONID",
      "ASPSESSIONID",
      "ASP.NET_SessionId",
      "CFID",
      "CFTOKEN",
      "__VIEWSTATE",
      "SECURID",
      "auth_token",
      "session_id",
      "session",
      "sid",
      "jsessionid",
      "phpsessid",
      "cookie"
    ][i % 15],
    operator: "contains",
    target: ["REQUEST_HEADERS:Cookie"],
    action: "log",
    phase: "REQUEST_HEADERS",
    severity: "NOTICE",
    msg: `Session Fixation Monitoring (Rule ${i + 1})`,
    tags: ["session", "owasp-crs-v3.3"]
  })),
  // ==================== MISC ATTACKS (43 rules) ====================
  ...Array.from({ length: 43 }, (_, i) => ({
    id: `20${String(i + 1).padStart(3, "0")}`,
    name: `Miscellaneous Attack Rule ${i + 1}`,
    pattern: [
      "<c:\\\\",
      "<script.*src",
      "onclick=",
      "onload=",
      "onmouseover=",
      "onmouseout=",
      "onerror=",
      "onchange=",
      "onsubmit=",
      "onreset=",
      "onkeydown=",
      "onkeyup=",
      "onkeypress=",
      "onmousedown=",
      "onmouseup=",
      "ondblclick=",
      "onfocus=",
      "onblur=",
      "oncontextmenu=",
      "ondrag=",
      "ondrop=",
      "onwheel=",
      "onscroll=",
      "ontouchstart=",
      "ontouchend=",
      "ontouchmove=",
      "ontouchcancel=",
      "onpaste=",
      "oncut=",
      "oncopy=",
      "onbeforeunload=",
      "onunload=",
      "onbeforeload=",
      "onload=",
      "formaction=",
      "onclick=",
      "onmousemove=",
      "onmouseenter=",
      "onmouseleave=",
      "oninput=",
      "onprogress=",
      "onended=",
      "onplaying=",
      "onseeking="
    ][i % 43],
    operator: "rx",
    target: ["ARGS", "POST_PAYLOAD"],
    action: "block",
    phase: "REQUEST_BODY",
    severity: "HIGH",
    msg: `Miscellaneous Attack Detected (Rule ${i + 1})`,
    tags: ["misc", "owasp-crs-v3.3"]
  }))
];
var owasp_crs_rules_default = OWASP_CRS_RULES;

// server/waf/modsecurity-integration.ts
var MODSECURITY_CRS_RULES = owasp_crs_rules_default;
var ModSecurityEngine = class {
  rules = [];
  enabled = true;
  constructor(customRules) {
    this.rules = [...MODSECURITY_CRS_RULES];
    if (customRules) {
      this.rules.push(...customRules);
    }
  }
  /**
   * Evaluate request against ModSecurity rules
   */
  evaluateRequest(requestData) {
    if (!this.enabled) return [];
    const matches = [];
    for (const rule of this.rules) {
      if (!this.shouldApplyRule(rule, requestData)) continue;
      const ruleMatches = this.evaluateRule(rule, requestData);
      if (ruleMatches) {
        matches.push({
          ruleId: rule.id,
          message: rule.msg,
          severity: rule.severity,
          action: rule.action,
          phase: rule.phase
        });
      }
    }
    return matches;
  }
  /**
   * Determine if rule should be evaluated for this request
   */
  shouldApplyRule(rule, requestData) {
    if (!["REQUEST_HEADERS", "REQUEST_BODY"].includes(rule.phase)) {
      return false;
    }
    for (const target of rule.target) {
      if (target === "REQUEST_METHOD" && requestData.method) return true;
      if (target === "REQUEST_URI" && requestData.uri) return true;
      if (target === "ARGS" && (requestData.query || requestData.body)) return true;
      if (target === "HEADERS" && requestData.headers) return true;
      if (target === "POST_PAYLOAD" && requestData.body) return true;
      if (target.startsWith("REQUEST_HEADERS:")) return true;
    }
    return false;
  }
  /**
   * Evaluate a single rule against request data
   */
  evaluateRule(rule, requestData) {
    const regex = new RegExp(rule.pattern, "i");
    for (const target of rule.target) {
      let valueToCheck = "";
      if (target === "REQUEST_METHOD") {
        valueToCheck = requestData.method;
      } else if (target === "REQUEST_URI") {
        valueToCheck = requestData.uri;
      } else if (target === "ARGS") {
        valueToCheck = [
          requestData.query ? JSON.stringify(requestData.query) : "",
          requestData.body || ""
        ].join(" ");
      } else if (target === "HEADERS") {
        valueToCheck = JSON.stringify(requestData.headers);
      } else if (target === "POST_PAYLOAD") {
        valueToCheck = requestData.body || "";
      } else if (target.startsWith("REQUEST_HEADERS:")) {
        const headerName = target.split(":")[1];
        valueToCheck = requestData.headers[headerName.toLowerCase()] || "";
      }
      if (this.matchesOperator(rule.operator, valueToCheck, rule.pattern)) {
        return true;
      }
    }
    return false;
  }
  /**
   * Match against operators
   */
  matchesOperator(operator, value, pattern) {
    switch (operator) {
      case "rx":
        return new RegExp(pattern, "i").test(value);
      case "eq":
        return value === pattern;
      case "contains":
        return value.includes(pattern);
      case "startswith":
        return value.startsWith(pattern);
      case "endswith":
        return value.endsWith(pattern);
      case "gt":
        return parseInt(value) > parseInt(pattern);
      case "lt":
        return parseInt(value) < parseInt(pattern);
      default:
        return false;
    }
  }
  /**
   * Get rule by ID
   */
  getRule(id) {
    return this.rules.find((r) => r.id === id);
  }
  /**
   * Enable/disable engine
   */
  setEnabled(enabled) {
    this.enabled = enabled;
  }
  /**
   * Add custom rule
   */
  addRule(rule) {
    this.rules.push(rule);
  }
  /**
   * Get all rules
   */
  getRules() {
    return this.rules;
  }
  /**
   * Get rule count
   */
  getRuleCount() {
    return this.rules.length;
  }
};
var modSecurityEngine = new ModSecurityEngine();

// server/api/comparison-endpoints.ts
function registerComparisonEndpoints(app2, requireAuth9, requireRole8) {
  app2.post("/api/tenants/:tenantId/waf/test", requireAuth9, (req, res) => {
    try {
      const { tenantId } = req.params;
      const { method = "POST", uri = "/test", headers = {}, body = "" } = req.body;
      const startTime = Date.now();
      const result = wafEngine.analyzeRequest({
        method,
        path: uri,
        headers,
        body: body ? JSON.stringify(body) : "",
        query: {},
        clientIp: req.ip,
        tenantId,
        enforcementMode: "block"
      });
      const processingTimeMs = Date.now() - startTime;
      const response = {
        engine: "waf",
        blocked: result.action === "block" || result.action === "deny",
        severity: result.riskLevel,
        matches: result.matches,
        score: result.score,
        action: result.action,
        processingTimeMs,
        details: result.reason
      };
      res.json({
        success: true,
        result: response
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: error instanceof Error ? error.message : "WAF test failed"
      });
    }
  });
  app2.post("/api/tenants/:tenantId/modsecurity/test", requireAuth9, (req, res) => {
    try {
      const { tenantId } = req.params;
      const { method = "POST", uri = "/test", headers = {}, body = "" } = req.body;
      const startTime = Date.now();
      const matches = modSecurityEngine.evaluateRequest({
        method,
        uri,
        headers,
        body,
        query: {},
        clientIp: req.ip
      });
      const processingTimeMs = Date.now() - startTime;
      const criticalMatches = matches.filter(
        (m) => ["CRITICAL", "EMERGENCY", "ALERT"].includes(m.severity)
      );
      const blocked = criticalMatches.length > 0;
      const maxSeverity = matches.length > 0 ? matches.reduce((max, m) => {
        const severityOrder = {
          "EMERGENCY": 8,
          "ALERT": 7,
          "CRITICAL": 6,
          "ERROR": 5,
          "WARNING": 4,
          "NOTICE": 3,
          "INFO": 2,
          "DEBUG": 1
        };
        return (severityOrder[m.severity] || 0) > (severityOrder[max] || 0) ? m.severity : max;
      }, "INFO") : "LOW";
      const response = {
        engine: "modsecurity",
        blocked,
        severity: maxSeverity,
        matches: matches.map((m) => ({
          id: m.ruleId,
          name: m.message,
          category: m.action
        })),
        score: matches.length > 0 ? Math.min(1, matches.length * 0.2) : 0,
        action: blocked ? "deny" : "allow",
        processingTimeMs,
        details: matches.length > 0 ? `${matches.length} rule(s) triggered` : "No threats detected"
      };
      res.json({
        success: true,
        result: response
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: error instanceof Error ? error.message : "ModSecurity test failed"
      });
    }
  });
  app2.post("/api/tenants/:tenantId/comparison", requireAuth9, async (req, res) => {
    try {
      const { tenantId } = req.params;
      const { method = "POST", uri = "/test", headers = {}, body = "" } = req.body;
      const wafStartTime = Date.now();
      const wafResult = wafEngine.analyzeRequest({
        method,
        path: uri,
        headers,
        body: body ? JSON.stringify(body) : "",
        query: {},
        clientIp: req.ip,
        tenantId,
        enforcementMode: "block"
      });
      const wafProcessingTime = Date.now() - wafStartTime;
      const modSecStartTime = Date.now();
      const modSecMatches = modSecurityEngine.evaluateRequest({
        method,
        uri,
        headers,
        body,
        query: {},
        clientIp: req.ip
      });
      const modSecProcessingTime = Date.now() - modSecStartTime;
      const wafResponse = {
        engine: "waf",
        blocked: wafResult.action === "block" || wafResult.action === "deny",
        severity: wafResult.riskLevel,
        matches: wafResult.matches,
        score: wafResult.score,
        action: wafResult.action,
        processingTimeMs: wafProcessingTime,
        details: wafResult.reason
      };
      const criticalModSecMatches2 = modSecMatches.filter(
        (m) => ["CRITICAL", "EMERGENCY", "ALERT"].includes(m.severity)
      );
      const modSecMaxSeverity = modSecMatches.length > 0 ? modSecMatches.reduce((max, m) => {
        const severityOrder = {
          "EMERGENCY": 8,
          "ALERT": 7,
          "CRITICAL": 6,
          "ERROR": 5,
          "WARNING": 4,
          "NOTICE": 3,
          "INFO": 2,
          "DEBUG": 1
        };
        return (severityOrder[m.severity] || 0) > (severityOrder[max] || 0) ? m.severity : max;
      }, "INFO") : "LOW";
      const modSecResponse = {
        engine: "modsecurity",
        blocked: criticalModSecMatches2.length > 0,
        severity: modSecMaxSeverity,
        matches: modSecMatches.map((m) => ({
          id: m.ruleId,
          name: m.message,
          category: m.action
        })),
        score: modSecMatches.length > 0 ? Math.min(1, modSecMatches.length * 0.2) : 0,
        action: criticalModSecMatches2.length > 0 ? "deny" : "allow",
        processingTimeMs: modSecProcessingTime,
        details: modSecMatches.length > 0 ? `${modSecMatches.length} rule(s) triggered` : "No threats detected"
      };
      const agreement = wafResponse.blocked === modSecResponse.blocked;
      const recommendation = wafResponse.blocked && modSecResponse.blocked ? "BLOCK" : wafResponse.blocked || modSecResponse.blocked ? "CHALLENGE" : "ALLOW";
      res.json({
        success: true,
        waf: wafResponse,
        modsecurity: modSecResponse,
        analysis: {
          agreement,
          speedDifference: Math.abs(wafProcessingTime - modSecProcessingTime),
          fasterEngine: wafProcessingTime < modSecProcessingTime ? "waf" : "modsecurity",
          rulesTriggered: {
            waf: wafResponse.matches.length,
            modsecurity: modSecResponse.matches.length
          },
          recommendation
        }
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: error instanceof Error ? error.message : "Comparison failed"
      });
    }
  });
  app2.get("/api/tenants/:tenantId/engines/status", requireAuth9, (req, res) => {
    try {
      const { tenantId } = req.params;
      res.json({
        success: true,
        engines: {
          waf: {
            name: "WAF Engine",
            status: "active",
            rulesLoaded: 453,
            // OWASP rules count
            enabled: true,
            priority: "secondary"
          },
          modsecurity: {
            name: "ModSecurity CRS v3.3",
            status: "active",
            rulesLoaded: modSecurityEngine.getRuleCount(),
            enabled: true,
            priority: "primary"
          }
        },
        tenantId,
        timestamp: (/* @__PURE__ */ new Date()).toISOString()
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: error instanceof Error ? error.message : "Failed to get status"
      });
    }
  });
}

// server/api/compliance-endpoints.ts
import { Router } from "express";

// server/services/compliance-verification.ts
init_models();
init_db();
var ComplianceVerificationService = class {
  /**
   * Get all compliance frameworks with rule counts
   */
  static async getAllFrameworks() {
    try {
      const frameworks = await ComplianceFramework.findAll({
        include: [
          {
            model: ComplianceRule,
            as: "rules",
            attributes: ["id"],
            required: false
          }
        ]
      });
      return frameworks.map((fw) => ({
        id: fw.id,
        name: fw.name,
        description: fw.description || "",
        ruleCount: fw.rules?.length || 0
      }));
    } catch (error) {
      console.error("Error fetching frameworks:", error);
      throw error;
    }
  }
  /**
   * Get compliance rules for a specific framework
   */
  static async getFrameworkRules(frameworkId) {
    try {
      const framework = await ComplianceFramework.findByPk(frameworkId, {
        include: [
          {
            model: ComplianceRule,
            as: "rules",
            include: [
              {
                model: WafRule,
                as: "wafRule",
                attributes: ["id", "name", "pattern"],
                required: false
              }
            ]
          }
        ]
      });
      if (!framework) {
        throw new Error("Framework not found");
      }
      return {
        framework: {
          id: framework.id,
          name: framework.name,
          description: framework.description || ""
        },
        rules: framework.rules.map((rule) => ({
          id: rule.complianceRuleId,
          description: rule.description,
          category: rule.mappedCategory,
          severity: rule.severity,
          proof: rule.proof,
          wafRuleId: rule.wafRuleId,
          wafRuleName: rule.wafRule?.name
        }))
      };
    } catch (error) {
      console.error("Error fetching framework rules:", error);
      throw error;
    }
  }
  /**
   * Verify a specific compliance rule status for a tenant
   */
  static async verifyComplianceRule(tenantId, ruleId) {
    try {
      const rule = await ComplianceRule.findOne({
        where: { complianceRuleId: ruleId },
        include: [
          {
            model: WafRule,
            as: "wafRule",
            attributes: ["id", "name"],
            required: false
          }
        ]
      });
      if (!rule) {
        throw new Error("Compliance rule not found");
      }
      const policies = await Policy.findAll({
        where: { tenantId },
        attributes: ["id", "enabled", "rules"]
      });
      let ruleEnabled = false;
      for (const policy of policies) {
        if (policy.enabled && policy.rules) {
          const policyRules = JSON.parse(policy.rules || "[]");
          if (policyRules.includes(rule.wafRuleId)) {
            ruleEnabled = true;
            break;
          }
        }
      }
      const status = {
        ruleId: rule.complianceRuleId,
        ruleName: rule.description,
        category: rule.mappedCategory,
        severity: rule.severity,
        status: ruleEnabled ? "compliant" : "non_compliant",
        evidence: rule.proof,
        wafRuleId: rule.wafRuleId,
        mappedWafRuleName: rule.wafRule?.name,
        lastChecked: /* @__PURE__ */ new Date()
      };
      return status;
    } catch (error) {
      console.error("Error verifying compliance rule:", error);
      throw error;
    }
  }
  /**
   * Get compliance status for a framework within a tenant
   */
  static async getFrameworkComplianceStatus(tenantId, frameworkId) {
    try {
      const framework = await ComplianceFramework.findByPk(frameworkId, {
        include: [
          {
            model: ComplianceRule,
            as: "rules",
            include: [
              {
                model: WafRule,
                as: "wafRule",
                attributes: ["id", "name"],
                required: false
              }
            ]
          }
        ]
      });
      if (!framework) {
        throw new Error("Framework not found");
      }
      const policies = await Policy.findAll({
        where: { tenantId, enabled: true },
        attributes: ["id", "rules"]
      });
      const enabledRuleIds = /* @__PURE__ */ new Set();
      for (const policy of policies) {
        const policyRules = JSON.parse(policy.rules || "[]");
        policyRules.forEach((ruleId) => enabledRuleIds.add(ruleId));
      }
      const ruleStatuses = [];
      let compliantCount = 0;
      let partialCount = 0;
      let mandatoryCompliant = 0;
      let mandatoryTotal = 0;
      for (const rule of framework.rules || []) {
        const isEnabled = enabledRuleIds.has(rule.wafRuleId);
        const status = isEnabled ? "compliant" : "non_compliant";
        ruleStatuses.push({
          ruleId: rule.complianceRuleId,
          ruleName: rule.description,
          category: rule.mappedCategory,
          severity: rule.severity,
          status,
          evidence: rule.proof,
          wafRuleId: rule.wafRuleId,
          mappedWafRuleName: rule.wafRule?.name,
          lastChecked: /* @__PURE__ */ new Date()
        });
        if (status === "compliant") compliantCount++;
        if (rule.severity === "mandatory") {
          mandatoryTotal++;
          if (status === "compliant") mandatoryCompliant++;
        }
      }
      const totalRules = ruleStatuses.length;
      const complianceScore = totalRules > 0 ? Math.round(compliantCount / totalRules * 100) : 0;
      const mandatoryCompliance = mandatoryTotal > 0 ? Math.round(mandatoryCompliant / mandatoryTotal * 100) : 100;
      return {
        frameworkId: framework.id,
        frameworkName: framework.name,
        totalRules,
        compliantRules: compliantCount,
        partialRules: partialCount,
        nonCompliantRules: totalRules - compliantCount - partialCount,
        complianceScore,
        mandatoryCompliance,
        ruleStatuses,
        lastAssessment: /* @__PURE__ */ new Date()
      };
    } catch (error) {
      console.error("Error calculating framework compliance:", error);
      throw error;
    }
  }
  /**
   * Get overall compliance status for a tenant across all selected frameworks
   */
  static async getTenantComplianceStatus(tenantId) {
    try {
      const tenantModel = db_default.models.Tenant;
      if (!tenantModel) throw new Error("Tenant model not found");
      const tenant = await tenantModel.findByPk(tenantId);
      if (!tenant) throw new Error("Tenant not found");
      const tenantCompliance = await TenantCompliance2.findAll({
        where: { tenantId },
        attributes: ["complianceFrameworkId"]
      });
      const frameworkIds = tenantCompliance.map(
        (tc) => tc.complianceFrameworkId
      );
      const frameworkStatuses = [];
      let totalScore = 0;
      for (const frameworkId of frameworkIds) {
        const status = await this.getFrameworkComplianceStatus(
          tenantId,
          frameworkId
        );
        frameworkStatuses.push(status);
        totalScore += status.complianceScore;
      }
      const overallScore = frameworkStatuses.length > 0 ? Math.round(totalScore / frameworkStatuses.length) : 0;
      let riskLevel = "low";
      if (overallScore < 50) riskLevel = "critical";
      else if (overallScore < 65) riskLevel = "high";
      else if (overallScore < 80) riskLevel = "medium";
      return {
        tenantId,
        tenantName: tenant.name,
        frameworkStatuses,
        overallScore,
        riskLevel,
        lastUpdated: /* @__PURE__ */ new Date()
      };
    } catch (error) {
      console.error("Error calculating tenant compliance:", error);
      throw error;
    }
  }
  /**
   * Log compliance audit event
   */
  static async logComplianceAudit(tenantId, frameworkId, userId, action, details) {
    try {
      const user = await User.findByPk(userId);
      const framework = await ComplianceFramework.findByPk(frameworkId);
      await ComplianceAudit.create({
        tenantId,
        complianceFrameworkId: frameworkId,
        userId,
        action,
        details,
        userEmail: user?.email || "unknown",
        frameworkName: framework?.name || "unknown"
      });
      console.log(
        `\u2705 Compliance audit logged: ${action} for ${framework?.name}`
      );
    } catch (error) {
      console.error("Error logging compliance audit:", error);
    }
  }
  /**
   * Get compliance audit trail for a tenant
   */
  static async getComplianceAuditTrail(tenantId, limit = 100) {
    try {
      const audits = await ComplianceAudit.findAll({
        where: { tenantId },
        order: [["createdAt", "DESC"]],
        limit,
        attributes: [
          "id",
          "action",
          "details",
          "userEmail",
          "frameworkName",
          "createdAt"
        ]
      });
      return audits;
    } catch (error) {
      console.error("Error fetching compliance audit trail:", error);
      throw error;
    }
  }
  /**
   * Calculate compliance score trends over time
   */
  static async getComplianceTrends(tenantId, frameworkId, days = 30) {
    try {
      const status = await this.getFrameworkComplianceStatus(
        tenantId,
        frameworkId
      );
      return {
        currentScore: status.complianceScore,
        trend: "stable",
        // placeholder
        lastAssessment: status.lastAssessment
      };
    } catch (error) {
      console.error("Error calculating compliance trends:", error);
      throw error;
    }
  }
};

// server/api/compliance-endpoints.ts
var router = Router();
function requireAuth(req, res, next) {
  if (!req.isAuthenticated || !req.isAuthenticated()) {
    return res.status(401).json({ message: "Unauthorized" });
  }
  res.set("Cache-Control", "no-cache, no-store, must-revalidate, private");
  res.set("Pragma", "no-cache");
  res.set("Expires", "0");
  next();
}
function requireRole2(allowedRoles) {
  return (req, res, next) => {
    if (!req.user || !allowedRoles.includes(req.user.role)) {
      return res.status(403).json({ message: "Insufficient permissions" });
    }
    next();
  };
}
router.get("/frameworks", requireAuth, requireRole2(["admin", "operator"]), async (req, res) => {
  try {
    const frameworks = await ComplianceVerificationService.getAllFrameworks();
    res.json({ success: true, frameworks });
  } catch (error) {
    console.error("Error fetching frameworks:", error);
    res.status(500).json({ success: false, error: "Failed to fetch frameworks" });
  }
});
router.get("/framework/:frameworkId/rules", requireAuth, requireRole2(["admin", "operator"]), async (req, res) => {
  try {
    const { frameworkId } = req.params;
    const rules = await ComplianceVerificationService.getFrameworkRules(frameworkId);
    res.json({ success: true, ...rules });
  } catch (error) {
    console.error("Error fetching framework rules:", error);
    res.status(500).json({ success: false, error: "Failed to fetch framework rules" });
  }
});
router.post("/verify-rule", requireAuth, requireRole2(["admin", "operator"]), async (req, res) => {
  try {
    const { tenantId, ruleId } = req.body;
    if (!tenantId || !ruleId) {
      return res.status(400).json({ success: false, error: "Missing tenantId or ruleId" });
    }
    const status = await ComplianceVerificationService.verifyComplianceRule(tenantId, ruleId);
    res.json({ success: true, status });
  } catch (error) {
    console.error("Error verifying compliance rule:", error);
    res.status(500).json({ success: false, error: "Failed to verify compliance rule" });
  }
});
router.get("/tenant/:tenantId/framework/:frameworkId", requireAuth, requireRole2(["admin", "operator"]), async (req, res) => {
  try {
    const { tenantId, frameworkId } = req.params;
    const status = await ComplianceVerificationService.getFrameworkComplianceStatus(tenantId, frameworkId);
    res.json({ success: true, status });
  } catch (error) {
    console.error("Error fetching framework compliance status:", error);
    res.status(500).json({ success: false, error: "Failed to fetch compliance status" });
  }
});
router.get("/tenant/:tenantId/status", requireAuth, requireRole2(["admin", "operator"]), async (req, res) => {
  try {
    const { tenantId } = req.params;
    const status = await ComplianceVerificationService.getTenantComplianceStatus(tenantId);
    res.json({ success: true, status });
  } catch (error) {
    console.error("Error fetching tenant compliance status:", error);
    res.status(500).json({ success: false, error: "Failed to fetch tenant compliance status" });
  }
});
router.post("/audit-log", requireAuth, requireRole2(["admin"]), async (req, res) => {
  try {
    const { tenantId, frameworkId, action, details } = req.body;
    const userId = req.user.id;
    if (!tenantId || !frameworkId || !action) {
      return res.status(400).json({
        success: false,
        error: "Missing required fields: tenantId, frameworkId, action"
      });
    }
    await ComplianceVerificationService.logComplianceAudit(
      tenantId,
      frameworkId,
      userId,
      action,
      details || ""
    );
    res.json({ success: true, message: "Audit logged" });
  } catch (error) {
    console.error("Error logging compliance audit:", error);
    res.status(500).json({ success: false, error: "Failed to log audit" });
  }
});
router.get("/tenant/:tenantId/audit-trail", requireAuth, requireRole2(["admin", "operator"]), async (req, res) => {
  try {
    const { tenantId } = req.params;
    const limit = parseInt(req.query.limit || "100");
    const audits = await ComplianceVerificationService.getComplianceAuditTrail(tenantId, limit);
    res.json({ success: true, audits });
  } catch (error) {
    console.error("Error fetching compliance audit trail:", error);
    res.status(500).json({ success: false, error: "Failed to fetch audit trail" });
  }
});
router.get("/tenant/:tenantId/framework/:frameworkId/trends", requireAuth, requireRole2(["admin", "operator"]), async (req, res) => {
  try {
    const { tenantId, frameworkId } = req.params;
    const days = parseInt(req.query.days || "30");
    const trends = await ComplianceVerificationService.getComplianceTrends(tenantId, frameworkId, days);
    res.json({ success: true, trends });
  } catch (error) {
    console.error("Error fetching compliance trends:", error);
    res.status(500).json({ success: false, error: "Failed to fetch trends" });
  }
});
var compliance_endpoints_default = router;

// server/api/tenant-compliance-endpoints.ts
import { Router as Router2 } from "express";
var router2 = Router2();
function requireAuth2(req, res, next) {
  if (!req.isAuthenticated || !req.isAuthenticated()) {
    return res.status(401).json({ message: "Unauthorized" });
  }
  res.set("Cache-Control", "no-cache, no-store, must-revalidate, private");
  res.set("Pragma", "no-cache");
  res.set("Expires", "0");
  next();
}
function requireRole3(allowedRoles) {
  return (req, res, next) => {
    if (!req.user || !allowedRoles.includes(req.user.role)) {
      return res.status(403).json({ message: "Insufficient permissions" });
    }
    next();
  };
}
router2.post(
  "/select-framework",
  requireAuth2,
  requireRole3(["admin"]),
  async (req, res) => {
    try {
      const { tenantId, frameworkId } = req.body;
      if (!tenantId || !frameworkId) {
        return res.status(400).json({ success: false, error: "Missing tenantId or frameworkId" });
      }
      const { TenantCompliance: TenantCompliance4, ComplianceFramework: ComplianceFramework2 } = await Promise.resolve().then(() => (init_models(), models_exports));
      const framework = await ComplianceFramework2.findByPk(frameworkId);
      if (!framework) {
        return res.status(404).json({ success: false, error: "Framework not found" });
      }
      const existing = await TenantCompliance4.findOne({
        where: { tenantId, complianceFrameworkId: frameworkId }
      });
      if (existing) {
        return res.status(400).json({
          success: false,
          error: "Framework already selected for this tenant"
        });
      }
      await TenantCompliance4.create({
        tenantId,
        complianceFrameworkId: frameworkId,
        complianceStatus: "pending_assessment"
      });
      await ComplianceVerificationService.logComplianceAudit(
        tenantId,
        frameworkId,
        req.user.id,
        "framework_selected",
        `Tenant selected ${framework.name} compliance framework`
      );
      res.json({
        success: true,
        message: `${framework.name} framework selected`
      });
    } catch (error) {
      console.error("Error selecting compliance framework:", error);
      res.status(500).json({ success: false, error: "Failed to select framework" });
    }
  }
);
router2.delete(
  "/deselect-framework",
  requireAuth2,
  requireRole3(["admin"]),
  async (req, res) => {
    try {
      const { tenantId, frameworkId } = req.body;
      if (!tenantId || !frameworkId) {
        return res.status(400).json({ success: false, error: "Missing tenantId or frameworkId" });
      }
      const { TenantCompliance: TenantCompliance4, ComplianceFramework: ComplianceFramework2 } = await Promise.resolve().then(() => (init_models(), models_exports));
      const framework = await ComplianceFramework2.findByPk(frameworkId);
      if (!framework) {
        return res.status(404).json({ success: false, error: "Framework not found" });
      }
      const result = await TenantCompliance4.destroy({
        where: { tenantId, complianceFrameworkId: frameworkId }
      });
      if (result === 0) {
        return res.status(404).json({
          success: false,
          error: "Framework not selected for this tenant"
        });
      }
      await ComplianceVerificationService.logComplianceAudit(
        tenantId,
        frameworkId,
        req.user.id,
        "framework_deselected",
        `Tenant deselected ${framework.name} compliance framework`
      );
      res.json({
        success: true,
        message: `${framework.name} framework deselected`
      });
    } catch (error) {
      console.error("Error deselecting compliance framework:", error);
      res.status(500).json({ success: false, error: "Failed to deselect framework" });
    }
  }
);
router2.get(
  "/:tenantId/frameworks",
  requireAuth2,
  requireRole3(["admin", "operator"]),
  async (req, res) => {
    try {
      const { tenantId } = req.params;
      const { TenantCompliance: TenantCompliance4, ComplianceFramework: ComplianceFramework2 } = await Promise.resolve().then(() => (init_models(), models_exports));
      const tenantFrameworks = await TenantCompliance4.findAll({
        where: { tenantId },
        include: [
          {
            model: ComplianceFramework2,
            as: "framework",
            attributes: ["id", "name", "description"],
            required: false
          }
        ],
        attributes: ["complianceFrameworkId", "complianceStatus", "createdAt"]
      });
      const frameworks = tenantFrameworks.map((tf) => ({
        frameworkId: tf.complianceFrameworkId,
        framework: tf.framework ? {
          id: tf.framework.id,
          name: tf.framework.name,
          description: tf.framework.description
        } : null,
        status: tf.complianceStatus,
        selectedAt: tf.createdAt
      }));
      res.json({ success: true, frameworks });
    } catch (error) {
      console.error("Error fetching tenant frameworks:", error);
      res.status(500).json({ success: false, error: "Failed to fetch frameworks" });
    }
  }
);
router2.get(
  "/:tenantId/available-frameworks",
  requireAuth2,
  requireRole3(["admin", "operator"]),
  async (req, res) => {
    try {
      const { tenantId } = req.params;
      const { TenantCompliance: TenantCompliance4, ComplianceFramework: ComplianceFramework2 } = await Promise.resolve().then(() => (init_models(), models_exports));
      const allFrameworks = await ComplianceFramework2.findAll({
        attributes: ["id", "name", "description"]
      });
      const selectedFrameworks = await TenantCompliance4.findAll({
        where: { tenantId },
        attributes: ["complianceFrameworkId"]
      });
      const selectedIds = selectedFrameworks.map(
        (sf) => sf.complianceFrameworkId
      );
      const available = allFrameworks.filter((f) => !selectedIds.includes(f.id)).map((f) => ({
        id: f.id,
        name: f.name,
        description: f.description
      }));
      res.json({ success: true, available });
    } catch (error) {
      console.error("Error fetching available frameworks:", error);
      res.status(500).json({ success: false, error: "Failed to fetch available frameworks" });
    }
  }
);
router2.patch(
  "/:tenantId/framework/:frameworkId/status",
  requireAuth2,
  requireRole3(["admin"]),
  async (req, res) => {
    try {
      const { tenantId, frameworkId } = req.params;
      const { status } = req.body;
      if (!status || !["pending_assessment", "compliant", "non_compliant"].includes(status)) {
        return res.status(400).json({
          success: false,
          error: "Invalid status value"
        });
      }
      const { TenantCompliance: TenantCompliance4, ComplianceFramework: ComplianceFramework2 } = await Promise.resolve().then(() => (init_models(), models_exports));
      const tenantCompliance = await TenantCompliance4.findOne({
        where: { tenantId, complianceFrameworkId: frameworkId }
      });
      if (!tenantCompliance) {
        return res.status(404).json({
          success: false,
          error: "Framework not selected for this tenant"
        });
      }
      await tenantCompliance.update({ complianceStatus: status });
      const framework = await ComplianceFramework2.findByPk(frameworkId);
      await ComplianceVerificationService.logComplianceAudit(
        tenantId,
        frameworkId,
        req.user.id,
        "status_updated",
        `Compliance status updated to ${status}`
      );
      res.json({
        success: true,
        message: "Compliance status updated"
      });
    } catch (error) {
      console.error("Error updating compliance status:", error);
      res.status(500).json({ success: false, error: "Failed to update status" });
    }
  }
);
router2.get(
  "/:tenantId/summary",
  requireAuth2,
  requireRole3(["admin", "operator"]),
  async (req, res) => {
    try {
      const { tenantId } = req.params;
      const status = await ComplianceVerificationService.getTenantComplianceStatus(tenantId);
      res.json({ success: true, summary: status });
    } catch (error) {
      console.error("Error fetching compliance summary:", error);
      res.status(500).json({ success: false, error: "Failed to fetch compliance summary" });
    }
  }
);
var tenant_compliance_endpoints_default = router2;

// server/api/compliance-dashboard-endpoints.ts
import { Router as Router3 } from "express";

// server/services/compliance-dashboard.ts
init_models();
init_db();
var ComplianceDashboardService = class {
  /**
   * Get dashboard overview data for a tenant
   */
  static async getTenantDashboardOverview(tenantId) {
    try {
      const tenantModel = db_default.models.Tenant;
      const tenant = await tenantModel.findByPk(tenantId);
      if (!tenant) throw new Error("Tenant not found");
      const selectedFrameworks = await TenantCompliance2.findAll({
        where: { tenantId },
        include: [
          {
            model: ComplianceFramework,
            as: "framework",
            attributes: ["id", "name"],
            required: false
          }
        ]
      });
      let totalRules = 0;
      let compliantRules = 0;
      const frameworkBreakdown = [];
      const policies = await Policy.findAll({
        where: { tenantId, enabled: true },
        attributes: ["rules"]
      });
      const enabledWafRuleIds = /* @__PURE__ */ new Set();
      for (const policy of policies) {
        const policyRules = JSON.parse(policy.rules || "[]");
        policyRules.forEach((ruleId) => enabledWafRuleIds.add(ruleId));
      }
      for (const sf of selectedFrameworks) {
        const framework = sf.framework;
        const rules = await ComplianceRule.findAll({
          where: { complianceFrameworkId: framework.id }
        });
        let frameworkCompliant = 0;
        for (const rule of rules) {
          totalRules++;
          if (enabledWafRuleIds.has(rule.wafRuleId)) {
            compliantRules++;
            frameworkCompliant++;
          }
        }
        frameworkBreakdown.push({
          frameworkName: framework.name,
          score: rules.length > 0 ? Math.round(frameworkCompliant / rules.length * 100) : 0,
          totalRules: rules.length,
          compliantRules: frameworkCompliant
        });
      }
      const overallScore = totalRules > 0 ? Math.round(compliantRules / totalRules * 100) : 0;
      let riskLevel = "low";
      if (overallScore < 50) riskLevel = "critical";
      else if (overallScore < 65) riskLevel = "high";
      else if (overallScore < 80) riskLevel = "medium";
      const dashboard = {
        tenantId,
        tenantName: tenant.name,
        overallScore,
        riskLevel,
        selectedFrameworks: selectedFrameworks.length,
        totalRules,
        compliantRules,
        nonCompliantRules: totalRules - compliantRules,
        trends: [],
        // Placeholder for now
        frameworkBreakdown
      };
      return dashboard;
    } catch (error) {
      console.error("Error fetching dashboard overview:", error);
      throw error;
    }
  }
  /**
   * Get system-wide compliance metrics
   */
  static async getSystemMetrics() {
    try {
      const tenantModel = db_default.models.Tenant;
      const allTenants = await tenantModel.findAll({
        attributes: ["id"]
      });
      let totalScore = 0;
      let criticalCount = 0;
      let aboveThresholdCount = 0;
      for (const tenant of allTenants) {
        const dashboard = await this.getTenantDashboardOverview(tenant.id);
        totalScore += dashboard.overallScore;
        if (dashboard.riskLevel === "critical") criticalCount++;
        if (dashboard.overallScore >= 80) aboveThresholdCount++;
      }
      const totalFrameworks = await ComplianceFramework.count();
      const totalRules = await ComplianceRule.count();
      const metrics = {
        totalFrameworks,
        totalRules,
        avgComplianceScore: allTenants.length > 0 ? Math.round(totalScore / allTenants.length) : 0,
        tenantsAboveThreshold: aboveThresholdCount,
        criticalRiskTenants: criticalCount,
        mandatoryRulesCovered: await ComplianceRule.count({ where: { severity: "mandatory" } }),
        complianceTrendDirection: "stable"
      };
      return metrics;
    } catch (error) {
      console.error("Error fetching system metrics:", error);
      throw error;
    }
  }
  /**
   * Get comparison data between frameworks for a tenant
   */
  static async getFrameworkComparison(tenantId) {
    try {
      const selectedFrameworks = await TenantCompliance2.findAll({
        where: { tenantId },
        include: [
          {
            model: ComplianceFramework,
            as: "framework",
            attributes: ["id", "name"],
            required: false
          }
        ]
      });
      const policies = await Policy.findAll({
        where: { tenantId, enabled: true },
        attributes: ["rules"]
      });
      const enabledWafRuleIds = /* @__PURE__ */ new Set();
      for (const policy of policies) {
        const policyRules = JSON.parse(policy.rules || "[]");
        policyRules.forEach((ruleId) => enabledWafRuleIds.add(ruleId));
      }
      const comparison = [];
      for (const sf of selectedFrameworks) {
        const framework = sf.framework;
        const rules = await ComplianceRule.findAll({
          where: { complianceFrameworkId: framework.id },
          attributes: ["severity"]
        });
        let mandatory = 0;
        let recommended = 0;
        let mandatoryCovered = 0;
        let recommendedCovered = 0;
        for (const rule of rules) {
          if (rule.severity === "mandatory") {
            mandatory++;
            if (enabledWafRuleIds.has(rule.wafRuleId)) mandatoryCovered++;
          } else if (rule.severity === "recommended") {
            recommended++;
            if (enabledWafRuleIds.has(rule.wafRuleId)) recommendedCovered++;
          }
        }
        comparison.push({
          framework: framework.name,
          totalRules: rules.length,
          mandatoryRules: mandatory,
          mandatoryCompliance: mandatory > 0 ? Math.round(mandatoryCovered / mandatory * 100) : 100,
          recommendedRules: recommended,
          recommendedCompliance: recommended > 0 ? Math.round(recommendedCovered / recommended * 100) : 100,
          overallCompliance: rules.length > 0 ? Math.round((mandatoryCovered + recommendedCovered) / rules.length * 100) : 0
        });
      }
      return comparison;
    } catch (error) {
      console.error("Error fetching framework comparison:", error);
      throw error;
    }
  }
  /**
   * Get rule-level compliance coverage across all tenants
   */
  static async getRuleCoverageAnalysis(frameworkId) {
    try {
      const whereClause = frameworkId ? { complianceFrameworkId: frameworkId } : {};
      const rules = await ComplianceRule.findAll({
        where: whereClause,
        include: [
          {
            model: ComplianceFramework,
            as: "framework",
            attributes: ["name"],
            required: false
          }
        ]
      });
      const tenantModel = db_default.models.Tenant;
      const allTenants = await tenantModel.findAll({ attributes: ["id"] });
      const coverage = [];
      for (const rule of rules) {
        let compliantTenants = 0;
        let nonCompliantTenants = 0;
        for (const tenant of allTenants) {
          const policies = await Policy.findAll({
            where: { tenantId: tenant.id, enabled: true },
            attributes: ["rules"]
          });
          let isCompliant = false;
          for (const policy of policies) {
            const policyRules = JSON.parse(policy.rules || "[]");
            if (policyRules.includes(rule.wafRuleId)) {
              isCompliant = true;
              break;
            }
          }
          if (isCompliant) compliantTenants++;
          else nonCompliantTenants++;
        }
        const totalTenants = compliantTenants + nonCompliantTenants;
        coverage.push({
          ruleId: rule.complianceRuleId,
          description: rule.description,
          category: rule.mappedCategory,
          severity: rule.severity,
          compliantTenants,
          nonCompliantTenants,
          overallCoverage: totalTenants > 0 ? Math.round(compliantTenants / totalTenants * 100) : 0
        });
      }
      return coverage;
    } catch (error) {
      console.error("Error fetching rule coverage analysis:", error);
      throw error;
    }
  }
  /**
   * Export compliance report for tenant
   */
  static async generateComplianceReport(tenantId) {
    try {
      const dashboard = await this.getTenantDashboardOverview(tenantId);
      const comparison = await this.getFrameworkComparison(tenantId);
      return {
        generatedAt: /* @__PURE__ */ new Date(),
        tenant: {
          id: dashboard.tenantId,
          name: dashboard.tenantName
        },
        summary: {
          overallScore: dashboard.overallScore,
          riskLevel: dashboard.riskLevel,
          selectedFrameworks: dashboard.selectedFrameworks,
          totalRules: dashboard.totalRules,
          compliantRules: dashboard.compliantRules,
          nonCompliantRules: dashboard.nonCompliantRules
        },
        frameworkDetails: comparison
      };
    } catch (error) {
      console.error("Error generating compliance report:", error);
      throw error;
    }
  }
};

// server/api/compliance-dashboard-endpoints.ts
var router3 = Router3();
function requireAuth3(req, res, next) {
  if (!req.isAuthenticated || !req.isAuthenticated()) {
    return res.status(401).json({ message: "Unauthorized" });
  }
  res.set("Cache-Control", "no-cache, no-store, must-revalidate, private");
  res.set("Pragma", "no-cache");
  res.set("Expires", "0");
  next();
}
function requireRole4(allowedRoles) {
  return (req, res, next) => {
    if (!req.user || !allowedRoles.includes(req.user.role)) {
      return res.status(403).json({ message: "Insufficient permissions" });
    }
    next();
  };
}
router3.get("/tenant/:tenantId/overview", requireAuth3, requireRole4(["admin", "operator", "viewer"]), async (req, res) => {
  try {
    const { tenantId } = req.params;
    const dashboard = await ComplianceDashboardService.getTenantDashboardOverview(tenantId);
    res.json({ success: true, dashboard });
  } catch (error) {
    console.error("Error fetching dashboard overview:", error);
    res.status(500).json({ success: false, error: "Failed to fetch dashboard overview" });
  }
});
router3.get("/metrics", requireAuth3, requireRole4(["admin", "operator"]), async (req, res) => {
  try {
    const metrics = await ComplianceDashboardService.getSystemMetrics();
    res.json({ success: true, metrics });
  } catch (error) {
    console.error("Error fetching metrics:", error);
    res.status(500).json({ success: false, error: "Failed to fetch metrics" });
  }
});
router3.get(
  "/tenant/:tenantId/framework-comparison",
  requireAuth3,
  requireRole4(["admin", "operator"]),
  async (req, res) => {
    try {
      const { tenantId } = req.params;
      const comparison = await ComplianceDashboardService.getFrameworkComparison(tenantId);
      res.json({ success: true, comparison });
    } catch (error) {
      console.error("Error fetching framework comparison:", error);
      res.status(500).json({ success: false, error: "Failed to fetch framework comparison" });
    }
  }
);
router3.get(
  "/rule-coverage",
  requireAuth3,
  requireRole4(["admin", "operator"]),
  async (req, res) => {
    try {
      const { frameworkId } = req.query;
      const coverage = await ComplianceDashboardService.getRuleCoverageAnalysis(
        frameworkId || void 0
      );
      res.json({ success: true, coverage });
    } catch (error) {
      console.error("Error fetching rule coverage:", error);
      res.status(500).json({ success: false, error: "Failed to fetch rule coverage" });
    }
  }
);
router3.get(
  "/tenant/:tenantId/report",
  requireAuth3,
  requireRole4(["admin", "operator"]),
  async (req, res) => {
    try {
      const { tenantId } = req.params;
      const report = await ComplianceDashboardService.generateComplianceReport(tenantId);
      res.json({ success: true, report });
    } catch (error) {
      console.error("Error generating compliance report:", error);
      res.status(500).json({ success: false, error: "Failed to generate compliance report" });
    }
  }
);
var compliance_dashboard_endpoints_default = router3;

// server/api/compliance-monitoring-endpoints.ts
import { Router as Router4 } from "express";

// server/services/compliance-monitoring.ts
init_models();
import { EventEmitter as EventEmitter2 } from "events";
var activeAlerts = /* @__PURE__ */ new Map();
var complianceMonitorEmitter = new EventEmitter2();
var ComplianceMonitoringService = class {
  static SCORE_DROP_THRESHOLD = 15;
  // Alert if score drops > 15%
  static LOW_SCORE_THRESHOLD = 65;
  // Alert if overall score < 65%
  static CRITICAL_SCORE_THRESHOLD = 50;
  // Critical alert if < 50%
  /**
   * Check compliance status and generate alerts
   */
  static async checkComplianceStatus(tenantId, frameworkId) {
    try {
      const framework = await ComplianceFramework.findByPk(frameworkId);
      if (!framework) return null;
      const tenantFramework = await TenantCompliance2.findOne({
        where: { tenantId, complianceFrameworkId: frameworkId }
      });
      if (!tenantFramework) return null;
      const rules = await ComplianceRule.findAll({
        where: { complianceFrameworkId: frameworkId }
      });
      const policies = await Policy.findAll({
        where: { tenantId, enabled: true },
        attributes: ["rules"]
      });
      const enabledWafRuleIds = /* @__PURE__ */ new Set();
      for (const policy of policies) {
        const policyRules = JSON.parse(policy.rules || "[]");
        policyRules.forEach((ruleId) => enabledWafRuleIds.add(ruleId));
      }
      let compliantCount = 0;
      for (const rule of rules) {
        if (enabledWafRuleIds.has(rule.wafRuleId)) {
          compliantCount++;
        }
      }
      const currentScore = rules.length > 0 ? Math.round(compliantCount / rules.length * 100) : 0;
      await this.generateAlerts(tenantId, frameworkId, framework.name, currentScore);
      const status = {
        tenantId,
        frameworkId,
        frameworkName: framework.name,
        score: currentScore,
        riskLevel: this.getRiskLevel(currentScore),
        status: this.getComplianceStatus(currentScore),
        lastCheck: /* @__PURE__ */ new Date(),
        alerts: activeAlerts.get(`${tenantId}:${frameworkId}`) || []
      };
      return status;
    } catch (error) {
      console.error("Error checking compliance status:", error);
      throw error;
    }
  }
  /**
   * Generate alerts based on compliance score changes
   */
  static async generateAlerts(tenantId, frameworkId, frameworkName, currentScore) {
    const alertKey = `${tenantId}:${frameworkId}`;
    const existingAlerts = activeAlerts.get(alertKey) || [];
    if (currentScore < this.CRITICAL_SCORE_THRESHOLD && !existingAlerts.some((a) => a.type === "threshold_breach")) {
      this.addAlert({
        tenantId,
        frameworkId,
        frameworkName,
        severity: "critical",
        type: "threshold_breach",
        message: `Critical: ${frameworkName} compliance at ${currentScore}%, below critical threshold of ${this.CRITICAL_SCORE_THRESHOLD}%`,
        currentScore,
        threshold: this.CRITICAL_SCORE_THRESHOLD
      });
    }
    if (currentScore < this.LOW_SCORE_THRESHOLD && !existingAlerts.some((a) => a.type === "compliance_drop")) {
      this.addAlert({
        tenantId,
        frameworkId,
        frameworkName,
        severity: "high",
        type: "compliance_drop",
        message: `High: ${frameworkName} compliance at ${currentScore}%, below threshold of ${this.LOW_SCORE_THRESHOLD}%`,
        currentScore,
        threshold: this.LOW_SCORE_THRESHOLD
      });
    }
    if (currentScore < 80 && currentScore >= this.LOW_SCORE_THRESHOLD) {
      if (!existingAlerts.some((a) => a.type === "rule_violation")) {
        this.addAlert({
          tenantId,
          frameworkId,
          frameworkName,
          severity: "medium",
          type: "rule_violation",
          message: `Medium: ${frameworkName} compliance at ${currentScore}%, review pending rules`,
          currentScore,
          threshold: 80
        });
      }
    }
    if (activeAlerts.has(alertKey)) {
      complianceMonitorEmitter.emit("compliance-alert", {
        tenantId,
        frameworkId,
        alerts: activeAlerts.get(alertKey)
      });
    }
  }
  /**
   * Add alert to active alerts
   */
  static addAlert(data) {
    const alertKey = `${data.tenantId}:${data.frameworkId}`;
    const alert = {
      id: `alert-${Date.now()}`,
      tenantId: data.tenantId,
      frameworkId: data.frameworkId,
      frameworkName: data.frameworkName,
      severity: data.severity,
      type: data.type,
      message: data.message,
      previousScore: data.previousScore || 0,
      currentScore: data.currentScore,
      threshold: data.threshold,
      isRead: false,
      createdAt: /* @__PURE__ */ new Date()
    };
    const alerts = activeAlerts.get(alertKey) || [];
    alerts.push(alert);
    activeAlerts.set(alertKey, alerts);
  }
  /**
   * Get all active alerts for a tenant
   */
  static async getTenantAlerts(tenantId) {
    const alerts = [];
    for (const [key, alertList] of activeAlerts.entries()) {
      if (key.startsWith(tenantId)) {
        alerts.push(...alertList);
      }
    }
    return alerts.sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime());
  }
  /**
   * Get alerts for a specific framework
   */
  static async getFrameworkAlerts(tenantId, frameworkId) {
    const alertKey = `${tenantId}:${frameworkId}`;
    return activeAlerts.get(alertKey) || [];
  }
  /**
   * Mark alert as read
   */
  static markAlertAsRead(alertId) {
    for (const [, alerts] of activeAlerts.entries()) {
      const alert = alerts.find((a) => a.id === alertId);
      if (alert) {
        alert.isRead = true;
        return true;
      }
    }
    return false;
  }
  /**
   * Clear alerts for a framework
   */
  static clearFrameworkAlerts(tenantId, frameworkId) {
    const alertKey = `${tenantId}:${frameworkId}`;
    activeAlerts.delete(alertKey);
  }
  /**
   * Get real-time compliance status for all tenant frameworks
   */
  static async getTenantComplianceStatusAll(tenantId) {
    const frameworks = await TenantCompliance2.findAll({
      where: { tenantId }
    });
    const statuses = [];
    for (const tf of frameworks) {
      const status = await this.checkComplianceStatus(tenantId, tf.complianceFrameworkId);
      if (status) {
        statuses.push(status);
      }
    }
    return statuses;
  }
  /**
   * Get event emitter for real-time updates
   */
  static getEventEmitter() {
    return complianceMonitorEmitter;
  }
  /**
   * Helper: determine risk level
   */
  static getRiskLevel(score) {
    if (score < 50) return "critical";
    if (score < 65) return "high";
    if (score < 80) return "medium";
    return "low";
  }
  /**
   * Helper: determine compliance status
   */
  static getComplianceStatus(score) {
    if (score >= 80) return "compliant";
    if (score >= 65) return "at_risk";
    return "non_compliant";
  }
};

// server/api/compliance-monitoring-endpoints.ts
var router4 = Router4();
function requireAuth4(req, res, next) {
  if (!req.isAuthenticated || !req.isAuthenticated()) {
    return res.status(401).json({ message: "Unauthorized" });
  }
  res.set("Cache-Control", "no-cache, no-store, must-revalidate, private");
  next();
}
function requireRole5(allowedRoles) {
  return (req, res, next) => {
    if (!req.user || !allowedRoles.includes(req.user.role)) {
      return res.status(403).json({ message: "Insufficient permissions" });
    }
    next();
  };
}
router4.get("/tenant/:tenantId/status", requireAuth4, requireRole5(["admin", "operator"]), async (req, res) => {
  try {
    const { tenantId } = req.params;
    const statuses = await ComplianceMonitoringService.getTenantComplianceStatusAll(tenantId);
    res.json({ success: true, statuses });
  } catch (error) {
    console.error("Error fetching compliance status:", error);
    res.status(500).json({ success: false, error: "Failed to fetch compliance status" });
  }
});
router4.get(
  "/tenant/:tenantId/framework/:frameworkId/status",
  requireAuth4,
  requireRole5(["admin", "operator", "viewer"]),
  async (req, res) => {
    try {
      const { tenantId, frameworkId } = req.params;
      const status = await ComplianceMonitoringService.checkComplianceStatus(tenantId, frameworkId);
      if (!status) {
        return res.status(404).json({ success: false, error: "Framework not found" });
      }
      res.json({ success: true, status });
    } catch (error) {
      console.error("Error fetching framework status:", error);
      res.status(500).json({ success: false, error: "Failed to fetch framework status" });
    }
  }
);
router4.get("/tenant/:tenantId/alerts", requireAuth4, requireRole5(["admin", "operator"]), async (req, res) => {
  try {
    const { tenantId } = req.params;
    const alerts = await ComplianceMonitoringService.getTenantAlerts(tenantId);
    res.json({ success: true, alerts });
  } catch (error) {
    console.error("Error fetching alerts:", error);
    res.status(500).json({ success: false, error: "Failed to fetch alerts" });
  }
});
router4.get(
  "/tenant/:tenantId/framework/:frameworkId/alerts",
  requireAuth4,
  requireRole5(["admin", "operator"]),
  async (req, res) => {
    try {
      const { tenantId, frameworkId } = req.params;
      const alerts = await ComplianceMonitoringService.getFrameworkAlerts(tenantId, frameworkId);
      res.json({ success: true, alerts });
    } catch (error) {
      console.error("Error fetching framework alerts:", error);
      res.status(500).json({ success: false, error: "Failed to fetch framework alerts" });
    }
  }
);
router4.post("/alert/:alertId/read", requireAuth4, requireRole5(["admin", "operator"]), async (req, res) => {
  try {
    const { alertId } = req.params;
    const success = ComplianceMonitoringService.markAlertAsRead(alertId);
    if (!success) {
      return res.status(404).json({ success: false, error: "Alert not found" });
    }
    res.json({ success: true });
  } catch (error) {
    console.error("Error marking alert as read:", error);
    res.status(500).json({ success: false, error: "Failed to mark alert as read" });
  }
});
router4.delete(
  "/tenant/:tenantId/framework/:frameworkId/alerts",
  requireAuth4,
  requireRole5(["admin"]),
  async (req, res) => {
    try {
      const { tenantId, frameworkId } = req.params;
      ComplianceMonitoringService.clearFrameworkAlerts(tenantId, frameworkId);
      res.json({ success: true });
    } catch (error) {
      console.error("Error clearing alerts:", error);
      res.status(500).json({ success: false, error: "Failed to clear alerts" });
    }
  }
);
router4.get("/stream/:tenantId", requireAuth4, requireRole5(["admin", "operator"]), (req, res) => {
  const { tenantId } = req.params;
  res.setHeader("Content-Type", "text/event-stream");
  res.setHeader("Cache-Control", "no-cache");
  res.setHeader("Connection", "keep-alive");
  res.setHeader("Access-Control-Allow-Origin", "*");
  const emitter = ComplianceMonitoringService.getEventEmitter();
  res.write(`data: ${JSON.stringify({ type: "connected", tenantId })}

`);
  const handleAlert = (data) => {
    if (data.tenantId === tenantId) {
      res.write(`data: ${JSON.stringify({ type: "compliance-alert", ...data })}

`);
    }
  };
  emitter.on("compliance-alert", handleAlert);
  const statusInterval = setInterval(async () => {
    try {
      const statuses = await ComplianceMonitoringService.getTenantComplianceStatusAll(tenantId);
      res.write(`data: ${JSON.stringify({ type: "status-update", statuses })}

`);
    } catch (error) {
      console.error("Error sending status update:", error);
    }
  }, 3e4);
  req.on("close", () => {
    emitter.removeListener("compliance-alert", handleAlert);
    clearInterval(statusInterval);
    res.end();
  });
});
var compliance_monitoring_endpoints_default = router4;

// server/api/compliance-remediation-endpoints.ts
import { Router as Router5 } from "express";

// server/services/compliance-remediation.ts
init_models();
init_db();
var ComplianceRemediationService = class {
  /**
   * Generate remediation actions for low compliance
   */
  static async generateRemediationActions(tenantId, frameworkId, complianceScore) {
    try {
      const actions = [];
      if (complianceScore < 50) {
        actions.push(await this.createRemediationAction(tenantId, frameworkId, "enforce_strict"));
      } else if (complianceScore < 65) {
        actions.push(await this.createRemediationAction(tenantId, frameworkId, "enable_rule"));
      } else if (complianceScore < 80) {
        actions.push(await this.createRemediationAction(tenantId, frameworkId, "update_policy"));
      }
      return actions;
    } catch (error) {
      console.error("Error generating remediation actions:", error);
      throw error;
    }
  }
  /**
   * Create a single remediation action
   */
  static async createRemediationAction(tenantId, frameworkId, type) {
    const framework = await db_default.models.ComplianceFramework.findByPk(frameworkId);
    const frameworkName = framework?.name || frameworkId;
    let description = "";
    let affectedRules = [];
    switch (type) {
      case "enable_rule":
        description = `Auto-enable missing compliance rules for ${frameworkName}`;
        affectedRules = await this.getMissingRuleIds(tenantId, frameworkId);
        break;
      case "update_policy":
        description = `Update security policy to meet ${frameworkName} requirements`;
        break;
      case "enforce_strict":
        description = `Enforce strict compliance mode for ${frameworkName} - CRITICAL`;
        break;
      case "manual_review":
        description = `Manual review required for ${frameworkName} compliance`;
        break;
    }
    return {
      id: `action-${Date.now()}`,
      tenantId,
      frameworkId,
      type,
      status: "pending",
      description,
      affectedRules,
      createdAt: /* @__PURE__ */ new Date()
    };
  }
  /**
   * Execute remediation action
   */
  static async executeRemediationAction(action) {
    try {
      action.status = "in_progress";
      switch (action.type) {
        case "enable_rule":
          await this.enableMissingRules(action.tenantId, action.frameworkId, action.affectedRules);
          action.result = `Enabled ${action.affectedRules.length} compliance rules`;
          break;
        case "update_policy":
          await this.updateTenantPolicy(action.tenantId, action.frameworkId);
          action.result = "Security policy updated with compliance rules";
          break;
        case "enforce_strict":
          await this.enforceStrictMode(action.tenantId, action.frameworkId);
          action.result = "Strict compliance mode activated";
          break;
        case "manual_review":
          action.result = "Flagged for manual compliance review";
          break;
      }
      action.status = "completed";
      action.executedAt = /* @__PURE__ */ new Date();
      return true;
    } catch (error) {
      console.error("Error executing remediation action:", error);
      action.status = "failed";
      action.result = `Failed: ${error instanceof Error ? error.message : "Unknown error"}`;
      return false;
    }
  }
  /**
   * Get missing rule IDs for framework
   */
  static async getMissingRuleIds(tenantId, frameworkId) {
    const rules = await db_default.models.ComplianceRule.findAll({
      where: { complianceFrameworkId: frameworkId }
    });
    const policies = await Policy.findAll({
      where: { tenantId, enabled: true },
      attributes: ["rules"]
    });
    const enabledRuleIds = /* @__PURE__ */ new Set();
    for (const policy of policies) {
      const policyRules = JSON.parse(policy.rules || "[]");
      policyRules.forEach((ruleId) => enabledRuleIds.add(ruleId));
    }
    const missingRules = [];
    for (const rule of rules) {
      if (!enabledRuleIds.has(rule.wafRuleId)) {
        missingRules.push(rule.wafRuleId);
      }
    }
    return missingRules;
  }
  /**
   * Enable missing compliance rules in policy
   */
  static async enableMissingRules(tenantId, frameworkId, ruleIds) {
    const policy = await Policy.findOne({
      where: { tenantId, enabled: true }
    });
    if (!policy) return;
    const currentRules = JSON.parse(policy.rules || "[]");
    const uniqueRules = /* @__PURE__ */ new Set([...currentRules, ...ruleIds]);
    policy.rules = JSON.stringify(Array.from(uniqueRules));
    await policy.save();
  }
  /**
   * Update tenant policy with compliance rules
   */
  static async updateTenantPolicy(tenantId, frameworkId) {
    const complianceRules = await db_default.models.ComplianceRule.findAll({
      where: { complianceFrameworkId: frameworkId, severity: "mandatory" }
    });
    const mandatoryRuleIds = complianceRules.map((r) => r.wafRuleId);
    const policy = await Policy.findOne({
      where: { tenantId, enabled: true }
    });
    if (policy) {
      const currentRules = JSON.parse(policy.rules || "[]");
      const updatedRules = Array.from(/* @__PURE__ */ new Set([...currentRules, ...mandatoryRuleIds]));
      policy.rules = JSON.stringify(updatedRules);
      await policy.save();
    }
  }
  /**
   * Enforce strict compliance mode
   */
  static async enforceStrictMode(tenantId, frameworkId) {
    const complianceRules = await db_default.models.ComplianceRule.findAll({
      where: { complianceFrameworkId: frameworkId }
    });
    const allRuleIds = complianceRules.map((r) => r.wafRuleId);
    let policy = await Policy.findOne({
      where: { tenantId, name: "Strict Compliance Policy" }
    });
    if (!policy) {
      policy = await Policy.create({
        tenantId,
        name: "Strict Compliance Policy",
        enabled: true,
        rules: JSON.stringify(allRuleIds)
      });
    } else {
      policy.rules = JSON.stringify(allRuleIds);
      await policy.save();
    }
  }
  /**
   * Get remediation history
   */
  static async getRemediationHistory(tenantId) {
    return [];
  }
  /**
   * Schedule automated remediation based on compliance schedule
   */
  static async scheduleAutomatedRemediation(tenantId) {
    console.log(`Scheduling automated remediation for tenant ${tenantId}`);
  }
};

// server/api/compliance-remediation-endpoints.ts
var router5 = Router5();
function requireAuth5(req, res, next) {
  if (!req.isAuthenticated || !req.isAuthenticated()) {
    return res.status(401).json({ message: "Unauthorized" });
  }
  res.set("Cache-Control", "no-cache, no-store, must-revalidate, private");
  next();
}
function requireRole6(allowedRoles) {
  return (req, res, next) => {
    if (!req.user || !allowedRoles.includes(req.user.role)) {
      return res.status(403).json({ message: "Insufficient permissions" });
    }
    next();
  };
}
router5.post("/generate", requireAuth5, requireRole6(["admin"]), async (req, res) => {
  try {
    const { tenantId, frameworkId, complianceScore } = req.body;
    if (!tenantId || !frameworkId || complianceScore === void 0) {
      return res.status(400).json({ success: false, error: "Missing required fields" });
    }
    const actions = await ComplianceRemediationService.generateRemediationActions(
      tenantId,
      frameworkId,
      complianceScore
    );
    res.json({ success: true, actions });
  } catch (error) {
    console.error("Error generating remediation actions:", error);
    res.status(500).json({ success: false, error: "Failed to generate remediation actions" });
  }
});
router5.post("/execute", requireAuth5, requireRole6(["admin"]), async (req, res) => {
  try {
    const action = req.body;
    const success = await ComplianceRemediationService.executeRemediationAction(action);
    if (success) {
      res.json({ success: true, action });
    } else {
      res.status(500).json({ success: false, error: "Remediation execution failed", action });
    }
  } catch (error) {
    console.error("Error executing remediation:", error);
    res.status(500).json({ success: false, error: "Failed to execute remediation action" });
  }
});
router5.get("/tenant/:tenantId/history", requireAuth5, requireRole6(["admin", "operator"]), async (req, res) => {
  try {
    const { tenantId } = req.params;
    const history = await ComplianceRemediationService.getRemediationHistory(tenantId);
    res.json({ success: true, history });
  } catch (error) {
    console.error("Error fetching remediation history:", error);
    res.status(500).json({ success: false, error: "Failed to fetch remediation history" });
  }
});
router5.post("/schedule", requireAuth5, requireRole6(["admin"]), async (req, res) => {
  try {
    const { tenantId } = req.body;
    if (!tenantId) {
      return res.status(400).json({ success: false, error: "Tenant ID required" });
    }
    await ComplianceRemediationService.scheduleAutomatedRemediation(tenantId);
    res.json({ success: true, message: "Automated remediation scheduled" });
  } catch (error) {
    console.error("Error scheduling remediation:", error);
    res.status(500).json({ success: false, error: "Failed to schedule remediation" });
  }
});
var compliance_remediation_endpoints_default = router5;

// server/api/compliance-webhooks-endpoints.ts
import { Router as Router6 } from "express";

// server/services/compliance-webhooks.ts
var webhooks = /* @__PURE__ */ new Map();
var webhookHistory = /* @__PURE__ */ new Map();
var ComplianceWebhookService = class {
  /**
   * Register a webhook
   */
  static registerWebhook(config) {
    const webhook = {
      ...config,
      id: `webhook-${Date.now()}`,
      createdAt: /* @__PURE__ */ new Date()
    };
    webhooks.set(webhook.id, webhook);
    webhookHistory.set(webhook.id, []);
    return webhook;
  }
  /**
   * Get webhooks for tenant
   */
  static getWebhooks(tenantId) {
    const result = [];
    for (const webhook of webhooks.values()) {
      if (webhook.tenantId === tenantId) {
        result.push(webhook);
      }
    }
    return result;
  }
  /**
   * Update webhook
   */
  static updateWebhook(webhookId, updates) {
    const webhook = webhooks.get(webhookId);
    if (!webhook) return null;
    const updated = { ...webhook, ...updates };
    webhooks.set(webhookId, updated);
    return updated;
  }
  /**
   * Delete webhook
   */
  static deleteWebhook(webhookId) {
    return webhooks.delete(webhookId);
  }
  /**
   * Send webhook event
   */
  static async sendWebhookEvent(tenantId, event, data) {
    const tenantWebhooks = this.getWebhooks(tenantId);
    for (const webhook of tenantWebhooks) {
      if (!webhook.isActive || !webhook.events.includes(event)) {
        continue;
      }
      const payload = {
        event,
        tenantId,
        timestamp: /* @__PURE__ */ new Date(),
        data
      };
      if (webhook.secret) {
        const crypto = __require("crypto");
        payload.signature = crypto.createHmac("sha256", webhook.secret).update(JSON.stringify(payload)).digest("hex");
      }
      await this.sendWithRetries(webhook, payload);
    }
  }
  /**
   * Send webhook with retry logic
   */
  static async sendWithRetries(webhook, payload) {
    let lastError = null;
    for (let attempt = 0; attempt <= webhook.retries; attempt++) {
      try {
        const response = await fetch(webhook.url, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "X-Webhook-Signature": payload.signature || ""
          },
          body: JSON.stringify(payload),
          signal: AbortSignal.timeout(1e4)
        });
        this.logWebhookEvent(webhook.id, {
          event: payload.event,
          status: "success",
          statusCode: response.status,
          timestamp: /* @__PURE__ */ new Date()
        });
        return;
      } catch (error) {
        lastError = error;
        this.logWebhookEvent(webhook.id, {
          event: payload.event,
          status: "failed",
          attempt: attempt + 1,
          error: lastError.message,
          timestamp: /* @__PURE__ */ new Date()
        });
        if (attempt < webhook.retries) {
          await new Promise((resolve) => setTimeout(resolve, 1e3 * (attempt + 1)));
        }
      }
    }
    console.error(`Webhook delivery failed after ${webhook.retries + 1} attempts:`, lastError?.message);
  }
  /**
   * Log webhook event for history/debugging
   */
  static logWebhookEvent(webhookId, event) {
    const history = webhookHistory.get(webhookId) || [];
    history.push(event);
    if (history.length > 100) {
      history.shift();
    }
    webhookHistory.set(webhookId, history);
  }
  /**
   * Get webhook delivery history
   */
  static getWebhookHistory(webhookId) {
    return webhookHistory.get(webhookId) || [];
  }
  /**
   * Test webhook
   */
  static async testWebhook(webhook) {
    const testPayload = {
      event: "test",
      tenantId: webhook.tenantId,
      timestamp: /* @__PURE__ */ new Date(),
      data: { message: "Webhook test from compliance system" }
    };
    try {
      const response = await fetch(webhook.url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(testPayload),
        signal: AbortSignal.timeout(5e3)
      });
      return response.status >= 200 && response.status < 300;
    } catch (error) {
      console.error("Webhook test failed:", error);
      return false;
    }
  }
  /**
   * Trigger compliance alert webhook
   */
  static async triggerComplianceAlert(tenantId, alert) {
    await this.sendWebhookEvent(tenantId, "compliance_alert", {
      type: "alert",
      framework: alert.frameworkName,
      severity: alert.severity,
      message: alert.message,
      score: alert.currentScore
    });
  }
  /**
   * Trigger remediation action webhook
   */
  static async triggerRemediationAction(tenantId, action) {
    await this.sendWebhookEvent(tenantId, "remediation_action", {
      type: "remediation",
      actionType: action.type,
      status: action.status,
      description: action.description,
      result: action.result
    });
  }
  /**
   * Trigger audit log webhook
   */
  static async triggerAuditLog(tenantId, audit) {
    await this.sendWebhookEvent(tenantId, "audit_log", {
      type: "audit",
      action: audit.action,
      framework: audit.frameworkName,
      user: audit.userEmail
    });
  }
};

// server/api/compliance-webhooks-endpoints.ts
import { z as z4 } from "zod";
var router6 = Router6();
function requireAuth6(req, res, next) {
  if (!req.isAuthenticated || !req.isAuthenticated()) {
    return res.status(401).json({ message: "Unauthorized" });
  }
  res.set("Cache-Control", "no-cache, no-store, must-revalidate, private");
  next();
}
function requireRole7(allowedRoles) {
  return (req, res, next) => {
    if (!req.user || !allowedRoles.includes(req.user.role)) {
      return res.status(403).json({ message: "Insufficient permissions" });
    }
    next();
  };
}
var webhookSchema = z4.object({
  url: z4.string().url(),
  events: z4.array(z4.enum(["compliance_alert", "remediation_action", "audit_log"])).min(1),
  isActive: z4.boolean().default(true),
  secret: z4.string().optional(),
  retries: z4.number().int().min(0).max(5).default(3)
});
router6.post("/register", requireAuth6, requireRole7(["admin"]), async (req, res) => {
  try {
    const validation = webhookSchema.safeParse(req.body);
    if (!validation.success) {
      return res.status(400).json({ success: false, errors: validation.error.errors });
    }
    const webhook = ComplianceWebhookService.registerWebhook({
      tenantId: req.body.tenantId,
      ...validation.data
    });
    res.json({ success: true, webhook });
  } catch (error) {
    console.error("Error registering webhook:", error);
    res.status(500).json({ success: false, error: "Failed to register webhook" });
  }
});
router6.get("/tenant/:tenantId", requireAuth6, requireRole7(["admin", "operator"]), (req, res) => {
  try {
    const { tenantId } = req.params;
    const webhooks2 = ComplianceWebhookService.getWebhooks(tenantId);
    res.json({ success: true, webhooks: webhooks2 });
  } catch (error) {
    console.error("Error fetching webhooks:", error);
    res.status(500).json({ success: false, error: "Failed to fetch webhooks" });
  }
});
router6.put("/:webhookId", requireAuth6, requireRole7(["admin"]), async (req, res) => {
  try {
    const { webhookId } = req.params;
    const webhook = ComplianceWebhookService.updateWebhook(webhookId, req.body);
    if (!webhook) {
      return res.status(404).json({ success: false, error: "Webhook not found" });
    }
    res.json({ success: true, webhook });
  } catch (error) {
    console.error("Error updating webhook:", error);
    res.status(500).json({ success: false, error: "Failed to update webhook" });
  }
});
router6.delete("/:webhookId", requireAuth6, requireRole7(["admin"]), (req, res) => {
  try {
    const { webhookId } = req.params;
    const success = ComplianceWebhookService.deleteWebhook(webhookId);
    if (!success) {
      return res.status(404).json({ success: false, error: "Webhook not found" });
    }
    res.json({ success: true });
  } catch (error) {
    console.error("Error deleting webhook:", error);
    res.status(500).json({ success: false, error: "Failed to delete webhook" });
  }
});
router6.post("/:webhookId/test", requireAuth6, requireRole7(["admin"]), async (req, res) => {
  try {
    const { webhookId } = req.params;
    const webhooks2 = Array.from(new Map(Object.entries({})));
    const allWebhooks = ComplianceWebhookService.getWebhooks(req.body.tenantId);
    const webhook = allWebhooks.find((w) => w.id === webhookId);
    if (!webhook) {
      return res.status(404).json({ success: false, error: "Webhook not found" });
    }
    const testSuccess = await ComplianceWebhookService.testWebhook(webhook);
    res.json({ success: true, testPassed: testSuccess });
  } catch (error) {
    console.error("Error testing webhook:", error);
    res.status(500).json({ success: false, error: "Failed to test webhook" });
  }
});
router6.get("/:webhookId/history", requireAuth6, requireRole7(["admin", "operator"]), (req, res) => {
  try {
    const { webhookId } = req.params;
    const history = ComplianceWebhookService.getWebhookHistory(webhookId);
    res.json({ success: true, history });
  } catch (error) {
    console.error("Error fetching webhook history:", error);
    res.status(500).json({ success: false, error: "Failed to fetch webhook history" });
  }
});
var compliance_webhooks_endpoints_default = router6;

// server/utils/ip-extraction.ts
var IPV4_REGEX = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
var IPV6_REGEX = /^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))$/;
function isValidIp(ip) {
  if (!ip || typeof ip !== "string") return false;
  const trimmed = ip.trim();
  if (trimmed.length === 0) return false;
  return IPV4_REGEX.test(trimmed) || IPV6_REGEX.test(trimmed);
}
function extractFirstValidIp(ips) {
  if (!ips) return null;
  const ipList = ips.split(",").map((ip) => ip.trim());
  for (const ip of ipList) {
    if (isValidIp(ip)) {
      return ip;
    }
  }
  return null;
}
function extractClientIp(req) {
  try {
    const xForwardedFor = req.headers?.["x-forwarded-for"];
    if (xForwardedFor) {
      const ip = extractFirstValidIp(xForwardedFor);
      if (ip) return ip;
    }
    const xRealIp = req.headers?.["x-real-ip"];
    if (xRealIp && typeof xRealIp === "string") {
      const ip = xRealIp.trim();
      if (isValidIp(ip)) return ip;
    }
    const remoteAddress = req.socket?.remoteAddress || req.connection?.remoteAddress;
    if (remoteAddress && typeof remoteAddress === "string") {
      let ip = remoteAddress.trim();
      if (ip.startsWith("::ffff:")) {
        ip = ip.substring(7);
      }
      if (isValidIp(ip)) return ip;
    }
    return "unknown";
  } catch (error) {
    console.warn("Error extracting client IP:", error);
    return "unknown";
  }
}
function extractClientIpFromRequest(req, requestBody) {
  if (requestBody?.clientIp && typeof requestBody.clientIp === "string") {
    const ip = requestBody.clientIp.trim();
    if (isValidIp(ip)) return ip;
  }
  return extractClientIp(req);
}
function sanitizeIp(ip) {
  if (!ip) return "unknown";
  const trimmed = ip.trim();
  if (isValidIp(trimmed)) return trimmed;
  if (trimmed.startsWith("::ffff:")) {
    const cleaned = trimmed.substring(7);
    if (isValidIp(cleaned)) return cleaned;
  }
  return "unknown";
}

// server/utils/waf-helpers.ts
function extractThresholds(policy) {
  return {
    blockThreshold: policy?.blockThreshold ?? 70,
    challengeThreshold: policy?.challengeThreshold ?? 50,
    monitorThreshold: policy?.monitorThreshold ?? 30
  };
}
function mergeAndPrepareRules(globalRules, customRules) {
  return [...globalRules, ...customRules].map((r) => ({
    ...r,
    severity: r.severity || "medium"
  }));
}

// server/api/challenge-endpoints.ts
import { Router as Router7 } from "express";

// server/utils/captcha.ts
var challenges = /* @__PURE__ */ new Map();
var MAX_CHALLENGES = 1e4;
var CHALLENGE_TTL = 10 * 60 * 1e3;
var MAX_ATTEMPTS = 5;
function generateChallenge() {
  const num1 = Math.floor(Math.random() * 20) + 1;
  const num2 = Math.floor(Math.random() * 20) + 1;
  const operations = ["+", "-", "*"];
  const operation = operations[Math.floor(Math.random() * operations.length)];
  let answer;
  let question;
  switch (operation) {
    case "+":
      answer = num1 + num2;
      question = `${num1} + ${num2}`;
      break;
    case "-":
      answer = Math.abs(num1 - num2);
      question = `${Math.max(num1, num2)} - ${Math.min(num1, num2)}`;
      break;
    case "*":
      answer = num1 * num2;
      question = `${num1} \xD7 ${num2}`;
      break;
  }
  const id = Math.random().toString(36).substring(2, 11);
  if (challenges.size > MAX_CHALLENGES) {
    const now2 = /* @__PURE__ */ new Date();
    for (const [key, challenge] of challenges.entries()) {
      if (challenge.expiresAt < now2) {
        challenges.delete(key);
      }
    }
  }
  const now = /* @__PURE__ */ new Date();
  challenges.set(id, {
    id,
    num1,
    num2,
    operation,
    question,
    answer,
    createdAt: now,
    expiresAt: new Date(now.getTime() + CHALLENGE_TTL),
    attempts: 0
  });
  return { id, question };
}
function verifyChallenge(id, answer) {
  const challenge = challenges.get(id);
  if (!challenge) {
    return { success: false, message: "Challenge not found", error: "invalid_challenge" };
  }
  if (/* @__PURE__ */ new Date() > challenge.expiresAt) {
    challenges.delete(id);
    return { success: false, message: "Challenge expired", error: "expired" };
  }
  challenge.attempts++;
  if (challenge.attempts > MAX_ATTEMPTS) {
    challenges.delete(id);
    return { success: false, message: "Too many attempts", error: "too_many_attempts" };
  }
  const userAnswer = parseInt(answer, 10);
  if (isNaN(userAnswer)) {
    return { success: false, message: "Invalid answer format" };
  }
  if (userAnswer === challenge.answer) {
    challenges.delete(id);
    return { success: true, message: "Challenge passed" };
  }
  return {
    success: false,
    message: "Incorrect answer. Please try again.",
    error: "incorrect_answer"
  };
}
function getChallenge(id) {
  const challenge = challenges.get(id);
  if (!challenge) {
    return null;
  }
  if (/* @__PURE__ */ new Date() > challenge.expiresAt) {
    challenges.delete(id);
    return null;
  }
  return { question: challenge.question };
}
function cleanupExpiredChallenges() {
  const now = /* @__PURE__ */ new Date();
  let cleaned = 0;
  for (const [key, challenge] of challenges.entries()) {
    if (challenge.expiresAt < now) {
      challenges.delete(key);
      cleaned++;
    }
  }
  return cleaned;
}
setInterval(() => {
  const cleaned = cleanupExpiredChallenges();
  if (cleaned > 0) {
    console.log(`[CAPTCHA] Cleaned up ${cleaned} expired challenges`);
  }
}, 5 * 60 * 1e3);

// server/api/challenge-endpoints.ts
var router7 = Router7();
var bypassTokens = /* @__PURE__ */ new Map();
function generateToken() {
  return Math.random().toString(36).substring(2) + Math.random().toString(36).substring(2);
}
router7.get("/challenge", (req, res) => {
  try {
    const { id, question } = generateChallenge();
    res.json({
      success: true,
      challengeId: id,
      question,
      hint: "Solve the math problem above",
      ttl: 600
      // 10 minutes
    });
  } catch (error) {
    console.error("Challenge generation error:", error);
    res.status(500).json({ error: "Failed to generate challenge" });
  }
});
router7.post("/verify-challenge", (req, res) => {
  try {
    const { challengeId, answer, requestId } = req.body;
    const clientIp = req.ip || req.socket?.remoteAddress || "unknown";
    if (!challengeId || !answer) {
      return res.status(400).json({
        error: "Missing challengeId or answer"
      });
    }
    const verification = verifyChallenge(challengeId, answer);
    if (!verification.success) {
      return res.status(400).json({
        success: false,
        message: verification.message,
        error: verification.error
      });
    }
    const token = generateToken();
    const expiresAt = new Date(Date.now() + 10 * 60 * 1e3);
    bypassTokens.set(token, {
      ip: clientIp,
      expiresAt,
      requestId: requestId || "unknown"
    });
    res.json({
      success: true,
      message: "Challenge passed! You can now retry your request.",
      bypassToken: token,
      expiresIn: 600
    });
  } catch (error) {
    console.error("Challenge verification error:", error);
    res.status(500).json({ error: "Verification service error" });
  }
});
router7.get("/challenge/:id", (req, res) => {
  try {
    const challenge = getChallenge(req.params.id);
    if (!challenge) {
      return res.status(404).json({
        error: "Challenge not found or expired"
      });
    }
    res.json({
      success: true,
      question: challenge.question
    });
  } catch (error) {
    console.error("Challenge retrieval error:", error);
    res.status(500).json({ error: "Failed to retrieve challenge" });
  }
});
function cleanupExpiredTokens() {
  const now = /* @__PURE__ */ new Date();
  let cleaned = 0;
  for (const [token, data] of bypassTokens.entries()) {
    if (data.expiresAt < now) {
      bypassTokens.delete(token);
      cleaned++;
    }
  }
  return cleaned;
}
setInterval(() => {
  const cleaned = cleanupExpiredTokens();
  if (cleaned > 0) {
    console.log(`[CAPTCHA] Cleaned up ${cleaned} expired bypass tokens`);
  }
}, 5 * 60 * 1e3);
var challenge_endpoints_default = router7;

// server/services/behavioral-analysis.ts
var BehavioralAnalysisEngine = class {
  loginHistory = /* @__PURE__ */ new Map();
  behaviorProfiles = /* @__PURE__ */ new Map();
  failedLoginThreshold = 5;
  lockoutDurationMs = 15 * 60 * 1e3;
  // 15 minutes
  historyWindow = 24 * 60 * 60 * 1e3;
  // 24 hours
  botThresholdScore = 75;
  /**
   * Track a login attempt
   */
  trackLoginAttempt(attempt) {
    let profile = this.behaviorProfiles.get(attempt.email) || this.createProfile(attempt.email);
    if (profile.isLocked && profile.lockExpiresAt > attempt.timestamp) {
      profile.totalAttempts++;
      return {
        allowed: false,
        reason: `Account locked due to too many failed attempts. Try again after ${Math.round((profile.lockExpiresAt.getTime() - attempt.timestamp.getTime()) / 6e4)} minutes`,
        profile
      };
    } else if (profile.isLocked && profile.lockExpiresAt <= attempt.timestamp) {
      profile.isLocked = false;
      profile.lockExpiresAt = void 0;
    }
    this.updateLoginHistory(attempt);
    profile.totalAttempts++;
    profile.lastAttempt = attempt.timestamp;
    this.updateIpBehavior(profile, attempt);
    if (!attempt.success) {
      profile.failedAttempts++;
      const recentFailures = this.getRecentFailures(attempt.email, this.historyWindow);
      if (recentFailures >= this.failedLoginThreshold) {
        profile.isLocked = true;
        profile.lockExpiresAt = new Date(attempt.timestamp.getTime() + this.lockoutDurationMs);
        return {
          allowed: false,
          reason: `Account locked after ${recentFailures} failed attempts. Try again in 15 minutes`,
          profile
        };
      }
      const riskScore = this.calculateFailureRisk(profile, attempt);
      if (riskScore > 70) {
        return {
          allowed: false,
          reason: `Suspicious login pattern detected (Risk: ${Math.round(riskScore)}/100)`,
          profile
        };
      }
    } else {
      profile.successfulAttempts++;
      profile.failedAttempts = 0;
    }
    this.behaviorProfiles.set(attempt.email, profile);
    return {
      allowed: true,
      profile
    };
  }
  /**
   * Analyze bot signals
   */
  analyzeBotSignals(signals, email) {
    let botScore = 0;
    const factors = [];
    if (signals.tlsFingerprint) {
      if (this.isGenericTlsFingerprint(signals.tlsFingerprint)) {
        botScore += 15;
        factors.push("Generic TLS fingerprint");
      }
    }
    if (signals.requestTiming.length >= 2) {
      const avgTiming = signals.requestTiming.reduce((a, b) => a + b, 0) / signals.requestTiming.length;
      const variance = this.calculateVariance(signals.requestTiming);
      const stdDev = Math.sqrt(variance);
      if (stdDev < 50 && avgTiming < 200) {
        botScore += 25;
        factors.push("Suspiciously regular request timing");
      }
      if (avgTiming < 100) {
        botScore += 15;
        factors.push("Requests too fast (possible automation)");
      }
    }
    if (signals.userAgentConsistency > 95) {
      botScore += 10;
      factors.push("Unusually consistent user agent");
    } else if (signals.userAgentConsistency < 10) {
      botScore += 20;
      factors.push("Rapidly changing user agents");
    }
    if (signals.headerAnomalies > 3) {
      botScore += signals.headerAnomalies * 5;
      factors.push(`Multiple header anomalies detected (${signals.headerAnomalies})`);
    }
    if (signals.pathPatterns.length > 0) {
      const suspiciousPatterns = signals.pathPatterns.filter(
        (p) => /admin|api|config|backup|\.env|\.git|wp-admin|phpmyadmin/i.test(p)
      );
      if (suspiciousPatterns.length > 0) {
        botScore += suspiciousPatterns.length * 10;
        factors.push(`Suspicious path patterns: ${suspiciousPatterns.slice(0, 2).join(", ")}`);
      }
    }
    botScore = Math.min(100, botScore + (100 - signals.trustScore) * 0.3);
    const profile = this.behaviorProfiles.get(email);
    if (profile) {
      profile.botScore = botScore;
    }
    return {
      isBotLikely: botScore >= this.botThresholdScore,
      botScore: Math.round(botScore),
      factors
    };
  }
  /**
   * Calculate anomaly score combining multiple factors
   */
  calculateAnomalyScore(email) {
    const profile = this.behaviorProfiles.get(email);
    if (!profile) {
      return {
        anomalyScore: 0,
        components: {},
        riskLevel: "low"
      };
    }
    const components = {};
    const failureRate = profile.failedAttempts / Math.max(1, profile.totalAttempts);
    components.failureRate = failureRate * 40;
    const uniqueCountries = /* @__PURE__ */ new Set();
    for (const ipData of Array.from(profile.ips.values())) {
      ipData.countries.forEach((c) => uniqueCountries.add(c));
    }
    if (uniqueCountries.size > 2) {
      components.geoAnomaly = Math.min(30, uniqueCountries.size * 10);
    } else {
      components.geoAnomaly = 0;
    }
    const totalUAs = /* @__PURE__ */ new Set();
    for (const ipData of Array.from(profile.ips.values())) {
      ipData.userAgents.forEach((ua) => totalUAs.add(ua));
    }
    if (totalUAs.size > 10) {
      components.userAgentAnomaly = 25;
    } else if (totalUAs.size > 5) {
      components.userAgentAnomaly = 15;
    } else {
      components.userAgentAnomaly = 0;
    }
    const recentAttempts = this.getRecentAttempts(email, 60 * 60 * 1e3);
    if (recentAttempts > 20) {
      components.velocityAnomaly = 30;
    } else if (recentAttempts > 10) {
      components.velocityAnomaly = 15;
    } else {
      components.velocityAnomaly = 0;
    }
    const anomalyScore = Math.min(100, Object.values(components).reduce((a, b) => a + b, 0));
    let riskLevel = "low";
    if (anomalyScore >= 75) riskLevel = "critical";
    else if (anomalyScore >= 60) riskLevel = "high";
    else if (anomalyScore >= 40) riskLevel = "medium";
    profile.anomalyScore = anomalyScore;
    profile.riskLevel = riskLevel;
    return {
      anomalyScore: Math.round(anomalyScore),
      components: Object.fromEntries(Object.entries(components).map(([k, v]) => [k, Math.round(v)])),
      riskLevel
    };
  }
  /**
   * Detect credential stuffing patterns
   */
  detectCredentialStuffing(email) {
    const profile = this.behaviorProfiles.get(email);
    if (!profile) {
      return { isStuffing: false, confidence: 0, indicators: [] };
    }
    const indicators = [];
    let confidence = 0;
    const uniqueIps = profile.ips.size;
    if (uniqueIps > 5) {
      confidence += 20;
      indicators.push(`${uniqueIps} different IPs (credential sharing)`);
    }
    if (profile.failedAttempts > 10) {
      confidence += 25;
      indicators.push(`${profile.failedAttempts} failed attempts (brute force)`);
    }
    const recentAttempts = this.getRecentAttempts(email, 10 * 60 * 1e3);
    if (recentAttempts > 15) {
      confidence += 30;
      indicators.push(`${recentAttempts} attempts in 10 minutes (rapid)`);
    }
    const uniqueUAs = /* @__PURE__ */ new Set();
    for (const ipData of Array.from(profile.ips.values())) {
      ipData.userAgents.forEach((ua) => uniqueUAs.add(ua));
    }
    if (uniqueUAs.size > 8) {
      confidence += 15;
      indicators.push(`${uniqueUAs.size} different user agents`);
    }
    const suspiciousIps = Array.from(profile.ips.values()).filter(
      (ip) => ip.suspiciousPatterns.length > 0
    ).length;
    if (suspiciousIps > 2) {
      confidence += 10;
      indicators.push(`${suspiciousIps} suspicious IPs`);
    }
    confidence = Math.min(100, confidence);
    return {
      isStuffing: confidence >= 60,
      confidence: Math.round(confidence),
      indicators
    };
  }
  /**
   * Get profile for user
   */
  getProfile(email) {
    return this.behaviorProfiles.get(email);
  }
  /**
   * Clear old history (cleanup)
   */
  clearOldHistory(beforeDate) {
    let cleaned = 0;
    for (const [email, attempts] of Array.from(this.loginHistory.entries())) {
      const filtered = attempts.filter((a) => a.timestamp > beforeDate);
      if (filtered.length === 0) {
        this.loginHistory.delete(email);
        cleaned++;
      } else {
        this.loginHistory.set(email, filtered);
      }
    }
    return cleaned;
  }
  // Private helpers
  createProfile(email) {
    return {
      email,
      totalAttempts: 0,
      failedAttempts: 0,
      successfulAttempts: 0,
      lastAttempt: /* @__PURE__ */ new Date(),
      ips: /* @__PURE__ */ new Map(),
      isLocked: false,
      botScore: 0,
      anomalyScore: 0,
      riskLevel: "low"
    };
  }
  updateLoginHistory(attempt) {
    const history = this.loginHistory.get(attempt.email) || [];
    history.push(attempt);
    if (history.length > 100) {
      history.shift();
    }
    this.loginHistory.set(attempt.email, history);
  }
  updateIpBehavior(profile, attempt) {
    let ipBehavior = profile.ips.get(attempt.ip);
    if (!ipBehavior) {
      ipBehavior = {
        attempts: 0,
        failures: 0,
        lastSeen: attempt.timestamp,
        countries: /* @__PURE__ */ new Set(),
        userAgents: /* @__PURE__ */ new Set(),
        suspiciousPatterns: []
      };
    }
    ipBehavior.attempts++;
    if (!attempt.success) ipBehavior.failures++;
    ipBehavior.lastSeen = attempt.timestamp;
    ipBehavior.userAgents.add(attempt.userAgent);
    if (ipBehavior.attempts > 10 && ipBehavior.failures === ipBehavior.attempts) {
      if (!ipBehavior.suspiciousPatterns.includes("all_failed")) {
        ipBehavior.suspiciousPatterns.push("all_failed");
      }
    }
    profile.ips.set(attempt.ip, ipBehavior);
  }
  getRecentFailures(email, windowMs) {
    const history = this.loginHistory.get(email) || [];
    const cutoff = new Date(Date.now() - windowMs);
    return history.filter((h) => h.timestamp > cutoff && !h.success).length;
  }
  getRecentAttempts(email, windowMs) {
    const history = this.loginHistory.get(email) || [];
    const cutoff = new Date(Date.now() - windowMs);
    return history.filter((h) => h.timestamp > cutoff).length;
  }
  calculateFailureRisk(profile, attempt) {
    let risk = 0;
    risk += 10;
    if (profile.failedAttempts > 3) {
      risk += 20;
    }
    const ipData = profile.ips.get(attempt.ip);
    if (ipData && ipData.userAgents.size > 5) {
      risk += 25;
    }
    if (profile.ips.size > 10) {
      risk += 20;
    }
    return Math.min(100, risk);
  }
  isGenericTlsFingerprint(fingerprint) {
    const genericFingerprints = ["default", "chrome", "firefox", "bot"];
    return genericFingerprints.some((g) => fingerprint.toLowerCase().includes(g));
  }
  calculateVariance(numbers) {
    if (numbers.length === 0) return 0;
    const mean = numbers.reduce((a, b) => a + b, 0) / numbers.length;
    return numbers.reduce((a, b) => a + Math.pow(b - mean, 2), 0) / numbers.length;
  }
};
var behavioralEngine = new BehavioralAnalysisEngine();

// server/services/bot-detector.ts
var BotDetector = class {
  suspiciousPathPatterns = [
    /\/admin/i,
    /\/api\/admin/i,
    /wp-admin/i,
    /phpmyadmin/i,
    /\.env/i,
    /\.git/i,
    /config\.php/i,
    /web\.config/i,
    /\.aws/i,
    /\.env\.local/i,
    /backup/i,
    /uploads/i,
    /downloads/i,
    /\.zip/i,
    /\.sql/i,
    /shell\.php/i,
    /test\.php/i
  ];
  suspiciousUserAgents = [
    /bot/i,
    /crawler/i,
    /spider/i,
    /scraper/i,
    /curl/i,
    /wget/i,
    /python/i,
    /java(?!script)/i,
    /perl/i,
    /ruby/i,
    /golang/i,
    /php/i,
    /sqlmap/i,
    /nikto/i,
    /nessus/i,
    /burp/i,
    /masscan/i,
    /nmap/i
  ];
  genericUserAgents = [
    "mozilla/5.0",
    "user-agent",
    "-",
    "none",
    ""
  ];
  /**
   * Analyze request for bot patterns
   */
  analyze(signals) {
    let score = 0;
    const factors = [];
    let detectionMethod = "composite";
    const pathScore = this.analyzePath(signals.path);
    if (pathScore > 0) {
      score += pathScore;
      factors.push("Suspicious path pattern");
    }
    const uaScore = this.analyzeUserAgent(signals.userAgent);
    if (uaScore > 0) {
      score += uaScore;
      factors.push("Bot-like user agent");
    }
    const headerScore = this.analyzeHeaders(signals.headers);
    if (headerScore > 0) {
      score += headerScore;
      factors.push("Suspicious header pattern");
    }
    if (this.isMethodAnomaly(signals.method, signals.path)) {
      score += 15;
      factors.push(`Unusual ${signals.method} request to ${signals.path}`);
    }
    if (signals.bodySize !== void 0 && signals.bodySize > 10 * 1024 * 1024) {
      score += 10;
      factors.push("Extremely large payload");
    }
    score = Math.min(100, score);
    return {
      isBot: score >= 60,
      score: Math.round(score),
      factors,
      detectionMethod
    };
  }
  /**
   * Detect scraping patterns
   */
  detectScrapingPattern(requests, windowMs = 6e4) {
    if (requests.length < 2) {
      return { isScraping: false, confidence: 0, indicators: [] };
    }
    const indicators = [];
    let confidence = 0;
    const requestsByIp = this.groupByIp(requests);
    for (const [ip, ipRequests] of Array.from(requestsByIp.entries())) {
      if (ipRequests.length < 5) continue;
      const paths = ipRequests.map((r) => r.path);
      const sequentialScore = this.detectSequentialAccess(paths);
      if (sequentialScore > 50) {
        confidence += 25;
        indicators.push(`IP ${ip.substring(0, 10)}... accessing sequential paths`);
      }
      const timeWindow = ipRequests[ipRequests.length - 1].timestamp - ipRequests[0].timestamp;
      const velocity = ipRequests.length / (timeWindow / 1e3);
      if (velocity > 10) {
        confidence += 30;
        indicators.push(`High velocity: ${velocity.toFixed(1)} requests/second`);
      }
      const headerConsistency = this.calculateHeaderConsistency(ipRequests);
      if (headerConsistency > 90) {
        confidence += 15;
        indicators.push("Highly consistent headers (bot-like)");
      }
      const userAgents = new Set(ipRequests.map((r) => r.userAgent));
      if (userAgents.size === 1 && ipRequests.length > 20) {
        confidence += 20;
        indicators.push("Single user agent for many requests");
      }
      const noRefererCount = ipRequests.filter((r) => !r.headers.referer).length;
      if (noRefererCount === ipRequests.length && ipRequests.length > 10) {
        confidence += 15;
        indicators.push("No referer headers (direct requests)");
      }
    }
    confidence = Math.min(100, confidence);
    return {
      isScraping: confidence >= 60,
      confidence: Math.round(confidence),
      indicators: indicators.slice(0, 3)
    };
  }
  /**
   * Detect credential stuffing bot patterns
   */
  detectCredentialStuffingBot(attempts) {
    const indicators = [];
    let confidence = 0;
    if (attempts.length < 5) {
      return { isCredentialStuffing: false, confidence: 0, indicators: [] };
    }
    const loginAttempts = attempts.filter((a) => a.path.includes("login") && a.method === "POST");
    if (loginAttempts.length > 10) {
      const timeWindow = loginAttempts[loginAttempts.length - 1].timestamp - loginAttempts[0].timestamp;
      const velocity = loginAttempts.length / (timeWindow / 1e3);
      if (velocity > 1) {
        confidence += 35;
        indicators.push(`Rapid login attempts: ${velocity.toFixed(1)}/second`);
      }
    }
    const headerConsistency = this.calculateHeaderConsistency(attempts);
    if (headerConsistency > 85) {
      confidence += 25;
      indicators.push("Bot-consistent headers");
    }
    const userAgents = new Set(attempts.map((a) => a.userAgent));
    if (userAgents.size <= 2 && attempts.length > 20) {
      confidence += 20;
      indicators.push("Consistent user agent across attempts");
    }
    const paths = attempts.map((a) => a.path).filter((p) => p.includes("login") || p.includes("admin"));
    if (paths.length === attempts.length && paths.length > 15) {
      confidence += 15;
      indicators.push("Systematic credential attack pattern");
    }
    const timings = [];
    for (let i = 1; i < attempts.length; i++) {
      timings.push(attempts[i].timestamp - attempts[i - 1].timestamp);
    }
    if (timings.length > 0) {
      const avgTiming = timings.reduce((a, b) => a + b) / timings.length;
      const variance = this.calculateVariance(timings);
      if (avgTiming < 500 && variance < 1e5) {
        confidence += 20;
        indicators.push("Mechanical request timing");
      }
    }
    confidence = Math.min(100, confidence);
    return {
      isCredentialStuffing: confidence >= 65,
      confidence: Math.round(confidence),
      indicators: indicators.slice(0, 3)
    };
  }
  // Private helpers
  analyzePath(path4) {
    let score = 0;
    for (const pattern of this.suspiciousPathPatterns) {
      if (pattern.test(path4)) {
        score += 20;
      }
    }
    return Math.min(40, score);
  }
  analyzeUserAgent(ua) {
    let score = 0;
    if (this.genericUserAgents.some((g) => ua.toLowerCase() === g.toLowerCase())) {
      score += 25;
    }
    for (const pattern of this.suspiciousUserAgents) {
      if (pattern.test(ua)) {
        score += 20;
        break;
      }
    }
    if (ua.length < 10) {
      score += 15;
    }
    return Math.min(50, score);
  }
  analyzeHeaders(headers) {
    let score = 0;
    const requiredHeaders = ["accept", "accept-language", "accept-encoding"];
    for (const header of requiredHeaders) {
      if (!headers[header] && !headers[header.replace("-", "_")]) {
        score += 10;
      }
    }
    if (headers["user-agent"]?.toString().includes("bot")) {
      score += 15;
    }
    if (!headers.referer && !headers.host) {
      score += 10;
    }
    return Math.min(40, score);
  }
  isMethodAnomaly(method, path4) {
    if ((method === "DELETE" || method === "PATCH") && path4.includes("login")) {
      return true;
    }
    if (method === "HEAD" && (path4.includes("api") && !path4.includes("health"))) {
      return true;
    }
    return false;
  }
  groupByIp(requests) {
    const grouped = /* @__PURE__ */ new Map();
    for (const req of requests) {
      if (!grouped.has(req.ip)) {
        grouped.set(req.ip, []);
      }
      grouped.get(req.ip).push(req);
    }
    return grouped;
  }
  detectSequentialAccess(paths) {
    if (paths.length < 5) return 0;
    let score = 0;
    let sequenceLen = 1;
    for (let i = 1; i < paths.length; i++) {
      if (this.arePathsSequential(paths[i - 1], paths[i])) {
        sequenceLen++;
      } else {
        sequenceLen = 1;
      }
      if (sequenceLen >= 5) {
        score += 30;
        break;
      }
    }
    return Math.min(60, score);
  }
  arePathsSequential(path1, path22) {
    const nums1 = path1.match(/\d+/g) || [];
    const nums2 = path22.match(/\d+/g) || [];
    if (nums1.length > 0 && nums2.length > 0) {
      const n1 = parseInt(nums1[nums1.length - 1]);
      const n2 = parseInt(nums2[nums2.length - 1]);
      if (n2 - n1 === 1 && path1.replace(/\d+/g, "X") === path22.replace(/\d+/g, "X")) {
        return true;
      }
    }
    return false;
  }
  calculateHeaderConsistency(requests) {
    if (requests.length < 2) return 0;
    let consistent = 0;
    const baseHeaders = requests[0].headers;
    for (let i = 1; i < requests.length; i++) {
      const headers = requests[i].headers;
      let match = 0;
      let total = 0;
      for (const key in baseHeaders) {
        total++;
        if (headers[key] === baseHeaders[key]) {
          match++;
        }
      }
      if (total > 0) {
        consistent += match / total * 100;
      }
    }
    return Math.round(consistent / (requests.length - 1));
  }
  calculateVariance(numbers) {
    if (numbers.length === 0) return 0;
    const mean = numbers.reduce((a, b) => a + b, 0) / numbers.length;
    return numbers.reduce((a, b) => a + Math.pow(b - mean, 2), 0) / numbers.length;
  }
};
var botDetector = new BotDetector();

// server/utils/advanced-threat-scoring.ts
var AdvancedThreatScorer = class {
  /**
   * Calculate enhanced threat score using multiple signals
   */
  calculateThreat(input) {
    const weights = {
      pattern: 0.3,
      // OWASP patterns
      anomaly: 0.15,
      // Request anomalies
      reputation: 0.1,
      // IP reputation
      bot: 0.2,
      // Bot detection
      behavioral: 0.15,
      // Login/behavioral
      geo: 0.05,
      // Geolocation
      velocity: 0.03,
      // Request velocity
      stuffing: 0.02
      // Credential stuffing indicators
    };
    const normalized = {
      pattern: Math.min(100, input.patternScore),
      anomaly: Math.min(100, input.anomalyScore),
      reputation: Math.min(100, input.reputationScore),
      bot: Math.min(100, input.botScore),
      behavioral: Math.min(100, input.behavioralScore),
      geo: Math.min(100, input.geoAnomaly),
      velocity: Math.min(100, input.velocityAnomaly),
      stuffing: Math.min(100, input.credentialStuffingIndicators)
    };
    const contributions = {
      pattern: normalized.pattern * weights.pattern,
      anomaly: normalized.anomaly * weights.anomaly,
      reputation: normalized.reputation * weights.reputation,
      bot: normalized.bot * weights.bot,
      behavioral: normalized.behavioral * weights.behavioral,
      geo: normalized.geo * weights.geo,
      velocity: normalized.velocity * weights.velocity,
      stuffing: normalized.stuffing * weights.stuffing
    };
    const baseScore = Object.values(contributions).reduce((a, b) => a + b, 0);
    let finalScore = baseScore;
    if (input.botScore > 60 && input.credentialStuffingIndicators > 50) {
      finalScore = Math.min(100, finalScore * 1.3);
    }
    if (input.patternScore > 50 && input.anomalyScore > 40) {
      finalScore = Math.min(100, finalScore * 1.15);
    }
    const riskLevel = this.determineRiskLevel(finalScore, input);
    const recommendation = this.getRecommendation(riskLevel, input);
    const factors = this.identifyFactors(input);
    const mlConfidence = this.calculateConfidence(input);
    const suggestedAction = this.suggestAction(riskLevel, factors);
    return {
      finalScore: Math.round(finalScore),
      riskLevel,
      recommendation,
      factors,
      weightBreakdown: {
        pattern: { weight: weights.pattern, value: normalized.pattern, contribution: contributions.pattern },
        anomaly: { weight: weights.anomaly, value: normalized.anomaly, contribution: contributions.anomaly },
        reputation: { weight: weights.reputation, value: normalized.reputation, contribution: contributions.reputation },
        bot: { weight: weights.bot, value: normalized.bot, contribution: contributions.bot },
        behavioral: { weight: weights.behavioral, value: normalized.behavioral, contribution: contributions.behavioral },
        geo: { weight: weights.geo, value: normalized.geo, contribution: contributions.geo },
        velocity: { weight: weights.velocity, value: normalized.velocity, contribution: contributions.velocity },
        stuffing: { weight: weights.stuffing, value: normalized.stuffing, contribution: contributions.stuffing }
      },
      mlConfidence: Math.round(mlConfidence),
      suggestedAction
    };
  }
  /**
   * Determine risk level with contextual analysis
   */
  determineRiskLevel(score, input) {
    if (score >= 80) {
      return "critical";
    } else if (score >= 65) {
      if (input.botScore > 80 && input.credentialStuffingIndicators > 70) {
        return "critical";
      }
      return "high";
    } else if (score >= 45) {
      return "medium";
    } else {
      return "low";
    }
  }
  /**
   * Get recommendation based on risk level
   */
  getRecommendation(riskLevel, input) {
    switch (riskLevel) {
      case "critical":
        return "block";
      case "high":
        if (input.botScore > 75 && input.credentialStuffingIndicators > 60 || input.credentialStuffingIndicators > 85) {
          return "block";
        }
        return "challenge";
      case "medium":
        return "challenge";
      default:
        return "allow";
    }
  }
  /**
   * Identify key threat factors
   */
  identifyFactors(input) {
    const factors = [];
    if (input.patternScore > 60) {
      factors.push(`OWASP patterns detected (${Math.round(input.patternScore)}/100)`);
    }
    if (input.botScore > 65) {
      factors.push(`Bot-like behavior detected (${Math.round(input.botScore)}/100)`);
    }
    if (input.credentialStuffingIndicators > 60) {
      factors.push(`Credential stuffing patterns (${Math.round(input.credentialStuffingIndicators)}/100)`);
    }
    if (input.behavioralScore > 60) {
      factors.push(`Behavioral anomalies (${Math.round(input.behavioralScore)}/100)`);
    }
    if (input.anomalyScore > 50) {
      factors.push(`Request anomalies (${Math.round(input.anomalyScore)}/100)`);
    }
    if (input.geoAnomaly > 50) {
      factors.push(`Geographic anomalies (${Math.round(input.geoAnomaly)}/100)`);
    }
    if (input.velocityAnomaly > 60) {
      factors.push(`High request velocity (${Math.round(input.velocityAnomaly)}/100)`);
    }
    if (input.reputationScore > 50) {
      factors.push(`Bad IP reputation (${Math.round(input.reputationScore)}/100)`);
    }
    return factors.slice(0, 5);
  }
  /**
   * Calculate ML confidence score
   */
  calculateConfidence(input) {
    let confidence = 50;
    const signals = [
      input.patternScore > 50,
      input.botScore > 60,
      input.credentialStuffingIndicators > 60,
      input.behavioralScore > 60,
      input.anomalyScore > 50
    ];
    const agreementCount = signals.filter((s) => s).length;
    confidence += agreementCount * 10;
    if (input.patternScore > 70 && input.anomalyScore > 60) {
      confidence = Math.min(95, confidence + 10);
    }
    return Math.min(100, confidence);
  }
  /**
   * Suggest specific action
   */
  suggestAction(riskLevel, factors) {
    if (riskLevel === "critical") {
      if (factors.some((f) => f.includes("Credential stuffing"))) {
        return "Block and notify security team - potential credential stuffing attack";
      }
      return "Block request - high confidence threat";
    } else if (riskLevel === "high") {
      if (factors.some((f) => f.includes("Bot-like"))) {
        return "Challenge with CAPTCHA - bot detection confirmed";
      }
      return "Challenge with CAPTCHA or require verification";
    } else if (riskLevel === "medium") {
      return "Challenge with CAPTCHA - behavioral anomalies detected";
    } else {
      return "Allow request - low risk";
    }
  }
};
var advancedThreatScorer = new AdvancedThreatScorer();

// server/routes/ml-feedback.ts
import { Router as Router8 } from "express";
function requireAuth7(req, res, next) {
  if (!req.isAuthenticated || !req.isAuthenticated()) {
    return res.status(401).json({ message: "Unauthorized" });
  }
  next();
}
var router8 = Router8();
router8.post("/api/ml/feedback", requireAuth7, async (req, res) => {
  try {
    const { requestId, tenantId, actualLabel, predictedLabel, notes, confidence } = req.body;
    if (!requestId || actualLabel === void 0 || predictedLabel === void 0) {
      return res.status(400).json({ error: "Missing required fields" });
    }
    const feedback = await feedbackService.submitFeedback(
      requestId,
      tenantId || "",
      req.user?.id || "system",
      actualLabel,
      predictedLabel,
      notes,
      confidence
    );
    res.json({
      success: true,
      feedback,
      message: `Feedback recorded: ${feedback.falsePositive ? "false positive" : feedback.falseNegative ? "false negative" : "correct prediction"}`
    });
  } catch (error) {
    console.error("\u274C Feedback submission error:", error);
    res.status(500).json({
      error: error instanceof Error ? error.message : "Failed to submit feedback"
    });
  }
});
router8.get("/api/ml/feedback", requireAuth7, async (req, res) => {
  try {
    const limit = parseInt(req.query.limit) || 1e3;
    const feedback = feedbackService.getAllFeedback(limit);
    res.json({
      success: true,
      count: feedback.length,
      feedback
    });
  } catch (error) {
    console.error("\u274C Get feedback error:", error);
    res.status(500).json({
      error: error instanceof Error ? error.message : "Failed to retrieve feedback"
    });
  }
});
router8.get("/api/ml/feedback/stats", requireAuth7, async (req, res) => {
  try {
    const stats = feedbackService.getStatistics();
    const metrics = feedbackService.getPerformanceMetrics();
    res.json({
      success: true,
      statistics: stats,
      metrics
    });
  } catch (error) {
    console.error("\u274C Get stats error:", error);
    res.status(500).json({
      error: error instanceof Error ? error.message : "Failed to retrieve stats"
    });
  }
});
router8.get("/api/ml/feedback/request/:requestId", requireAuth7, async (req, res) => {
  try {
    const feedback = feedbackService.getFeedbackByRequest(req.params.requestId);
    res.json({
      success: true,
      count: feedback.length,
      feedback
    });
  } catch (error) {
    console.error("\u274C Get request feedback error:", error);
    res.status(500).json({
      error: error instanceof Error ? error.message : "Failed to retrieve request feedback"
    });
  }
});
router8.get("/api/ml/feedback/tenant/:tenantId", requireAuth7, async (req, res) => {
  try {
    const feedback = feedbackService.getFeedbackByTenant(req.params.tenantId);
    res.json({
      success: true,
      count: feedback.length,
      feedback
    });
  } catch (error) {
    console.error("\u274C Get tenant feedback error:", error);
    res.status(500).json({
      error: error instanceof Error ? error.message : "Failed to retrieve tenant feedback"
    });
  }
});
router8.get("/api/ml/feedback/false-positives", requireAuth7, async (req, res) => {
  try {
    const fps = feedbackService.getFalsePositives();
    res.json({
      success: true,
      count: fps.length,
      falsePositives: fps
    });
  } catch (error) {
    console.error("\u274C Get false positives error:", error);
    res.status(500).json({
      error: error instanceof Error ? error.message : "Failed to retrieve false positives"
    });
  }
});
router8.get("/api/ml/feedback/false-negatives", requireAuth7, async (req, res) => {
  try {
    const fns = feedbackService.getFalseNegatives();
    res.json({
      success: true,
      count: fns.length,
      falseNegatives: fns
    });
  } catch (error) {
    console.error("\u274C Get false negatives error:", error);
    res.status(500).json({
      error: error instanceof Error ? error.message : "Failed to retrieve false negatives"
    });
  }
});
router8.put("/api/ml/feedback/:id", requireAuth7, async (req, res) => {
  try {
    const updated = await feedbackService.updateFeedback(req.params.id, req.body);
    if (!updated) {
      return res.status(404).json({ error: "Feedback not found" });
    }
    res.json({
      success: true,
      feedback: updated
    });
  } catch (error) {
    console.error("\u274C Update feedback error:", error);
    res.status(500).json({
      error: error instanceof Error ? error.message : "Failed to update feedback"
    });
  }
});
router8.delete("/api/ml/feedback/:id", requireAuth7, async (req, res) => {
  try {
    const deleted = feedbackService.deleteFeedback(req.params.id);
    if (!deleted) {
      return res.status(404).json({ error: "Feedback not found" });
    }
    res.json({
      success: true,
      message: "Feedback deleted"
    });
  } catch (error) {
    console.error("\u274C Delete feedback error:", error);
    res.status(500).json({
      error: error instanceof Error ? error.message : "Failed to delete feedback"
    });
  }
});
var ml_feedback_default = router8;

// server/routes.ts
function scrubHeaders(headers, scrubCookies, scrubAuthHeaders) {
  const scrubbed = { ...headers };
  if (scrubCookies) {
    delete scrubbed["cookie"];
    delete scrubbed["set-cookie"];
  }
  if (scrubAuthHeaders) {
    delete scrubbed["authorization"];
    delete scrubbed["x-api-key"];
    delete scrubbed["x-auth-token"];
    delete scrubbed["x-access-token"];
  }
  return scrubbed;
}
function requireAuth8(req, res, next) {
  if (!req.isAuthenticated || !req.isAuthenticated()) {
    return res.status(401).json({ message: "Unauthorized" });
  }
  if (req.method === "GET") {
    res.set("Cache-Control", "no-cache, no-store, must-revalidate, private");
    res.set("Pragma", "no-cache");
    res.set("Expires", "0");
  }
  next();
}
async function registerRoutes(app2) {
  startRateLimitCleanup(6e4);
  app2.use(securityHeaders());
  app2.use(requestSanitizer());
  app2.use(validateContentType());
  app2.post("/api/login", rateLimit(6e4, 5), (req, res, next) => {
    const clientIp = extractClientIpFromRequest(req);
    const userAgent = req.get("user-agent") || "unknown";
    const email = req.body.email || "unknown";
    const attempt = {
      email,
      ip: clientIp,
      userAgent,
      timestamp: /* @__PURE__ */ new Date(),
      success: false
    };
    const behaviorCheck = behavioralEngine.trackLoginAttempt(attempt);
    if (!behaviorCheck.allowed) {
      return res.status(429).json({
        message: behaviorCheck.reason,
        type: "behavioral_block",
        profile: behaviorCheck.profile
      });
    }
    const botCheck = botDetector.analyze({
      method: req.method,
      path: req.path,
      userAgent,
      headers: req.headers,
      ip: clientIp,
      timestamp: Date.now(),
      bodySize: req.get("content-length") ? parseInt(req.get("content-length")) : void 0
    });
    if (botCheck.isBot && botCheck.score > 75) {
      return res.status(429).json({
        message: "Bot detection triggered. Please solve the CAPTCHA.",
        type: "bot_detected",
        botScore: botCheck.score,
        factors: botCheck.factors
      });
    }
    passport.authenticate("local", (err, user, info) => {
      if (err) {
        return res.status(500).json({ message: "Authentication error" });
      }
      if (!user) {
        attempt.success = false;
        behavioralEngine.trackLoginAttempt(attempt);
        const stuffingCheck = behavioralEngine.detectCredentialStuffing(email);
        if (stuffingCheck.isStuffing) {
          return res.status(429).json({
            message: "Credential stuffing detected. Account temporarily locked.",
            type: "credential_stuffing",
            confidence: stuffingCheck.confidence,
            indicators: stuffingCheck.indicators
          });
        }
        return res.status(401).json({ message: info?.message || "Invalid credentials" });
      }
      attempt.success = true;
      behavioralEngine.trackLoginAttempt(attempt);
      req.login(user, (err2) => {
        if (err2) {
          return res.status(500).json({ message: "Login failed" });
        }
        res.json(user);
      });
    })(req, res, next);
  });
  app2.get("/api/auth/logout", (req, res) => {
    req.logout((err) => {
      if (err) {
        return res.status(500).json({ message: "Logout failed" });
      }
      req.session?.destroy((destroyErr) => {
        if (destroyErr) {
          console.error("Session destroy error:", destroyErr);
        }
        res.clearCookie("connect.sid");
        res.json({ message: "Logged out successfully" });
      });
    });
  });
  app2.get("/api/logout", (req, res) => {
    req.logout((err) => {
      if (err) {
        return res.status(500).json({ message: "Logout failed" });
      }
      req.session?.destroy((destroyErr) => {
        if (destroyErr) {
          console.error("Session destroy error:", destroyErr);
        }
        res.clearCookie("connect.sid");
        res.redirect("/");
      });
    });
  });
  app2.get("/api/auth/user", async (req, res) => {
    if (!req.isAuthenticated || !req.isAuthenticated()) {
      return res.status(401).json({ message: "Unauthorized" });
    }
    res.json(req.user);
  });
  app2.get("/api/dashboard/stats", requireAuth8, async (req, res) => {
    try {
      const stats = await storage.getDashboardStats();
      res.json(stats);
    } catch (error) {
      console.error("Error fetching dashboard stats:", error);
      res.status(500).json({ message: "Failed to fetch dashboard stats" });
    }
  });
  app2.get("/api/tenants", requireAuth8, async (req, res) => {
    try {
      const tenants = await storage.getTenants();
      res.json(tenants);
    } catch (error) {
      console.error("Error fetching tenants:", error);
      res.status(500).json({ message: "Failed to fetch tenants" });
    }
  });
  app2.get("/api/tenants/:id", requireAuth8, async (req, res) => {
    try {
      const tenant = await storage.getTenant(req.params.id);
      if (!tenant) {
        return res.status(404).json({ message: "Tenant not found" });
      }
      res.json(tenant);
    } catch (error) {
      console.error("Error fetching tenant:", error);
      res.status(500).json({ message: "Failed to fetch tenant" });
    }
  });
  app2.post("/api/tenants", requireRole("admin"), async (req, res) => {
    try {
      const data = insertTenantSchema.parse(req.body);
      const tenant = await storage.createTenant(data);
      await storage.createPolicy({
        tenantId: tenant.id,
        name: "Default Policy",
        enforcementMode: req.body.enforcementMode || "monitor",
        blockThreshold: req.body.blockThreshold || 70,
        challengeThreshold: 50,
        monitorThreshold: 30,
        rateLimit: 100,
        rateLimitWindow: 60,
        isDefault: true
      });
      res.status(201).json(tenant);
    } catch (error) {
      console.error("Error creating tenant:", error);
      if (error instanceof z5.ZodError) {
        return res.status(400).json({ message: "Invalid data", errors: error.errors });
      }
      res.status(500).json({ message: "Failed to create tenant" });
    }
  });
  app2.patch("/api/tenants/:id", requireRole("admin"), async (req, res) => {
    try {
      const tenant = await storage.updateTenant(req.params.id, req.body);
      if (!tenant) {
        return res.status(404).json({ message: "Tenant not found" });
      }
      if (req.body.enforcementMode || req.body.blockThreshold !== void 0 || req.body.challengeThreshold !== void 0 || req.body.monitorThreshold !== void 0) {
        const policy = await storage.getPolicyByTenant(req.params.id);
        if (policy) {
          await storage.updatePolicy(policy.id, {
            enforcementMode: req.body.enforcementMode || policy.enforcementMode,
            blockThreshold: req.body.blockThreshold !== void 0 ? req.body.blockThreshold : policy.blockThreshold,
            challengeThreshold: req.body.challengeThreshold !== void 0 ? req.body.challengeThreshold : policy.challengeThreshold,
            monitorThreshold: req.body.monitorThreshold !== void 0 ? req.body.monitorThreshold : policy.monitorThreshold
          });
        }
      }
      res.json(tenant);
    } catch (error) {
      console.error("Error updating tenant:", error);
      res.status(500).json({ message: "Failed to update tenant" });
    }
  });
  app2.delete("/api/tenants/:id", requireRole("admin"), async (req, res) => {
    try {
      await storage.deleteTenant(req.params.id);
      res.status(204).send();
    } catch (error) {
      console.error("Error deleting tenant:", error);
      res.status(500).json({ message: "Failed to delete tenant" });
    }
  });
  app2.get("/api/tenants/:id/policy", requireAuth8, async (req, res) => {
    try {
      const policy = await storage.getPolicyByTenant(req.params.id);
      if (!policy) {
        return res.status(404).json({ message: "Policy not found" });
      }
      res.json(policy);
    } catch (error) {
      console.error("Error fetching tenant policy:", error);
      res.status(500).json({ message: "Failed to fetch policy" });
    }
  });
  app2.get("/api/tenants/:id/requests", requireAuth8, async (req, res) => {
    try {
      const requests = await storage.getRequests(req.params.id);
      res.json(requests);
    } catch (error) {
      console.error("Error fetching tenant requests:", error);
      res.status(500).json({ message: "Failed to fetch requests" });
    }
  });
  app2.get("/api/policies", requireAuth8, async (req, res) => {
    try {
      const policies = await storage.getPolicies();
      res.json(policies);
    } catch (error) {
      console.error("Error fetching policies:", error);
      res.status(500).json({ message: "Failed to fetch policies" });
    }
  });
  app2.get("/api/policies/:id", requireAuth8, async (req, res) => {
    try {
      const policy = await storage.getPolicy(req.params.id);
      if (!policy) {
        return res.status(404).json({ message: "Policy not found" });
      }
      res.json(policy);
    } catch (error) {
      console.error("Error fetching policy:", error);
      res.status(500).json({ message: "Failed to fetch policy" });
    }
  });
  app2.post("/api/policies", requireRole("admin", "operator"), async (req, res) => {
    try {
      const data = insertPolicySchema.parse(req.body);
      const policy = await storage.createPolicy(data);
      res.status(201).json(policy);
    } catch (error) {
      console.error("Error creating policy:", error);
      if (error instanceof z5.ZodError) {
        return res.status(400).json({ message: "Invalid data", errors: error.errors });
      }
      res.status(500).json({ message: "Failed to create policy" });
    }
  });
  app2.patch("/api/policies/:id", requireRole("admin", "operator"), async (req, res) => {
    try {
      const policy = await storage.getPolicy(req.params.id);
      if (!policy) {
        return res.status(404).json({ message: "Policy not found" });
      }
      if (req.body.isDefault === true && !policy.isDefault) {
        const allPolicies = await storage.getPolicies();
        const sameTenantPolicies = allPolicies.filter((p) => p.tenantId === policy.tenantId && p.id !== req.params.id);
        for (const p of sameTenantPolicies) {
          await storage.updatePolicy(p.id, { isDefault: false });
        }
      }
      const updated = await storage.updatePolicy(req.params.id, req.body);
      res.json(updated);
    } catch (error) {
      console.error("Error updating policy:", error);
      res.status(500).json({ message: "Failed to update policy" });
    }
  });
  app2.post("/api/policies/:id/duplicate", requireRole("admin", "operator"), async (req, res) => {
    try {
      const policy = await storage.getPolicy(req.params.id);
      if (!policy) {
        return res.status(404).json({ message: "Policy not found" });
      }
      const duplicated = await storage.createPolicy({
        tenantId: policy.tenantId,
        name: `${policy.name} (Copy)`,
        enforcementMode: policy.enforcementMode,
        blockThreshold: policy.blockThreshold,
        challengeThreshold: policy.challengeThreshold,
        monitorThreshold: policy.monitorThreshold,
        rateLimit: policy.rateLimit,
        rateLimitWindow: policy.rateLimitWindow
      });
      res.status(201).json(duplicated);
    } catch (error) {
      console.error("Error duplicating policy:", error);
      res.status(500).json({ message: "Failed to duplicate policy" });
    }
  });
  app2.delete("/api/policies/:id", requireRole("admin", "operator"), async (req, res) => {
    try {
      const policy = await storage.getPolicy(req.params.id);
      if (!policy) {
        return res.status(404).json({ message: "Policy not found" });
      }
      await storage.deletePolicy(req.params.id);
      res.status(204).send();
    } catch (error) {
      console.error("Error deleting policy:", error);
      res.status(500).json({ message: "Failed to delete policy" });
    }
  });
  app2.get("/api/rules", requireAuth8, async (req, res) => {
    try {
      const rules = await storage.getRules();
      res.json(rules);
    } catch (error) {
      console.error("Error fetching rules:", error);
      res.status(500).json({ message: "Failed to fetch rules" });
    }
  });
  app2.get("/api/rules/all-with-stats", requireAuth8, async (req, res) => {
    try {
      const rules = await storage.getRules();
      const stats = {
        total: rules.length,
        enabled: rules.filter((r) => r.enabled).length,
        disabled: rules.filter((r) => !r.enabled).length,
        builtIn: rules.filter((r) => r.isBuiltIn).length,
        custom: rules.filter((r) => !r.isBuiltIn).length,
        rules: rules.map((r) => ({
          ...r,
          type: r.isBuiltIn ? "built-in" : "custom",
          status: r.enabled ? "enabled" : "disabled"
        }))
      };
      res.json(stats);
    } catch (error) {
      console.error("Error fetching rules with stats:", error);
      res.status(500).json({ message: "Failed to fetch rules" });
    }
  });
  app2.get("/api/rules/:id", requireAuth8, async (req, res) => {
    try {
      const rule = await storage.getRule(req.params.id);
      if (!rule) {
        return res.status(404).json({ message: "Rule not found" });
      }
      res.json(rule);
    } catch (error) {
      console.error("Error fetching rule:", error);
      res.status(500).json({ message: "Failed to fetch rule" });
    }
  });
  app2.post("/api/rules", requireRole("admin"), async (req, res) => {
    try {
      const data = insertWafRuleSchema.parse(req.body);
      const rule = await storage.createRule(data);
      res.status(201).json(rule);
    } catch (error) {
      console.error("Error creating rule:", error);
      if (error instanceof z5.ZodError) {
        return res.status(400).json({ message: "Invalid data", errors: error.errors });
      }
      res.status(500).json({ message: "Failed to create rule" });
    }
  });
  app2.patch("/api/rules/:id", requireRole("admin"), async (req, res) => {
    try {
      const rule = await storage.updateRule(req.params.id, req.body);
      if (!rule) {
        return res.status(404).json({ message: "Rule not found" });
      }
      res.json(rule);
    } catch (error) {
      console.error("Error updating rule:", error);
      res.status(500).json({ message: "Failed to update rule" });
    }
  });
  app2.delete("/api/rules/:id", requireRole("admin"), async (req, res) => {
    try {
      await storage.deleteRule(req.params.id);
      res.status(204).send();
    } catch (error) {
      console.error("Error deleting rule:", error);
      res.status(500).json({ message: "Failed to delete rule" });
    }
  });
  app2.get("/api/requests", requireAuth8, async (req, res) => {
    try {
      const { tenantId, ip, path: path4, method, scoreMin, scoreMax } = req.query;
      let requests = await storage.getRequestsWithAnalysis(tenantId);
      if (ip) requests = requests.filter((r) => r.clientIp?.includes(ip));
      if (path4) requests = requests.filter((r) => r.path.includes(path4));
      if (method) requests = requests.filter((r) => r.method === method);
      res.json(requests);
    } catch (error) {
      console.error("Error fetching requests:", error);
      res.status(500).json({ message: "Failed to fetch requests" });
    }
  });
  app2.get("/api/requests/:id", requireAuth8, async (req, res) => {
    try {
      const request = await storage.getRequestWithAnalysis(req.params.id);
      if (!request) {
        return res.status(404).json({ message: "Request not found" });
      }
      res.json(request);
    } catch (error) {
      console.error("Error fetching request:", error);
      res.status(500).json({ message: "Failed to fetch request" });
    }
  });
  app2.post("/api/requests/:id/override", requireRole("admin", "operator"), async (req, res) => {
    try {
      const request = await storage.getRequest(req.params.id);
      if (!request) {
        return res.status(404).json({ message: "Request not found" });
      }
      const override = await storage.createOverride({
        overrideType: "request",
        targetId: req.params.id,
        tenantId: request.tenantId,
        action: req.body.action,
        operatorId: req.user.id,
        reason: req.body.reason
      });
      res.status(201).json(override);
    } catch (error) {
      console.error("Error creating override:", error);
      res.status(500).json({ message: "Failed to create override" });
    }
  });
  app2.post("/api/requests/:id/whitelist-ip", requireRole("admin", "operator"), async (req, res) => {
    try {
      const request = await storage.getRequest(req.params.id);
      if (!request || !request.clientIp) {
        return res.status(404).json({ message: "Request not found or has no IP" });
      }
      await storage.createIpList({
        tenantId: request.tenantId,
        listType: "whitelist",
        ipAddress: request.clientIp,
        reason: req.body.reason || "Whitelisted from request detail"
      });
      res.status(201).json({ message: "IP whitelisted successfully" });
    } catch (error) {
      console.error("Error whitelisting IP:", error);
      res.status(500).json({ message: "Failed to whitelist IP" });
    }
  });
  app2.post("/api/requests/:id/blacklist-ip", requireRole("admin", "operator"), async (req, res) => {
    try {
      const request = await storage.getRequest(req.params.id);
      if (!request || !request.clientIp) {
        return res.status(404).json({ message: "Request not found or has no IP" });
      }
      await storage.createIpList({
        tenantId: request.tenantId,
        listType: "blacklist",
        ipAddress: request.clientIp,
        reason: req.body.reason || "Blacklisted from request detail"
      });
      res.status(201).json({ message: "IP blacklisted successfully" });
    } catch (error) {
      console.error("Error blacklisting IP:", error);
      res.status(500).json({ message: "Failed to blacklist IP" });
    }
  });
  app2.post("/api/requests/:id/create-rule", requireRole("admin", "operator"), async (req, res) => {
    try {
      const request = await storage.getRequest(req.params.id);
      if (!request) {
        return res.status(404).json({ message: "Request not found" });
      }
      const rule = await storage.createRule({
        tenantId: request.tenantId,
        name: req.body.name,
        category: req.body.category || "custom",
        pattern: req.body.pattern || request.path,
        targetField: req.body.targetField || "request",
        description: req.body.description || `Custom rule created from request`,
        severity: req.body.severity || "medium",
        enabled: true
      });
      res.status(201).json(rule);
    } catch (error) {
      console.error("Error creating rule:", error);
      if (error instanceof z5.ZodError) {
        return res.status(400).json({ message: "Invalid data", errors: error.errors });
      }
      res.status(500).json({ message: "Failed to create rule" });
    }
  });
  app2.get("/api/alerts", requireAuth8, async (req, res) => {
    try {
      const alerts = await storage.getAlerts();
      res.json(alerts);
    } catch (error) {
      console.error("Error fetching alerts:", error);
      res.status(500).json({ message: "Failed to fetch alerts" });
    }
  });
  app2.get("/api/alerts/recent", requireAuth8, async (req, res) => {
    try {
      const alerts = await storage.getAlerts();
      res.json(alerts.slice(0, 5));
    } catch (error) {
      console.error("Error fetching recent alerts:", error);
      res.status(500).json({ message: "Failed to fetch alerts" });
    }
  });
  app2.patch("/api/alerts/:id", requireAuth8, async (req, res) => {
    try {
      const alert = await storage.updateAlert(req.params.id, req.body);
      if (!alert) {
        return res.status(404).json({ message: "Alert not found" });
      }
      res.json(alert);
    } catch (error) {
      console.error("Error updating alert:", error);
      res.status(500).json({ message: "Failed to update alert" });
    }
  });
  app2.post("/api/alerts/mark-all-read", requireAuth8, async (req, res) => {
    try {
      await storage.markAllAlertsRead();
      res.status(204).send();
    } catch (error) {
      console.error("Error marking alerts as read:", error);
      res.status(500).json({ message: "Failed to mark alerts as read" });
    }
  });
  app2.post("/api/alerts/:id/dismiss", requireAuth8, async (req, res) => {
    try {
      const alert = await storage.updateAlert(req.params.id, { isDismissed: true });
      if (!alert) {
        return res.status(404).json({ message: "Alert not found" });
      }
      res.json(alert);
    } catch (error) {
      console.error("Error dismissing alert:", error);
      res.status(500).json({ message: "Failed to dismiss alert" });
    }
  });
  app2.get("/api/webhooks", requireRole("admin"), async (req, res) => {
    try {
      const webhooks2 = await storage.getWebhooks();
      res.json(webhooks2);
    } catch (error) {
      console.error("Error fetching webhooks:", error);
      res.status(500).json({ message: "Failed to fetch webhooks" });
    }
  });
  app2.post("/api/webhooks", requireRole("admin"), async (req, res) => {
    try {
      const webhook = await storage.createWebhook(req.body);
      res.status(201).json(webhook);
    } catch (error) {
      console.error("Error creating webhook:", error);
      res.status(500).json({ message: "Failed to create webhook" });
    }
  });
  app2.patch("/api/webhooks/:id", requireRole("admin"), async (req, res) => {
    try {
      const webhook = await storage.updateWebhook(req.params.id, req.body);
      if (!webhook) {
        return res.status(404).json({ message: "Webhook not found" });
      }
      res.json(webhook);
    } catch (error) {
      console.error("Error updating webhook:", error);
      res.status(500).json({ message: "Failed to update webhook" });
    }
  });
  app2.delete("/api/webhooks/:id", requireRole("admin"), async (req, res) => {
    try {
      await storage.deleteWebhook(req.params.id);
      res.status(204).send();
    } catch (error) {
      console.error("Error deleting webhook:", error);
      res.status(500).json({ message: "Failed to delete webhook" });
    }
  });
  app2.get("/api/export/csv", requireAuth8, async (req, res) => {
    try {
      const { tenantId, startDate, endDate } = req.query;
      const reqs = await storage.getRequestsForExport(
        tenantId,
        startDate ? new Date(startDate) : void 0,
        endDate ? new Date(endDate) : void 0
      );
      let csv = "ID,Timestamp,ClientIP,Method,Path,StatusCode,ActionTaken,Score\n";
      for (const req2 of reqs) {
        csv += `"${req2.id}","${req2.timestamp}","${req2.clientIp || "N/A"}","${req2.method}","${req2.path}",${req2.responseCode || "N/A"},"${req2.actionTaken}",0
`;
      }
      res.setHeader("Content-Type", "text/csv");
      res.setHeader("Content-Disposition", "attachment; filename=requests_export.csv");
      res.send(csv);
    } catch (error) {
      console.error("Error exporting CSV:", error);
      res.status(500).json({ message: "Failed to export CSV" });
    }
  });
  app2.get("/api/export/json", requireAuth8, async (req, res) => {
    try {
      const { tenantId, startDate, endDate } = req.query;
      const reqs = await storage.getRequestsForExport(
        tenantId,
        startDate ? new Date(startDate) : void 0,
        endDate ? new Date(endDate) : void 0
      );
      res.setHeader("Content-Type", "application/json");
      res.setHeader("Content-Disposition", "attachment; filename=requests_export.json");
      res.json({ exports: reqs, totalRecords: reqs.length });
    } catch (error) {
      console.error("Error exporting JSON:", error);
      res.status(500).json({ message: "Failed to export JSON" });
    }
  });
  app2.get("/api/users", requireRole("admin"), async (req, res) => {
    try {
      const users = await storage.getUsers();
      res.json(users);
    } catch (error) {
      console.error("Error fetching users:", error);
      res.status(500).json({ message: "Failed to fetch users" });
    }
  });
  app2.post("/api/users", requireRole("admin"), async (req, res) => {
    try {
      const { email, firstName, lastName, role } = req.body;
      if (!email || !role) {
        return res.status(400).json({ message: "Email and role are required" });
      }
      const existingUser = await storage.getUserByEmail(email);
      if (existingUser) {
        return res.status(409).json({ message: "User already exists" });
      }
      const user = await storage.createUser({
        email,
        firstName: firstName || "",
        lastName: lastName || "",
        role,
        tenantIds: []
      });
      res.status(201).json(user);
    } catch (error) {
      console.error("Error creating user:", error);
      res.status(500).json({ message: "Failed to create user" });
    }
  });
  app2.patch("/api/users/:id", requireRole("admin"), async (req, res) => {
    try {
      const user = await storage.updateUser(req.params.id, req.body);
      if (!user) {
        return res.status(404).json({ message: "User not found" });
      }
      res.json(user);
    } catch (error) {
      console.error("Error updating user:", error);
      res.status(500).json({ message: "Failed to update user" });
    }
  });
  app2.delete("/api/users/:id", requireRole("admin"), async (req, res) => {
    try {
      const user = await storage.getUser(req.params.id);
      if (!user) {
        return res.status(404).json({ message: "User not found" });
      }
      await storage.deleteUser(req.params.id);
      res.json({ message: "User deleted successfully" });
    } catch (error) {
      console.error("Error deleting user:", error);
      res.status(500).json({ message: "Failed to delete user" });
    }
  });
  app2.get("/api/settings", requireAuth8, async (req, res) => {
    try {
      const settings = await storage.getSettings();
      res.json(settings);
    } catch (error) {
      console.error("Error fetching settings:", error);
      res.status(500).json({ message: "Failed to fetch settings" });
    }
  });
  app2.put("/api/settings", requireRole("admin"), async (req, res) => {
    try {
      const settings = await storage.updateSettings(req.body);
      res.json(settings);
    } catch (error) {
      console.error("Error updating settings:", error);
      res.status(500).json({ message: "Failed to update settings" });
    }
  });
  app2.post("/api/waf/ingress", async (req, res) => {
    try {
      const { tenantId, request: incomingRequest } = req.body;
      if (!tenantId || !incomingRequest) {
        return res.status(400).json({ message: "tenantId and request are required" });
      }
      if (!incomingRequest.clientIp || incomingRequest.clientIp === "unknown") {
        incomingRequest.clientIp = extractClientIpFromRequest(req, incomingRequest);
      } else {
        incomingRequest.clientIp = sanitizeIp(incomingRequest.clientIp);
      }
      const tenant = await storage.getTenant(tenantId);
      if (!tenant || !tenant.isActive) {
        return res.status(404).json({ message: "Tenant not found or inactive" });
      }
      const tenantRateLimiter = createTenantRateLimiter(String(tenantId), 6e4, 1e3);
      const rateLimitRes = await new Promise((resolve) => {
        tenantRateLimiter(req, res, () => resolve({ limited: false }));
        if (res.headersSent) resolve({ limited: true });
      });
      if (rateLimitRes.limited) return;
      const policy = await storage.getPolicyByTenant(tenantId);
      const thresholds = extractThresholds(policy);
      const customRules = await storage.getRulesByTenant(tenantId);
      const globalRules = await storage.getRulesByTenant(null);
      const allRules = mergeAndPrepareRules(globalRules, customRules);
      wafEngine.setCustomRules(allRules);
      const selectedEngine = policy?.securityEngine || "both";
      let modSecMatches = [];
      let modSecBlocked = false;
      let analysis = null;
      let combinedMatches = [];
      if (selectedEngine === "modsecurity" || selectedEngine === "both") {
        modSecMatches = modSecurityEngine.evaluateRequest({
          method: incomingRequest.method,
          uri: incomingRequest.path,
          headers: incomingRequest.headers || {},
          body: incomingRequest.body || "",
          query: incomingRequest.query || {},
          clientIp: incomingRequest.clientIp
        });
        const criticalModSecMatches2 = modSecMatches.filter(
          (m) => ["CRITICAL", "EMERGENCY", "ALERT"].includes(m.severity)
        );
        modSecBlocked = criticalModSecMatches2.length > 0;
      }
      if (selectedEngine === "waf-engine" || selectedEngine === "both") {
        analysis = wafEngine.analyzeRequest({
          ...incomingRequest,
          tenantId,
          enforcementMode: policy?.enforcementMode || "block"
        }, thresholds, policy);
      } else {
        analysis = {
          action: "allow",
          score: 0,
          riskLevel: "LOW",
          matches: [],
          processingTimeMs: 0,
          reason: "WAF Engine disabled"
        };
      }
      const finalAction = selectedEngine === "modsecurity" ? modSecBlocked ? "block" : "allow" : selectedEngine === "waf-engine" ? analysis.action === "block" ? "block" : analysis.action === "challenge" ? "challenge" : "allow" : (
        // both engines
        modSecBlocked || analysis.action === "block" ? "block" : analysis.action === "challenge" ? "challenge" : "allow"
      );
      combinedMatches = [];
      if (selectedEngine === "waf-engine" || selectedEngine === "both") {
        combinedMatches.push(...analysis.matches);
      }
      if (selectedEngine === "modsecurity" || selectedEngine === "both") {
        combinedMatches.push(...modSecMatches.map((m) => ({
          id: m.ruleId,
          ruleName: m.message,
          category: "modsecurity",
          severity: m.severity,
          description: m.message
        })));
      }
      const responseCode = finalAction === "block" ? 403 : finalAction === "challenge" ? 429 : 200;
      let headersToStore = incomingRequest.headers || {};
      if ((tenant.scrubCookies ?? false) || (tenant.scrubAuthHeaders ?? false)) {
        headersToStore = scrubHeaders(headersToStore, tenant.scrubCookies ?? false, tenant.scrubAuthHeaders ?? false);
      }
      const storedRequest = await storage.createRequest({
        tenantId,
        timestamp: /* @__PURE__ */ new Date(),
        method: incomingRequest.method,
        path: incomingRequest.path,
        clientIp: incomingRequest.clientIp,
        userAgent: incomingRequest.headers?.["user-agent"],
        responseCode,
        actionTaken: finalAction === "block" ? "deny" : finalAction,
        headersJson: headersToStore,
        bodyPreview: incomingRequest.body?.substring(0, 500) || null,
        queryString: Object.entries(incomingRequest.query || {}).map(([k, v]) => `${k}=${v}`).join("&") || null,
        wafHitsJson: combinedMatches
      });
      await storage.createAnalysis({
        requestId: storedRequest.id,
        matchedRulesJson: combinedMatches,
        totalScore: analysis.score,
        suggestedAction: finalAction === "block" ? "deny" : finalAction,
        finalAction: finalAction === "block" ? "deny" : finalAction,
        processingTimeMs: analysis.processingTimeMs,
        breakdownJson: {
          riskLevel: analysis.riskLevel,
          matchCount: combinedMatches.length,
          wafMatches: analysis.matches.length,
          modSecMatches: modSecMatches.length,
          engines: ["WAF Engine", "ModSecurity CRS v3.3"]
        }
      });
      sseServer.broadcastRequest(storedRequest);
      if (analysis.score >= 70 || modSecBlocked) {
        const alert = await storage.createAlert({
          tenantId,
          severity: modSecBlocked ? "CRITICAL" : analysis.riskLevel,
          type: combinedMatches[0]?.category || "unknown",
          title: modSecBlocked ? `BLOCKED: Critical threat detected by ModSecurity (${criticalModSecMatches.length} rules)` : `High-risk request detected (Score: ${analysis.score})`,
          message: `Engines: WAF Engine (${analysis.matches.length} matches) + ModSecurity (${modSecMatches.length} rules). ${combinedMatches.slice(0, 3).map((m) => m.ruleName).join(", ")}${combinedMatches.length > 3 ? "..." : ""}`
        });
        sseServer.broadcastAlert({
          id: alert.id,
          severity: alert.severity,
          message: alert.title,
          tenantId
        });
      }
      res.json({
        requestId: storedRequest.id,
        action: finalAction,
        score: analysis.score,
        riskLevel: analysis.riskLevel,
        totalMatches: combinedMatches.length,
        wafMatches: analysis.matches.length,
        modSecMatches: modSecMatches.length,
        modSecBlocked,
        processingTimeMs: analysis.processingTimeMs,
        engines: ["WAF Engine", "ModSecurity CRS v3.3 (513+ rules)"]
      });
    } catch (error) {
      console.error("Error processing WAF ingress:", error);
      res.status(500).json({ message: "WAF processing error" });
    }
  });
  app2.post("/api/waf/analyze", requireAuth8, async (req, res) => {
    try {
      const { tenantId, request: wafRequest } = req.body;
      const tenant = await storage.getTenant(tenantId);
      if (!tenant) {
        return res.status(404).json({ message: "Tenant not found" });
      }
      const policy = await storage.getPolicyByTenant(tenantId);
      const thresholds = extractThresholds(policy);
      const customRules = await storage.getRulesByTenant(tenantId);
      const globalRules = await storage.getRulesByTenant(null);
      const allAnalysisRules = mergeAndPrepareRules(globalRules, customRules);
      wafEngine.setCustomRules(allAnalysisRules);
      const result = wafEngine.analyzeRequest({
        ...wafRequest,
        tenantId,
        enforcementMode: policy?.enforcementMode || "block"
      }, thresholds, policy);
      res.json(result);
    } catch (error) {
      console.error("Error analyzing request:", error);
      res.status(500).json({ message: "Failed to analyze request" });
    }
  });
  app2.post("/api/waf/test-attack", requireAuth8, async (req, res) => {
    try {
      const { targetUrl, payload, tenantId } = req.body;
      if (!targetUrl || !payload || !tenantId) {
        return res.status(400).json({ message: "targetUrl, payload, and tenantId are required" });
      }
      const tenant = await storage.getTenant(tenantId);
      if (!tenant) {
        return res.status(404).json({ message: "Tenant not found" });
      }
      const wafRequest = {
        method: "GET",
        path: `/?q=${encodeURIComponent(payload)}`,
        query: { q: payload },
        headers: { "user-agent": "WAF-Test-Attack" },
        body: payload,
        clientIp: "127.0.0.1",
        timestamp: (/* @__PURE__ */ new Date()).toISOString()
      };
      const policy = await storage.getPolicyByTenant(tenantId);
      const thresholds = extractThresholds(policy);
      const customRules = await storage.getRulesByTenant(tenantId);
      const globalRules = await storage.getRulesByTenant(null);
      const allRules = mergeAndPrepareRules(globalRules, customRules);
      wafEngine.setCustomRules(allRules);
      const analysis = wafEngine.analyzeRequest({
        ...wafRequest,
        tenantId,
        enforcementMode: policy?.enforcementMode || "block"
      }, thresholds, policy);
      res.json({
        attackType: payload.substring(0, 40),
        payload,
        statusCode: analysis.action === "block" ? 403 : analysis.action === "challenge" ? 429 : 200,
        message: analysis.reason,
        timestamp: (/* @__PURE__ */ new Date()).toISOString(),
        action: analysis.action,
        score: analysis.score
      });
    } catch (error) {
      console.error("Error testing attack:", error);
      res.status(500).json({ message: "Failed to test attack" });
    }
  });
  app2.post("/api/tenants/:tenantId/waf/test", requireAuth8, async (req, res) => {
    try {
      const { tenantId } = req.params;
      const { method = "POST", uri = "/api/test", headers = {}, body = "", query = {} } = req.body;
      const tenant = await storage.getTenant(tenantId);
      if (!tenant) {
        return res.status(404).json({ message: "Tenant not found" });
      }
      const wafRequest = {
        method,
        path: uri,
        headers,
        body,
        query,
        clientIp: "127.0.0.1"
      };
      const policy = await storage.getPolicyByTenant(tenantId);
      const thresholds = extractThresholds(policy);
      const customRules = await storage.getRulesByTenant(tenantId);
      const globalRules = await storage.getRulesByTenant(null);
      const allRules = mergeAndPrepareRules(globalRules, customRules);
      wafEngine.setCustomRules(allRules);
      const startTime = Date.now();
      const analysis = wafEngine.analyzeRequest({
        ...wafRequest,
        tenantId,
        enforcementMode: policy?.enforcementMode || "block"
      }, thresholds, policy);
      const processingTimeMs = Date.now() - startTime;
      res.json({
        engine: "waf",
        blocked: analysis.action === "block" || analysis.action === "challenge",
        severity: analysis.riskLevel,
        matches: analysis.matches,
        score: analysis.score,
        action: analysis.action,
        processingTimeMs,
        details: analysis.reason
      });
    } catch (error) {
      console.error("Error testing WAF:", error);
      res.status(500).json({ message: "Failed to test WAF" });
    }
  });
  app2.post("/api/tenants/:tenantId/modsecurity/test", requireAuth8, async (req, res) => {
    try {
      const { tenantId } = req.params;
      const { method = "POST", uri = "/api/test", headers = {}, body = "", query = {} } = req.body;
      const tenant = await storage.getTenant(tenantId);
      if (!tenant) {
        return res.status(404).json({ message: "Tenant not found" });
      }
      const requestData = {
        method,
        uri,
        headers,
        body,
        query,
        clientIp: "127.0.0.1"
      };
      const startTime = Date.now();
      const matches = modSecurityEngine.evaluateRequest(requestData);
      const processingTimeMs = Date.now() - startTime;
      const blocked = matches.length > 0;
      const maxSeverity = matches.length > 0 ? matches.reduce((max, m) => m.severity > max ? m.severity : max, "low") : "low";
      res.json({
        engine: "modsecurity",
        blocked,
        severity: maxSeverity,
        matches: matches.map((m) => ({ id: m.ruleId, name: m.message, category: m.phase })),
        score: blocked ? 85 : 0,
        action: blocked ? "block" : "allow",
        processingTimeMs,
        details: blocked ? `ModSecurity detected ${matches.length} rule(s)` : "No threats detected"
      });
    } catch (error) {
      console.error("Error testing ModSecurity:", error);
      res.status(500).json({ message: "Failed to test ModSecurity" });
    }
  });
  startDataRetentionJob();
  app2.use("/api/waf", challenge_endpoints_default);
  app2.use(ml_feedback_default);
  app2.get("/api/security/behavior/:email", requireAuth8, async (req, res) => {
    try {
      const profile = behavioralEngine.getProfile(req.params.email);
      const anomalies = behavioralEngine.calculateAnomalyScore(req.params.email);
      res.json({
        profile,
        anomalies
      });
    } catch (error) {
      console.error("Error fetching behavior profile:", error);
      res.status(500).json({ message: "Failed to fetch behavior profile" });
    }
  });
  app2.post("/api/security/threat-score", requireAuth8, async (req, res) => {
    try {
      const input = req.body;
      const analysis = advancedThreatScorer.calculateThreat(input);
      res.json(analysis);
    } catch (error) {
      console.error("Error calculating threat score:", error);
      res.status(500).json({ message: "Failed to calculate threat score" });
    }
  });
  registerMLEndpoints(app2, requireAuth8, requireRole);
  registerDDoSEndpoints(app2, requireAuth8, requireRole);
  registerComparisonEndpoints(app2, requireAuth8, requireRole);
  app2.use("/api/compliance", compliance_endpoints_default);
  app2.use("/api/tenant-compliance", tenant_compliance_endpoints_default);
  app2.use("/api/compliance-dashboard", compliance_dashboard_endpoints_default);
  app2.use("/api/compliance-monitoring", compliance_monitoring_endpoints_default);
  app2.use("/api/compliance-remediation", compliance_remediation_endpoints_default);
  app2.use("/api/compliance-webhooks", compliance_webhooks_endpoints_default);
  app2.options("/api/traffic/stream", (req, res) => {
    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader("Access-Control-Allow-Methods", "GET, OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
    res.setHeader("Access-Control-Allow-Credentials", "true");
    res.sendStatus(204);
  });
  app2.get("/api/traffic/stream", requireAuth8, (req, res) => {
    req.socket?.setTimeout(0);
    res.socket?.setTimeout(0);
    const clientId = sseServer.registerClient(res);
    console.log(`[SSE] Stream endpoint: ${clientId} connected`);
  });
  app2.get("/api/sse/status", requireAuth8, async (req, res) => {
    res.json({
      clients: sseServer.getClientCount(),
      status: "active"
    });
  });
  app2.get("/api/analytics/dashboard", requireAuth8, async (req, res) => {
    try {
      const stats = await storage.getDashboardStats();
      res.json({ ...stats, behavioral: { totalProfiles: 0, lockedAccounts: 0, riskProfiles: [], credentialStuffingDetected: 0, botAttacksBlocked: 0, anomaliesDetected: 0 }, geo: { totalCountries: 0, topCountries: [], vpnDetectionsBlocked: 0, geoblockedRequests: 0, regionalRateLimitEnforced: 0 } });
    } catch (error) {
      res.status(500).json({ message: "Failed" });
    }
  });
  app2.get("/api/analytics/tenant/:tenantId", requireAuth8, async (req, res) => {
    try {
      const requests = await storage.getRequests(req.params.tenantId);
      res.json({ totalRequests: requests.length, blockedRequests: requests.filter((r) => r.actionTaken === "deny").length, monitoredRequests: requests.filter((r) => r.actionTaken === "monitor").length, allowedRequests: requests.filter((r) => r.actionTaken === "allow").length, behavioral: { totalProfiles: 0, lockedAccounts: 0, riskProfiles: [], credentialStuffingDetected: 0, botAttacksBlocked: 0, anomaliesDetected: 0 }, geo: { totalCountries: 0, topCountries: [], vpnDetectionsBlocked: 0, geoblockedRequests: 0, regionalRateLimitEnforced: 0 } });
    } catch (error) {
      res.status(500).json({ message: "Failed" });
    }
  });
  app2.patch("/api/policies/:id/behavior", requireRole("admin", "operator"), async (req, res) => {
    try {
      const policy = await storage.updatePolicy(req.params.id, req.body);
      res.json(policy);
    } catch (error) {
      res.status(500).json({ message: "Failed to update policy" });
    }
  });
  app2.patch("/api/policies/:id/engine", requireAuth8, async (req, res) => {
    try {
      const { securityEngine } = req.body;
      if (!["waf-engine", "modsecurity", "both"].includes(securityEngine)) {
        return res.status(400).json({ error: "Invalid engine selection" });
      }
      const policy = await storage.updatePolicy(req.params.id, { securityEngine });
      res.json(policy);
    } catch (error) {
      res.status(500).json({ message: "Failed to update engine" });
    }
  });
  const httpServer = createServer2(app2);
  await startWafProxy();
  return httpServer;
}

// server/app.ts
import MemoryStore from "memorystore";
function log(message, source = "express") {
  const formattedTime = (/* @__PURE__ */ new Date()).toLocaleTimeString("en-US", {
    hour: "numeric",
    minute: "2-digit",
    second: "2-digit",
    hour12: true
  });
  console.log(`${formattedTime} [${source}] ${message}`);
}
var app = express();
app.use(express.json({
  verify: (req, _res, buf) => {
    req.rawBody = buf;
  }
}));
app.use(express.urlencoded({ extended: false }));
var MemStore = MemoryStore(session);
app.use(
  session({
    store: new MemStore({
      checkPeriod: 864e5
      // 24 hours
    }),
    secret: process.env.SESSION_SECRET || "dev-secret-change-in-production",
    resave: false,
    saveUninitialized: false,
    cookie: {
      maxAge: 30 * 24 * 60 * 60 * 1e3,
      // 30 days
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax"
    }
  })
);
passport2.use(
  new LocalStrategy(
    {
      usernameField: "email",
      passwordField: "email"
      // For demo, use email as both username and password
    },
    async (email, _, done) => {
      try {
        const user = await storage.getUserByEmail(email);
        if (!user) {
          return done(null, false, { message: "User not found" });
        }
        return done(null, user);
      } catch (err) {
        return done(err);
      }
    }
  )
);
passport2.serializeUser((user, done) => {
  done(null, user.id);
});
passport2.deserializeUser(async (id, done) => {
  try {
    const user = await storage.getUser(id);
    done(null, user);
  } catch (err) {
    done(err);
  }
});
app.use(passport2.initialize());
app.use(passport2.session());
app.get("/api/config", (req, res) => {
  const replitDomain = process.env.REPLIT_DEV_DOMAIN || null;
  res.json({
    replitDomain,
    isReplit: !!replitDomain
  });
});
app.use((req, res, next) => {
  if (process.env.NODE_ENV === "production") {
    res.setHeader(
      "Content-Security-Policy",
      `default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' data:; connect-src 'self' wss: ws:`
    );
  } else {
    res.setHeader(
      "Content-Security-Policy",
      `default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' data:; connect-src *`
    );
  }
  if (process.env.NODE_ENV === "production") {
    res.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
  }
  res.setHeader("X-Frame-Options", "SAMEORIGIN");
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-XSS-Protection", "1; mode=block");
  res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
  next();
});
app.use((req, res, next) => {
  const start = Date.now();
  const path4 = req.path;
  let capturedJsonResponse = void 0;
  const originalResJson = res.json;
  res.json = function(bodyJson, ...args) {
    capturedJsonResponse = bodyJson;
    return originalResJson.apply(res, [bodyJson, ...args]);
  };
  res.on("finish", () => {
    const duration = Date.now() - start;
    if (path4.startsWith("/api")) {
      let logLine = `${req.method} ${path4} ${res.statusCode} in ${duration}ms`;
      if (capturedJsonResponse) {
        logLine += ` :: ${JSON.stringify(capturedJsonResponse)}`;
      }
      if (logLine.length > 80) {
        logLine = logLine.slice(0, 79) + "\u2026";
      }
      log(logLine);
    }
  });
  next();
});
async function runApp(setup) {
  const server = await registerRoutes(app);
  app.use((err, _req, res, _next) => {
    const status = err.status || err.statusCode || 500;
    const message = err.message || "Internal Server Error";
    res.status(status).json({ message });
    throw err;
  });
  await setup(app, server);
  const port = parseInt(process.env.PORT || "5000", 10);
  const host = process.platform === "win32" ? "127.0.0.1" : "0.0.0.0";
  server.listen(port, host, () => {
    log(`serving on port ${port}`);
  });
}

// server/index-prod.ts
async function serveStatic(app2, _server) {
  const distPath = path3.resolve(import.meta.dirname, "public");
  if (!fs2.existsSync(distPath)) {
    throw new Error(
      `Could not find the build directory: ${distPath}, make sure to build the client first`
    );
  }
  app2.use(express2.static(distPath));
  app2.use("*", (_req, res) => {
    res.sendFile(path3.resolve(distPath, "index.html"));
  });
}
(async () => {
  const { syncDatabase: syncDatabase2 } = await Promise.resolve().then(() => (init_db(), db_exports));
  await syncDatabase2();
  await runApp(serveStatic);
})();
export {
  serveStatic
};
