// SQL Injection Rules (ModSecurity CRS 942)
export const SQL_INJECTION_RULES = [
  {
    id: 'sqli-union',
    name: 'SQL Injection - UNION Attack',
    pattern: /\bUNION\s+(ALL\s+)?SELECT\b/i,
    field: 'request',
    severity: 'critical',
    score: 95,
    category: 'sql-injection',
    description: 'Detects UNION-based SQL injection attempts',
    recommendation: 'Use parameterized queries and input validation'
  },
  {
    id: 'sqli-boolean',
    name: 'SQL Injection - Boolean-based',
    pattern: /(\bOR\b|\bAND\b)\s+['"]?\d+['"]?\s*=\s*['"]?\d+['"]?/i,
    field: 'request',
    severity: 'high',
    score: 85,
    category: 'sql-injection',
    description: 'Detects boolean-based SQL injection attempts (OR 1=1)',
    recommendation: 'Implement prepared statements'
  },
  {
    id: 'sqli-stacked',
    name: 'SQL Injection - Stacked Queries',
    pattern: /;\s*(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|TRUNCATE)\b/i,
    field: 'request',
    severity: 'critical',
    score: 90,
    category: 'sql-injection',
    description: 'Detects stacked SQL query injection',
    recommendation: 'Disable multiple statements in database driver'
  },
  {
    id: 'sqli-comment',
    name: 'SQL Injection - Comment Bypass',
    pattern: /(--|#|\/\*.*\*\/)/,
    field: 'query',
    severity: 'medium',
    score: 45,
    category: 'sql-injection',
    description: 'SQL comment characters used to bypass filters',
    recommendation: 'Strip or escape comment sequences'
  },
  {
    id: 'sqli-time',
    name: 'SQL Injection - Time-based',
    pattern: /\b(SLEEP|WAITFOR|BENCHMARK|DELAY)\s*\(/i,
    field: 'request',
    severity: 'high',
    score: 80,
    category: 'sql-injection',
    description: 'Time-based blind SQL injection attempt',
    recommendation: 'Set strict query timeouts'
  },
  {
    id: 'sqli-error',
    name: 'SQL Injection - Error-based',
    pattern: /\b(EXTRACTVALUE|UPDATEXML|XMLTYPE|CONVERT|CAST)\s*\(/i,
    field: 'request',
    severity: 'high',
    score: 75,
    category: 'sql-injection',
    description: 'Error-based SQL injection technique',
    recommendation: 'Hide database error messages from users'
  },
  {
    id: 'sqli-inline-comment',
    name: 'SQL Injection - Inline Comments',
    pattern: /\/\*.*?\*\/|--.*?$|#.*?$/mi,
    field: 'request',
    severity: 'high',
    score: 78,
    category: 'sql-injection',
    description: 'SQL inline comments detected (comment bypass attempt)',
    recommendation: 'Filter SQL comments and special characters'
  },
  {
    id: 'sqli-hex-encoding',
    name: 'SQL Injection - Hex Encoded SQL',
    pattern: /0x[0-9a-fA-F]+|char\s*\([0-9]+\)|ascii\s*\(/i,
    field: 'request',
    severity: 'high',
    score: 82,
    category: 'sql-injection',
    description: 'Hex or ASCII encoded SQL keywords detected',
    recommendation: 'Decode and validate all user input'
  },
  {
    id: 'sqli-alternatives',
    name: 'SQL Injection - Alternative Syntax',
    pattern: /\b(SELECT|INSERT|UPDATE|DELETE|DROP)\b[\s\S]*?\b(REPLACE|CASE|WHEN|THEN|ELSE)\b/i,
    field: 'request',
    severity: 'high',
    score: 75,
    category: 'sql-injection',
    description: 'Complex SQL syntax patterns detected',
    recommendation: 'Use parameterized queries exclusively'
  },
  {
    id: 'sqli-keywords',
    name: 'SQL Injection - Suspicious Keywords',
    pattern: /\b(FETCH|PRAGMA|INFORMATION_SCHEMA|SYSTEM_USER|VERSION|DATABASE|SCHEMA|TABLE_SCHEMA|TABLE_NAME)\b/i,
    field: 'request',
    severity: 'high',
    score: 80,
    category: 'sql-injection',
    description: 'Suspicious SQL keywords for data exfiltration',
    recommendation: 'Restrict access to system tables and schemas'
  },
  {
    id: 'sqli-info-leakage',
    name: 'SQL Injection - Information Leakage',
    pattern: /SQL\s+syntax|mysql_fetch|OLE\s+DB|Incorrect\s+syntax|Unclosed\s+quotation/i,
    field: 'response',
    severity: 'medium',
    score: 50,
    category: 'sql-injection',
    description: 'SQL error messages leaked in response',
    recommendation: 'Hide database error details from users'
  },
  {
    id: 'sqli-fuzzing',
    name: 'SQL Injection - Fuzzing Patterns',
    pattern: /[\'"]+\s*(\+|-|\*|\/|%)\s*[\'"]+|[\'"]\s*;\s*[\'"]/,
    field: 'request',
    severity: 'medium',
    score: 65,
    category: 'sql-injection',
    description: 'SQL fuzzing patterns detected',
    recommendation: 'Implement strict input validation'
  },
  {
    id: 'sqli-identifiers',
    name: 'SQL Injection - Identifier Manipulation',
    pattern: /\[.*?\]|`.*?`|".*?"|\b(USER|CURRENT_USER|SYSTEM_USER|SESSION_USER|DATABASE)\b/i,
    field: 'request',
    severity: 'high',
    score: 77,
    category: 'sql-injection',
    description: 'SQL identifier brackets or sensitive functions',
    recommendation: 'Whitelist allowed identifiers'
  },
  {
    id: 'sqli-obfuscation',
    name: 'SQL Injection - Obfuscation Techniques',
    pattern: /\bXOR\b|\bOR\b\s+\d+\s*=\s*\d+|\bAND\b\s+\d+\s*=\s*\d+|!\s*=|<>|%3D/i,
    field: 'request',
    severity: 'high',
    score: 76,
    category: 'sql-injection',
    description: 'SQL obfuscation and evasion techniques',
    recommendation: 'Normalize and validate all input'
  },
  {
    id: 'sqli-advanced-evasion',
    name: 'SQL Injection - Advanced Evasion',
    pattern: /\b(IF|CASE|WHEN|EXISTS|NOT\s+EXISTS|EXCEPT|INTERSECT|UNION\s+ALL)\b.*\b(SELECT|INSERT|UPDATE|DELETE)\b/i,
    field: 'request',
    severity: 'critical',
    score: 88,
    category: 'sql-injection',
    description: 'Advanced SQL evasion with compound statements',
    recommendation: 'Implement strict query parsing'
  },
  {
    id: 'sqli-batch-operations',
    name: 'SQL Injection - Batch Operations',
    pattern: /;\s*CREATE|;\s*ALTER|;\s*DROP|;\s*EXEC|;\s*sp_/i,
    field: 'request',
    severity: 'critical',
    score: 92,
    category: 'sql-injection',
    description: 'Multiple SQL statements (batch injection)',
    recommendation: 'Disable multi-statement execution'
  },
  {
    id: 'sqli-double-encoding',
    name: 'SQLi - Double URL Encoding',
    pattern: /%252[0-7a-fA-F]|%25[0-9a-fA-F]{2}.*(?:UNION|SELECT)/i,
    field: 'request',
    severity: 'high',
    score: 81,
    category: 'sql-injection',
    description: 'Double-encoded SQL injection payload'
  },
  {
    id: 'sqli-unicode-encoding',
    name: 'SQLi - Unicode Encoding Bypass',
    pattern: /\\u[0-9a-fA-F]{4}|&#\d+;|&#x[0-9a-fA-F]+;/i,
    field: 'request',
    severity: 'high',
    score: 79,
    category: 'sql-injection',
    description: 'Unicode-encoded SQL keywords'
  },
  {
    id: 'sqli-case-variation',
    name: 'SQLi - Case Variation Bypass',
    pattern: /[Ss][Ee][Ll][Ee][Cc][Tt]|[Uu][Nn][Ii][Oo][Nn]|[Ww][Hh][Ee][Rr][Ee]/,
    field: 'request',
    severity: 'medium',
    score: 65,
    category: 'sql-injection',
    description: 'Mixed-case SQL keywords for filter bypass'
  },
  {
    id: 'sqli-null-byte',
    name: 'SQLi - Null Byte Injection',
    pattern: /%00|\\x00|\\0(?=.*(?:SELECT|UNION))/i,
    field: 'request',
    severity: 'high',
    score: 76,
    category: 'sql-injection',
    description: 'Null byte in SQL injection payload'
  },
  {
    id: 'sqli-whitespace-bypass',
    name: 'SQLi - Whitespace Bypass Techniques',
    pattern: /(?:SELECT|UNION)[\s\n\r\t]+(?:ALL|DISTINCT)|OR[\s]+1[\s]*=[\s]*1/i,
    field: 'request',
    severity: 'high',
    score: 78,
    category: 'sql-injection',
    description: 'Newlines/tabs used to bypass filters'
  },
  {
    id: 'sqli-mysql-into-outfile',
    name: 'SQLi - MySQL INTO OUTFILE',
    pattern: /INTO\s+(OUTFILE|DUMPFILE)\s+["']/i,
    field: 'request',
    severity: 'critical',
    score: 93,
    category: 'sql-injection',
    description: 'MySQL file write via INTO OUTFILE'
  },
  {
    id: 'sqli-postgresql-copy',
    name: 'SQLi - PostgreSQL COPY Injection',
    pattern: /COPY\s+\w+\s+(?:FROM|TO)|pg_read_file|pg_write_file/i,
    field: 'request',
    severity: 'critical',
    score: 92,
    category: 'sql-injection',
    description: 'PostgreSQL file operations via COPY'
  },
  {
    id: 'sqli-mssql-xp-cmdshell',
    name: 'SQLi - MSSQL xp_cmdshell RCE',
    pattern: /xp_cmdshell|xp_regread|xp_regwrite|sp_oacreate/i,
    field: 'request',
    severity: 'critical',
    score: 95,
    category: 'sql-injection',
    description: 'MSSQL stored procedure RCE'
  },
  {
    id: 'sqli-oracle-dbms-sql',
    name: 'SQLi - Oracle DBMS_SQL Injection',
    pattern: /DBMS_SQL|EXECUTE\s+IMMEDIATE|UTL_FILE/i,
    field: 'request',
    severity: 'critical',
    score: 93,
    category: 'sql-injection',
    description: 'Oracle dynamic SQL execution'
  },
  {
    id: 'sqli-second-order',
    name: 'SQLi - Second-Order Injection Indicators',
    pattern: /INSERT\s+INTO.*SELECT|UPDATE.*SELECT|CREATE\s+TABLE.*SELECT/i,
    field: 'request',
    severity: 'high',
    score: 84,
    category: 'sql-injection',
    description: 'Second-order SQLi patterns'
  },
  {
    id: 'sqli-subquery-injection',
    name: 'SQLi - Subquery Injection',
    pattern: /\(SELECT.*FROM.*WHERE.*\)|SELECT.*\(SELECT/i,
    field: 'request',
    severity: 'high',
    score: 80,
    category: 'sql-injection',
    description: 'Nested subquery injection'
  },
  {
    id: 'sqli-union-all-select',
    name: 'SQLi - UNION ALL SELECT Variant',
    pattern: /UNION\s+ALL\s+SELECT/i,
    field: 'request',
    severity: 'critical',
    score: 94,
    category: 'sql-injection',
    description: 'UNION ALL SELECT injection'
  },
  {
    id: 'sqli-intersect-except',
    name: 'SQLi - INTERSECT/EXCEPT Injection',
    pattern: /\b(INTERSECT|EXCEPT)\s+SELECT/i,
    field: 'request',
    severity: 'high',
    score: 82,
    category: 'sql-injection',
    description: 'INTERSECT/EXCEPT set operations'
  },
  {
    id: 'sqli-order-by-blind',
    name: 'SQLi - ORDER BY Blind Injection',
    pattern: /ORDER\s+BY\s+\d+.*(?:--|\#)|ORDER\s+BY\s+\(SELECT/i,
    field: 'request',
    severity: 'high',
    score: 79,
    category: 'sql-injection',
    description: 'ORDER BY clause blind SQLi'
  },
  {
    id: 'sqli-limit-offset',
    name: 'SQLi - LIMIT/OFFSET Injection',
    pattern: /LIMIT\s+[\d,\s]+(?:UNION|SELECT|OR)|OFFSET.*(?:UNION|SELECT)/i,
    field: 'request',
    severity: 'high',
    score: 75,
    category: 'sql-injection',
    description: 'LIMIT/OFFSET clause injection'
  },
  {
    id: 'sqli-group-by-having',
    name: 'SQLi - GROUP BY/HAVING Injection',
    pattern: /GROUP\s+BY.*(?:UNION|SELECT|OR)|HAVING.*(?:UNION|SELECT)/i,
    field: 'request',
    severity: 'high',
    score: 77,
    category: 'sql-injection',
    description: 'GROUP BY/HAVING clause injection'
  },
  {
    id: 'sqli-json-extraction',
    name: 'SQLi - JSON Extraction Functions',
    pattern: /JSON_EXTRACT|JSON_UNQUOTE|JSON_CONTAINS|->|->>/i,
    field: 'request',
    severity: 'high',
    score: 76,
    category: 'sql-injection',
    description: 'JSON function extraction for data theft'
  },
  {
    id: 'sqli-xml-functions',
    name: 'SQLi - XML Function Injection',
    pattern: /XPATH|EXTRACTVALUE|UPDATEXML|XMLPARSE|XMLQUERY/i,
    field: 'request',
    severity: 'high',
    score: 80,
    category: 'sql-injection',
    description: 'XML function exploitation'
  },
  {
    id: 'sqli-string-functions',
    name: 'SQLi - String Manipulation for Bypass',
    pattern: /CONCAT\s*\(|CONCAT_WS|GROUP_CONCAT|STRING_AGG|REPLACE\s*\(.*OR/i,
    field: 'request',
    severity: 'high',
    score: 74,
    category: 'sql-injection',
    description: 'String functions for payload obfuscation'
  },
  {
    id: 'sqli-cast-convert',
    name: 'SQLi - CAST/CONVERT Type Juggling',
    pattern: /CAST\s*\([^)]*AS\s*(?:INT|CHAR|VARCHAR)|CONVERT\s*\([^)]*,[^)]*\)/i,
    field: 'request',
    severity: 'high',
    score: 78,
    category: 'sql-injection',
    description: 'Type conversion for bypass'
  },
  {
    id: 'sqli-mathematical-ops',
    name: 'SQLi - Mathematical Operations',
    pattern: /(\d+)\s*[\+\-\*\/\%]\s*(\d+)\s*(?:AND|OR|=)/i,
    field: 'request',
    severity: 'medium',
    score: 62,
    category: 'sql-injection',
    description: 'Math operations in WHERE clause'
  },
  {
    id: 'sqli-bitwise-ops',
    name: 'SQLi - Bitwise Operations',
    pattern: /(&|<<|>>|\^)\s*\d+|BINARY\s+/i,
    field: 'request',
    severity: 'high',
    score: 73,
    category: 'sql-injection',
    description: 'Bitwise operations for payload encoding'
  },
  {
    id: 'sqli-like-bypass',
    name: 'SQLi - LIKE Clause Injection',
    pattern: /LIKE\s+['"][\%_]|LIKE\s+[\d\w%_]*(?:%|_)/i,
    field: 'request',
    severity: 'high',
    score: 71,
    category: 'sql-injection',
    description: 'LIKE clause SQLi with wildcards'
  },
  {
    id: 'sqli-in-list-injection',
    name: 'SQLi - IN Clause Injection',
    pattern: /IN\s*\(\s*(?:SELECT|UNION)|IN\s*\([^)]*OR[^)]*\)/i,
    field: 'request',
    severity: 'high',
    score: 75,
    category: 'sql-injection',
    description: 'IN clause with subqueries'
  },
  {
    id: 'sqli-exists-injection',
    name: 'SQLi - EXISTS Clause Injection',
    pattern: /EXISTS\s*\(\s*SELECT|NOT\s+EXISTS\s*\(\s*SELECT/i,
    field: 'request',
    severity: 'high',
    score: 79,
    category: 'sql-injection',
    description: 'EXISTS clause exploitation'
  },
  {
    id: 'sqli-between-injection',
    name: 'SQLi - BETWEEN Clause Injection',
    pattern: /BETWEEN.*AND.*(?:SELECT|UNION|OR)/i,
    field: 'request',
    severity: 'high',
    score: 76,
    category: 'sql-injection',
    description: 'BETWEEN clause SQLi'
  },
  {
    id: 'sqli-case-when-injection',
    name: 'SQLi - CASE/WHEN Injection',
    pattern: /CASE\s+WHEN.*THEN.*(?:SELECT|UNION)|CASE\s+WHEN\s+.*=.*THEN/i,
    field: 'request',
    severity: 'high',
    score: 77,
    category: 'sql-injection',
    description: 'CASE statement conditional injection'
  },
  {
    id: 'sqli-if-function',
    name: 'SQLi - IF Function Injection',
    pattern: /IF\s*\([^)]*,[^)]*,[^)]*\).*(?:SELECT|UNION)|IF\s*\(\d+\s*=\s*\d+/i,
    field: 'request',
    severity: 'high',
    score: 78,
    category: 'sql-injection',
    description: 'IF conditional function exploitation'
  },
  {
    id: 'sqli-aggregate-functions',
    name: 'SQLi - Aggregate Function Abuse',
    pattern: /(?:COUNT|SUM|AVG|MIN|MAX)\s*\(\s*(?:\*|\w+)\s*\).*(?:SELECT|UNION)/i,
    field: 'request',
    severity: 'high',
    score: 72,
    category: 'sql-injection',
    description: 'Aggregate functions for data extraction'
  },
  {
    id: 'sqli-window-functions',
    name: 'SQLi - Window Functions',
    pattern: /ROW_NUMBER|RANK|DENSE_RANK|LAG|LEAD|OVER\s*\(/i,
    field: 'request',
    severity: 'high',
    score: 74,
    category: 'sql-injection',
    description: 'Window functions for advanced extraction'
  },
  {
    id: 'sqli-cte-injection',
    name: 'SQLi - CTE (WITH) Clause Injection',
    pattern: /WITH\s+\w+\s+AS\s*\(\s*SELECT|RECURSIVE/i,
    field: 'request',
    severity: 'high',
    score: 80,
    category: 'sql-injection',
    description: 'Common Table Expression injection'
  },
  {
    id: 'sqli-lateral-join',
    name: 'SQLi - LATERAL JOIN Injection',
    pattern: /LATERAL\s+\(|CROSS\s+APPLY|OUTER\s+APPLY/i,
    field: 'request',
    severity: 'high',
    score: 75,
    category: 'sql-injection',
    description: 'LATERAL/APPLY join injection'
  },
  {
    id: 'sqli-full-outer-join',
    name: 'SQLi - FULL OUTER JOIN Injection',
    pattern: /FULL\s+OUTER\s+JOIN.*(?:SELECT|UNION)|RIGHT\s+OUTER\s+JOIN.*(?:UNION)/i,
    field: 'request',
    severity: 'high',
    score: 73,
    category: 'sql-injection',
    description: 'Outer join exploitation'
  },
  {
    id: 'sqli-self-join',
    name: 'SQLi - Self-Join Exploitation',
    pattern: /FROM\s+\w+\s+a\s+JOIN\s+\w+\s+b.*(?:UNION|SELECT\s+\*\s+FROM)/i,
    field: 'request',
    severity: 'high',
    score: 71,
    category: 'sql-injection',
    description: 'Self-join for data enumeration'
  },
  {
    id: 'sqli-cross-join',
    name: 'SQLi - CROSS JOIN DoS',
    pattern: /CROSS\s+JOIN.*CROSS\s+JOIN|CROSS\s+JOIN.*CROSS\s+JOIN.*CROSS\s+JOIN/i,
    field: 'request',
    severity: 'high',
    score: 72,
    category: 'sql-injection',
    description: 'CROSS JOIN cartesian product DoS'
  },
  {
    id: 'sqli-natural-join',
    name: 'SQLi - NATURAL JOIN Confusion',
    pattern: /NATURAL\s+(?:INNER\s+)?JOIN|USING\s*\([^)]*\)/i,
    field: 'request',
    severity: 'medium',
    score: 68,
    category: 'sql-injection',
    description: 'NATURAL/USING join confusion'
  },
  {
    id: 'sqli-on-clause-injection',
    name: 'SQLi - ON Clause Injection',
    pattern: /ON\s+\d+\s*=\s*\d+|ON\s+.*OR\s+.*=|ON.*AND.*SELECT/i,
    field: 'request',
    severity: 'high',
    score: 76,
    category: 'sql-injection',
    description: 'JOIN ON clause exploitation'
  },
  {
    id: 'sqli-where-clause-chain',
    name: 'SQLi - WHERE Clause Chaining',
    pattern: /WHERE.*AND.*OR.*(?:=|!=|<>).*WHERE/i,
    field: 'request',
    severity: 'high',
    score: 70,
    category: 'sql-injection',
    description: 'Multiple WHERE conditions'
  },
  {
    id: 'sqli-having-clause-injection',
    name: 'SQLi - HAVING Filter Bypass',
    pattern: /GROUP\s+BY.*HAVING\s+[\d]\s*=\s*[\d]|HAVING\s+.*OR\s+.*=.*OR/i,
    field: 'request',
    severity: 'high',
    score: 74,
    category: 'sql-injection',
    description: 'HAVING clause filter bypass'
  },
  {
    id: 'sqli-raw-string-concat',
    name: 'SQLi - Raw String Concatenation',
    pattern: /['"][+\s]+"[^"]*"|['"][+\s]+'[^']*'/,
    field: 'request',
    severity: 'high',
    score: 77,
    category: 'sql-injection',
    description: 'String concatenation for payload building'
  },
  {
    id: 'sqli-wildcard-injection',
    name: 'SQLi - Wildcard Character Abuse',
    pattern: /['%_][%_]['"]|LIKE\s+['"][%_]+['"]|LIKE\s+CONCAT/i,
    field: 'request',
    severity: 'medium',
    score: 69,
    category: 'sql-injection',
    description: 'LIKE wildcard exploitation'
  },
  {
    id: 'sqli-escape-quote-bypass',
    name: 'SQLi - Quote Escape Bypass',
    pattern: /['\\"\\\\]+|['\\\\]{2,}|('')+/i,
    field: 'request',
    severity: 'high',
    score: 75,
    category: 'sql-injection',
    description: 'Quote/escape character bypass'
  },
  {
    id: 'sqli-regex-like-injection',
    name: 'SQLi - REGEXP/RLIKE Injection',
    pattern: /REGEXP\s+['"]|RLIKE\s+['"]|~\s*['"].*(?:SELECT|UNION)/i,
    field: 'request',
    severity: 'high',
    score: 76,
    category: 'sql-injection',
    description: 'Regular expression matching injection'
  },
  {
    id: 'sqli-array-injection',
    name: 'SQLi - Array/List Injection',
    pattern: /\[.*\].*(?:SELECT|UNION)|ARRAY\[|ARRAY\s*\(/i,
    field: 'request',
    severity: 'high',
    score: 73,
    category: 'sql-injection',
    description: 'Array/list operations in SQL'
  },
  {
    id: 'sqli-triggers-injection',
    name: 'SQLi - Trigger Manipulation',
    pattern: /CREATE\s+TRIGGER|ALTER\s+TRIGGER|DROP\s+TRIGGER|ON\s+(?:INSERT|UPDATE|DELETE)/i,
    field: 'request',
    severity: 'critical',
    score: 94,
    category: 'sql-injection',
    description: 'Database trigger creation for persistence'
  },
  {
    id: 'sqli-view-injection',
    name: 'SQLi - View Injection',
    pattern: /CREATE\s+(?:OR\s+REPLACE\s+)?VIEW|DROP\s+VIEW|ALTER\s+VIEW/i,
    field: 'request',
    severity: 'critical',
    score: 91,
    category: 'sql-injection',
    description: 'Database view manipulation'
  },
  {
    id: 'sqli-procedure-injection',
    name: 'SQLi - Stored Procedure Injection',
    pattern: /CREATE\s+(?:PROCEDURE|FUNCTION)|ALTER\s+(?:PROCEDURE|FUNCTION)|DROP\s+(?:PROCEDURE|FUNCTION)/i,
    field: 'request',
    severity: 'critical',
    score: 95,
    category: 'sql-injection',
    description: 'Stored procedure creation/modification'
  },
  {
    id: 'sqli-privilege-escalation',
    name: 'SQLi - Privilege Escalation',
    pattern: /GRANT\s+(?:ALL|ADMIN)|ALTER\s+USER.*ADMIN|ALTER\s+LOGIN|EXECUTE\s+AS/i,
    field: 'request',
    severity: 'critical',
    score: 96,
    category: 'sql-injection',
    description: 'Privilege escalation via SQL'
  },
  {
    id: 'sqli-user-creation',
    name: 'SQLi - User Account Creation',
    pattern: /CREATE\s+USER|CREATE\s+LOGIN|ALTER\s+USER.*PASSWORD|SET\s+PASSWORD/i,
    field: 'request',
    severity: 'critical',
    score: 93,
    category: 'sql-injection',
    description: 'Unauthorized user/account creation'
  },
  {
    id: 'sqli-role-manipulation',
    name: 'SQLi - Role/Permission Manipulation',
    pattern: /CREATE\s+ROLE|ALTER\s+ROLE|GRANT\s+ROLE|REVOKE\s+ROLE/i,
    field: 'request',
    severity: 'critical',
    score: 92,
    category: 'sql-injection',
    description: 'Database role manipulation'
  },
  {
    id: 'sqli-temp-table',
    name: 'SQLi - Temporary Table Injection',
    pattern: /CREATE\s+(?:#|TEMPORARY)\s+TABLE|DROP\s+(?:#|TEMPORARY)\s+TABLE/i,
    field: 'request',
    severity: 'high',
    score: 82,
    category: 'sql-injection',
    description: 'Temporary table creation for data manipulation'
  },
  {
    id: 'sqli-transaction-control',
    name: 'SQLi - Transaction Control Injection',
    pattern: /BEGIN\s+TRANSACTION|START\s+TRANSACTION|COMMIT|ROLLBACK|SAVEPOINT/i,
    field: 'request',
    severity: 'high',
    score: 79,
    category: 'sql-injection',
    description: 'Transaction statement injection'
  },
  {
    id: 'sqli-lock-wait-injection',
    name: 'SQLi - Lock/Wait Injection',
    pattern: /LOCK\s+IN\s+SHARE\s+MODE|FOR\s+UPDATE|FOR\s+SHARE|WAIT|NOWAIT/i,
    field: 'request',
    severity: 'high',
    score: 77,
    category: 'sql-injection',
    description: 'Lock/wait for injection'
  },
  {
    id: 'sqli-cursor-injection',
    name: 'SQLi - Cursor Operations',
    pattern: /DECLARE\s+CURSOR|FETCH\s+(?:NEXT|PRIOR|FIRST|LAST|ABSOLUTE)/i,
    field: 'request',
    severity: 'high',
    score: 75,
    category: 'sql-injection',
    description: 'Cursor-based data traversal'
  },
  {
    id: 'sqli-bulk-insert',
    name: 'SQLi - BULK INSERT/LOAD',
    pattern: /BULK\s+INSERT|LOAD\s+DATA|INTO\s+OUTFILE|FROM\s+['\"].*\.csv/i,
    field: 'request',
    severity: 'critical',
    score: 90,
    category: 'sql-injection',
    description: 'Bulk data operations'
  },
  {
    id: 'sqli-truncate-injection',
    name: 'SQLi - TRUNCATE/DELETE All',
    pattern: /TRUNCATE\s+TABLE|DELETE\s+FROM\s+\w+\s*;|DELETE\s+FROM\s+\w+\s*WHERE\s+1=1/i,
    field: 'request',
    severity: 'critical',
    score: 94,
    category: 'sql-injection',
    description: 'Data destruction via truncate/delete'
  },
  {
    id: 'sqli-rename-injection',
    name: 'SQLi - Table Rename Injection',
    pattern: /ALTER\s+TABLE\s+\w+\s+RENAME|RENAME\s+TABLE/i,
    field: 'request',
    severity: 'high',
    score: 81,
    category: 'sql-injection',
    description: 'Table renaming for confusion'
  },
  {
    id: 'sqli-column-operations',
    name: 'SQLi - Column Add/Drop Operations',
    pattern: /ALTER\s+TABLE\s+\w+\s+(?:ADD|DROP|MODIFY)\s+COLUMN/i,
    field: 'request',
    severity: 'high',
    score: 80,
    category: 'sql-injection',
    description: 'Schema modification attacks'
  },
  {
    id: 'sqli-index-injection',
    name: 'SQLi - Index Creation Injection',
    pattern: /CREATE\s+(?:UNIQUE\s+)?INDEX|DROP\s+INDEX|ALTER\s+INDEX/i,
    field: 'request',
    severity: 'high',
    score: 76,
    category: 'sql-injection',
    description: 'Index manipulation for performance attacks'
  },
  {
    id: 'sqli-collation-injection',
    name: 'SQLi - Collation Manipulation',
    pattern: /COLLATE\s+[a-zA-Z0-9_]+|CHARACTER\s+SET|CHARSET/i,
    field: 'request',
    severity: 'medium',
    score: 66,
    category: 'sql-injection',
    description: 'Collation confusion attacks'
  },
  {
    id: 'sqli-constraint-injection',
    name: 'SQLi - Constraint Manipulation',
    pattern: /ADD\s+(?:CONSTRAINT|PRIMARY|FOREIGN|UNIQUE|CHECK)|DROP\s+CONSTRAINT/i,
    field: 'request',
    severity: 'high',
    score: 77,
    category: 'sql-injection',
    description: 'Integrity constraint manipulation'
  },
  {
    id: 'sqli-schema-qualification',
    name: 'SQLi - Schema Qualification Bypass',
    pattern: /\w+\.\w+\.\w+|dbo\.\w+|public\.\w+/i,
    field: 'request',
    severity: 'high',
    score: 72,
    category: 'sql-injection',
    description: 'Cross-schema object access'
  },
  {
    id: 'sqli-database-link',
    name: 'SQLi - Database Link Exploitation',
    pattern: /@\w+|DBLINK|REMOTE_OS|REMOTE_OS_USER/i,
    field: 'request',
    severity: 'critical',
    score: 91,
    category: 'sql-injection',
    description: 'Database link for remote access'
  },
  {
    id: 'sqli-implicit-type-conversion',
    name: 'SQLi - Implicit Type Conversion',
    pattern: /\d+\s*=\s*['"][^"]*['"]|['"][^\d"]*['"][\s]*=\s*\d+/,
    field: 'request',
    severity: 'medium',
    score: 64,
    category: 'sql-injection',
    description: 'Type conversion confusion'
  },
  {
    id: 'sqli-column-aliasing',
    name: 'SQLi - Column Aliasing Confusion',
    pattern: /\bAS\s+[\w\d]+\s+(?:WHERE|UNION|SELECT)/i,
    field: 'request',
    severity: 'medium',
    score: 63,
    category: 'sql-injection',
    description: 'Column alias for query structure confusion'
  },
  {
    id: 'sqli-table-aliasing',
    name: 'SQLi - Table Aliasing Injection',
    pattern: /FROM\s+\w+\s+[a-z]+\s+WHERE|FROM.*\s+[a-z]{1,3}\s+(?:INNER|LEFT|RIGHT|FULL|CROSS)/i,
    field: 'request',
    severity: 'high',
    score: 71,
    category: 'sql-injection',
    description: 'Table alias manipulation'
  },
  {
    id: 'sqli-expression-injection',
    name: 'SQLi - Complex Expression Injection',
    pattern: /SELECT.*\+.*SELECT|SELECT.*\*.*SELECT|SELECT.*\/.*SELECT/i,
    field: 'request',
    severity: 'high',
    score: 73,
    category: 'sql-injection',
    description: 'Complex expression-based injection'
  },
  {
    id: 'sqli-database-metadata',
    name: 'SQLi - Database Metadata Extraction',
    pattern: /information_schema|mysql\.user|pg_catalog|sys\.tables|sys\.columns/i,
    field: 'request',
    severity: 'high',
    score: 81,
    category: 'sql-injection',
    description: 'System metadata table access'
  }
];
