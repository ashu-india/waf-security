// Java Attack Rules (ModSecurity CRS 944)
export const JAVA_ATTACKS_RULES = [
  {
    id: 'java-serialization',
    name: 'Java - Unsafe Deserialization',
    pattern: /\bObjectInputStream\b|\breadObject\b|java\.io\.Serializable|ysoserial|CommonsCollections|JNDI/i,
    field: 'request',
    severity: 'critical',
    score: 98,
    category: 'java-attacks',
    description: 'Java deserialization exploitation (gadget chains)',
    recommendation: 'Disable object deserialization, use allowlists'
  },
  {
    id: 'java-reflection',
    name: 'Java - Unsafe Reflection',
    pattern: /\bClass\.forName\b|\bgetMethod\b|\bgetField\b|invoke\s*\(|newInstance|defineClass/i,
    field: 'request',
    severity: 'high',
    score: 90,
    category: 'java-attacks',
    description: 'Java reflection for dynamic code execution',
    recommendation: 'Avoid reflection with user input, use security manager'
  },
  {
    id: 'java-jndi-injection',
    name: 'Java - JNDI Injection',
    pattern: /(rmi:\/\/|ldap:\/\/|nis:\/\/|iiop:\/\/|corbaname:\/\/|ldaps:\/\/).*\$\{.*\}|InitialContext|lookup/i,
    field: 'request',
    severity: 'critical',
    score: 96,
    category: 'java-attacks',
    description: 'JNDI injection with variable expansion (Log4Shell)',
    recommendation: 'Update Log4j and disable variable expansion'
  },
  {
    id: 'java-spring-expression',
    name: 'Java - Spring Expression Injection',
    pattern: /SpEL|\$\{.*T\(.*\)\}|T\(java\.|\.class\.forName/i,
    field: 'request',
    severity: 'critical',
    score: 94,
    category: 'java-attacks',
    description: 'Spring Expression Language injection',
    recommendation: 'Avoid SpEL with user input, use strict parser'
  },
  {
    id: 'java-velocity-template',
    name: 'Java - Velocity Template Injection',
    pattern: /#set\s*\(|#if\s*\(|#foreach|#parse|#include|\$\{.*\.class\..*\}|#evaluate/i,
    field: 'request',
    severity: 'high',
    score: 88,
    category: 'java-attacks',
    description: 'Velocity template engine injection',
    recommendation: 'Disable dangerous directives, sandbox template execution'
  },
  {
    id: 'java-freemarker-injection',
    name: 'Java - FreeMarker Template Injection',
    pattern: /<#assign|<#if|<#list|<@|\?new|\?api|FreeMarkerException/i,
    field: 'request',
    severity: 'high',
    score: 86,
    category: 'java-attacks',
    description: 'FreeMarker template language injection',
    recommendation: 'Use safe configuration, disable object wrapping'
  },
  {
    id: 'java-groovy-injection',
    name: 'Java - Groovy Script Injection',
    pattern: /GroovyShell|GroovyEngine|\.evaluate\s*\(|\.execute\s*\(|Runtime\.getRuntime|ProcessGroovyMethods/i,
    field: 'request',
    severity: 'critical',
    score: 92,
    category: 'java-attacks',
    description: 'Groovy dynamic script execution',
    recommendation: 'Disable script evaluation, use sandboxing'
  },
  {
    id: 'java-xpath-injection',
    name: 'Java - XPath Injection',
    pattern: /XPathFactory|XPath\.evaluate|selectNodes|selectSingleNode|concat\s*\(|string-length/i,
    field: 'request',
    severity: 'high',
    score: 82,
    category: 'java-attacks',
    description: 'XPath injection in Java applications',
    recommendation: 'Use parameterized XPath queries'
  },
  {
    id: 'java-mybatis-injection',
    name: 'Java - MyBatis SQL Injection',
    pattern: /\$\{.*\}|#\{.*\}|sqlmap|union.*select|mybatis|mapper/i,
    field: 'request',
    severity: 'high',
    score: 85,
    category: 'java-attacks',
    description: 'MyBatis SQL injection via unsanitized variables',
    recommendation: 'Use parameterized queries, validate all input'
  },
  {
    id: 'java-classloader-injection',
    name: 'Java - ClassLoader Manipulation',
    pattern: /ClassLoader|defineClass|findClass|loadClass|setClassAssertionStatus|getClassloader/i,
    field: 'request',
    severity: 'high',
    score: 83,
    category: 'java-attacks',
    description: 'ClassLoader manipulation for code injection',
    recommendation: 'Restrict ClassLoader access, use security manager'
  },
  {
    id: 'java-runtime-exec',
    name: 'Java - Runtime.exec() Command Injection',
    pattern: /Runtime\.getRuntime\s*\(\)\s*\.exec|ProcessBuilder|ProcessImpl|java\.lang\.UNIXProcess/i,
    field: 'request',
    severity: 'critical',
    score: 97,
    category: 'java-attacks',
    description: 'Direct runtime command execution',
    recommendation: 'Avoid Runtime.exec(), use security manager'
  },
  {
    id: 'java-script-engine',
    name: 'Java - ScriptEngineManager Injection',
    pattern: /ScriptEngineManager|ScriptEngine|getEngineByName|eval\s*\(|javascript|nashorn|rhino/i,
    field: 'request',
    severity: 'critical',
    score: 93,
    category: 'java-attacks',
    description: 'Script engine injection (Nashorn/Rhino)',
    recommendation: 'Disable script engines, use sandboxing'
  },
  {
    id: 'java-mbean-injection',
    name: 'Java - MBean/JMX Injection',
    pattern: /MBeanServer|ObjectName|createMBean|setAttribute|getAttribute|invoke|JMXConnectorFactory/i,
    field: 'request',
    severity: 'high',
    score: 89,
    category: 'java-attacks',
    description: 'JMX/MBean manipulation',
    recommendation: 'Restrict JMX access, use authentication'
  },
  {
    id: 'java-el-injection',
    name: 'Java - Expression Language (EL) Injection',
    pattern: /\$\{[^}]*\}|\#\{[^}]*\}|ELProcessor|evaluateExpression|parseExpression/i,
    field: 'request',
    severity: 'high',
    score: 88,
    category: 'java-attacks',
    description: 'EL injection in JSP/JSF',
    recommendation: 'Disable EL evaluation, use strict templates'
  },
  {
    id: 'java-ognl-injection',
    name: 'Java - OGNL Injection',
    pattern: /OGNL|%\{[^}]*\}|struts|getValue|setValue|\(#|@java|@org/i,
    field: 'request',
    severity: 'high',
    score: 87,
    category: 'java-attacks',
    description: 'Object-Graph Navigation Language injection',
    recommendation: 'Update Struts, disable OGNL with user input'
  },
  {
    id: 'java-log4j-injection',
    name: 'Java - Log4j Injection Patterns',
    pattern: /\$\{jndi:[^}]*\}|log4j|Log4j|CVE-2021-44228|log4shell|JndiLookup/i,
    field: 'request',
    severity: 'critical',
    score: 95,
    category: 'java-attacks',
    description: 'Log4Shell and related Log4j exploits',
    recommendation: 'Update to patched Log4j version'
  },
  {
    id: 'java-urlclassloader',
    name: 'Java - URLClassLoader Exploitation',
    pattern: /URLClassLoader|new\s+URL|addURL|jar:file|codebase|java\.net\.URL/i,
    field: 'request',
    severity: 'high',
    score: 84,
    category: 'java-attacks',
    description: 'Remote class loading via URLClassLoader',
    recommendation: 'Restrict URLClassLoader usage'
  },
  {
    id: 'java-bcel-injection',
    name: 'Java - BCEL Classloader Injection',
    pattern: /BCEL|org\.apache\.bcel|com\.sun\.org\.apache\.bcel|Bytecode Engineering|ClassPool/i,
    field: 'request',
    severity: 'high',
    score: 86,
    category: 'java-attacks',
    description: 'BCEL bytecode manipulation',
    recommendation: 'Update BCEL, restrict bytecode manipulation'
  },
  {
    id: 'java-jexl-injection',
    name: 'Java - JEXL Expression Injection',
    pattern: /JexlEngine|JexlContext|createExpression|getValue|jexl|commons\.jexl/i,
    field: 'request',
    severity: 'high',
    score: 85,
    category: 'java-attacks',
    description: 'JEXL expression language injection',
    recommendation: 'Use parameterized JEXL expressions'
  },
  {
    id: 'java-pickle-serialization',
    name: 'Java - Unsafe Pickle Deserialization',
    pattern: /pickle\.loads|cPickle|marshal\.loads|unpickle|ObjectInputStream|readObject/i,
    field: 'request',
    severity: 'high',
    score: 88,
    category: 'java-attacks',
    description: 'Python pickle or Java serialization attacks',
    recommendation: 'Avoid unsafe deserialization'
  }
];
