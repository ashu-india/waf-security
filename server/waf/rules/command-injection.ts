export const COMMAND_INJECTION_RULES = [
  {id:'cmd-injection-basic',name:'Command Injection - Basic',pattern:/[;&|`$]\s*(cat|ls|id|whoami|uname|pwd|wget|curl|nc|bash|sh|python|perl|ruby|php)/i,field:'request',severity:'critical',score:95,category:'command-injection',description:'Shell command execution',recommendation:'Never pass user input to shell'},
  {id:'cmd-injection-redirect',name:'Command Injection - Redirection',pattern:/[<>]\s*[\/\w]+|>>\s*[\/\w]+/,field:'request',severity:'high',score:75,category:'command-injection',description:'Shell redirection operators',recommendation:'Block shell metacharacters'},
  {id:'cmd-injection-subshell',name:'Command Injection - Subshell',pattern:/\$\([^)]+\)|\`[^`]+\`/,field:'request',severity:'critical',score:90,category:'command-injection',description:'Command substitution',recommendation:'Use safe APIs only'}
];
