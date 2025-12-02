export const LOG_INJECTION_RULES = [
  {id:'log-injection',name:'Log Injection',pattern:/(\n|\r).*?(ERROR|WARN|INFO|DEBUG|FATAL)/i,field:'request',severity:'medium',score:45,category:'log-injection',description:'Fake log entry injection',recommendation:'Sanitize log output'}
];
