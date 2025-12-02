export const HEADER_INJECTION_RULES = [
  {id:'crlf-injection',name:'CRLF Injection',pattern:/(%0d|%0a|\\r|\\n)/i,field:'request',severity:'high',score:75,category:'header-injection',description:'CRLF characters for header injection',recommendation:'Strip CRLF characters'}
];
