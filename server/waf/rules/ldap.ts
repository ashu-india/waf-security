export const LDAP_RULES = [
  {id:'ldap-injection',name:'LDAP Injection',pattern:/[)(|*\\]/,field:'query',severity:'medium',score:50,category:'ldap-injection',description:'LDAP special characters',recommendation:'Escape LDAP characters'}
];
