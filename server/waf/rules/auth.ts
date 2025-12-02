export const AUTH_RULES = [
  {id:'jwt-manipulation',name:'JWT Manipulation',pattern:/eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[^.]+/,field:'headers',severity:'low',score:20,category:'auth',description:'JWT token detected',recommendation:'Ensure JWT validation'}
];
