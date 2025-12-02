export const MASS_ASSIGNMENT_RULES = [
  {id:'mass-assignment',name:'Mass Assignment',pattern:/(isAdmin|is_admin|role|admin|privilege|permission)\s*[=:]/i,field:'body',severity:'medium',score:55,category:'mass-assignment',description:'Mass assignment of sensitive fields',recommendation:'Use field whitelisting'}
];
