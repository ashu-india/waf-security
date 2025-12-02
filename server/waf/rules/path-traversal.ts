export const PATH_TRAVERSAL_RULES = [
  {id:'path-traversal',name:'Path Traversal',pattern:/(\.\.(\/|\\|%2f|%5c))+/i,field:'request',severity:'high',score:80,category:'path-traversal',description:'Directory traversal attempt',recommendation:'Validate and sanitize file paths'},
  {id:'path-null-byte',name:'Path Traversal - Null Byte',pattern:/%00|\\x00|\0/,field:'request',severity:'high',score:85,category:'path-traversal',description:'Null byte injection',recommendation:'Remove null bytes'}
];
