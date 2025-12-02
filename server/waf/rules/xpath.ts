export const XPATH_RULES = [
  {id:'xpath-injection',name:'XPath Injection',pattern:/['"][\s]*or[\s]*['"]|contains\s*\(|text\s*\(\)/i,field:'request',severity:'high',score:75,category:'xpath-injection',description:'XPath injection',recommendation:'Use parameterized queries'}
];
