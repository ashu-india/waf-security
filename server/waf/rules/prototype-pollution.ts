export const PROTOTYPE_POLLUTION_RULES = [
  {id:'prototype-pollution',name:'Prototype Pollution',pattern:/__proto__|constructor\s*\[|prototype\s*\[/i,field:'body',severity:'high',score:80,category:'prototype-pollution',description:'JavaScript prototype pollution',recommendation:'Validate JSON keys'}
];
