export const SSTI_RULES = [
  {id:'ssti-jinja',name:'SSTI - Jinja2/Twig',pattern:/\{\{.*(__class__|__mro__|__subclasses__|__globals__|__builtins__).*\}\}/i,field:'request',severity:'critical',score:95,category:'ssti',description:'Server-Side Template Injection',recommendation:'Avoid rendering user input'}
];
