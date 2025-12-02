export const OPEN_REDIRECT_RULES = [
  {id:'open-redirect',name:'Open Redirect',pattern:/(url|redirect|next|goto|return|returnUrl|returnTo|dest|destination|redir|redirect_uri|continue)\s*=\s*https?:\/\//i,field:'query',severity:'medium',score:55,category:'open-redirect',description:'Open redirect vulnerability',recommendation:'Validate against whitelist'}
];
