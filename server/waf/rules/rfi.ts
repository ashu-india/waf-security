export const RFI_RULES = [
  {id:'rfi-attempt',name:'Remote File Inclusion',pattern:/(https?|ftp|php|data|expect|input|filter):\/\//i,field:'query',severity:'critical',score:90,category:'rfi',description:'Remote file inclusion',recommendation:'Disable RFI'},
  {id:'php-wrapper',name:'PHP Wrapper Abuse',pattern:/php:\/\/(input|filter|data|expect)/i,field:'request',severity:'critical',score:90,category:'rfi',description:'PHP stream wrapper abuse',recommendation:'Disable wrappers'}
];
