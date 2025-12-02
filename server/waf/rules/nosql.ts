export const NOSQL_RULES = [
  {id:'nosql-injection',name:'NoSQL Injection',pattern:/(\$where|\$ne|\$gt|\$lt|\$regex|\$or|\$and|\$not|\$nor|\$in|\$nin)/i,field:'request',severity:'high',score:80,category:'nosql-injection',description:'MongoDB/NoSQL injection',recommendation:'Sanitize NoSQL operators'}
];
