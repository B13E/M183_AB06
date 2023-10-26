const pino = require('pino');
const rotatingLogStream = require('@vrbo/pino-rotating-file');

const logger = pino(
  {
    level: 'info',
  },
  rotatingLogStream({
    path: 'logs',      
    size: '1MB',       
    count: 5           
  })
);

module.exports = logger;
