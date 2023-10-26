const pino = require('pino');
const rotatingLogFileModule = require('@vrbo/pino-rotating-file');

const logger = pino({
    level: 'info',
    stream: rotatingLogFileModule.start({
        path: 'logs',      
        size: '1MB',       
        count: 5           
    })
});

module.exports = logger;
