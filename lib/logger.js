/*
   DESCRIPTION
    This class will is a wrapper for bunyan logger module

   MODIFIED    (MM/DD/YY)
    xinnwang    12/06/16 - Refacotoring
    junyhe      11/22/16 - Creation
 */
'use strict';

// third party logger module
const buyanLogger = require('bunyan');
var level = 'info';
class Logger {
  /**
   * Get logger instance for specified name
   */
  static getLogger(name) {
    let logger = buyanLogger.createLogger({
      name,
      streams: [{
        level: 'error',
        name: 'error',
        path: 'error.log'
      }, {
        stream: process.stdout,
        level: 'warn',
        name: 'console',
      }]
    });
    logger.level(level);
    return logger;
  }

  static setLevel(vLevel) {
    level = vLevel;
  }
}

module.exports = Logger;
