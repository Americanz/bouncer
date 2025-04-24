const LOG_LEVELS = {
  debug: 0,
  info: 1,
  warn: 2,
  error: 3,
};

class Logger {
  private level: number;

  constructor(level: string = "info") {
    this.level = LOG_LEVELS[level.toLowerCase()] || LOG_LEVELS.info;
  }

  debug(message: string): void {
    if (this.level <= LOG_LEVELS.debug) {
      console.debug(`[DEBUG] ${new Date().toISOString()} - ${message}`);
    }
  }

  info(message: string): void {
    if (this.level <= LOG_LEVELS.info) {
      console.info(`[INFO] ${new Date().toISOString()} - ${message}`);
    }
  }

  warn(message: string): void {
    if (this.level <= LOG_LEVELS.warn) {
      console.warn(`[WARN] ${new Date().toISOString()} - ${message}`);
    }
  }

  error(message: string): void {
    if (this.level <= LOG_LEVELS.error) {
      console.error(`[ERROR] ${new Date().toISOString()} - ${message}`);
    }
  }
}

import { config } from "../config";
export const logger = new Logger(config.logLevel);
