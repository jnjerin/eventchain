/**
 * Winston Logger Configuration
 * 
 * This module sets up structured logging for our application using Winston.
 * Proper logging is crucial for debugging, monitoring, and maintaining
 * a production application.
 * 
 * Features:
 * - Different log levels (error, warn, info, debug)
 * - JSON formatting for production (easier to parse)
 * - Console output for development (human-readable)
 * - File rotation to prevent disk space issues
 * - Request ID tracking for tracing requests through the system
 */

import winston from 'winston';
import path from 'path';

// Define log levels with colors for console output
const logLevels = {
    error: 0,
    warn: 1,
    info: 2,
    http: 3,
    debug: 4,
};

const logColors = {
    error: 'red',
    warn: 'yellow',
    info: 'green',
    http: 'magenta',
    debug: 'white',
};

// Add colors to winston
winston.addColors(logColors);

/**
 * Custom log format for development
 * Shows timestamp, level, and message in a readable format
 */
const developmentFormat = winston.format.combine(
    winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
    winston.format.colorize({ all: true }),
    winston.format.printf(
        (info) => `${info.timestamp} ${info.level}: ${info.message}`
    )
);

/**
 * JSON format for production
 * Structured logs are easier to parse and analyze with tools like ELK stack
 */
const productionFormat = winston.format.combine(
    winston.format.timestamp(),
    winston.format.errors({ stack: true }),
    winston.format.json()
);

/**
 * Configure transports (where logs are written)
 * - Console: Always available for real-time monitoring
 * - File: For persistent storage and analysis
 */
const transports: winston.transport[] = [
    // Console transport - always enabled
    new winston.transports.Console({
        format: process.env.NODE_ENV === 'production' ? productionFormat : developmentFormat,
    }),
];

// Add file transports for production
if (process.env.NODE_ENV === 'production') {
    // Error logs - separate file for quick error analysis
    transports.push(
        new winston.transports.File({
            filename: path.join(process.cwd(), 'logs', 'error.log'),
            level: 'error',
            format: productionFormat,
            maxsize: 5242880, // 5MB
            maxFiles: 5,
        })
    );

    // Combined logs - all log levels
    transports.push(
        new winston.transports.File({
            filename: path.join(process.cwd(), 'logs', 'combined.log'),
            format: productionFormat,
            maxsize: 5242880, // 5MB
            maxFiles: 5,
        })
    );
}

/**
 * Create the main logger instance
 */
const logger = winston.createLogger({
    level: process.env.LOG_LEVEL || (process.env.NODE_ENV === 'development' ? 'debug' : 'info'),
    levels: logLevels,
    format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.errors({ stack: true }),
        winston.format.metadata({ fillExcept: ['message', 'level', 'timestamp', 'label'] })
    ),
    transports,
    // Don't exit on handled exceptions
    exitOnError: false,
});

/**
 * Create a stream object for Morgan HTTP request logging
 * This allows us to integrate HTTP request logs with our main logger
 */
const morganStream = {
    write: (message: string) => {
        // Remove trailing newline and log as HTTP level
        logger.http(message.trim());
    },
};

/**
 * Helper function to create child loggers with additional context
 * Useful for adding request IDs or module names to logs
 * 
 * @param context - Additional context to add to all log messages
 * @returns Child logger instance
 */
const createChildLogger = (context: Record<string, any>) => {
    return logger.child(context);
};

/**
 * Helper function to log API request/response for debugging
 * 
 * @param req - Express request object
 * @param res - Express response object
 * @param responseTime - Time taken to process request
 */
const logApiRequest = (req: any, res: any, responseTime?: number) => {
    const logData = {
        method: req.method,
        url: req.originalUrl,
        status: res.statusCode,
        userAgent: req.get('User-Agent'),
        ip: req.ip || req.connection.remoteAddress,
        responseTime: responseTime ? `${responseTime}ms` : undefined,
    };

    if (res.statusCode >= 400) {
        logger.warn('API Request failed', logData);
    } else {
        logger.info('API Request completed', logData);
    }
};

/**
 * Helper function to log Hedera blockchain operations
 * 
 * @param operation - Type of operation (mint, transfer, etc.)
 * @param details - Operation details
 */
const logHederaOperation = (operation: string, details: Record<string, any>) => {
    logger.info(`Hedera ${operation}`, {
        ...details,
        service: 'hedera',
    });
};

/**
 * Helper function to log business events
 * Used for tracking important business metrics and events
 * 
 * @param event - Event name
 * @param data - Event data
 */
const logBusinessEvent = (event: string, data: Record<string, any>) => {
    logger.info(`Business Event: ${event}`, {
        ...data,
        eventType: 'business',
    });
};

// Export logger and utilities
export {
    logger,
    morganStream,
    createChildLogger,
    logApiRequest,
    logHederaOperation,
    logBusinessEvent,
};

// Export default logger for simple imports
export default logger;
