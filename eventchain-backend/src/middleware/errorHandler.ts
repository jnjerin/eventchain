/**
 * Global Error Handling Middleware
 * 
 * This middleware catches all unhandled errors in our Express application
 * and returns consistent error responses to clients. It also logs errors
 * for debugging and monitoring.
 * 
 * Error Types Handled:
 * - Validation errors (400 Bad Request)
 * - Authentication errors (401 Unauthorized)
 * - Authorization errors (403 Forbidden)
 * - Not found errors (404 Not Found)
 * - Database errors (500 Internal Server Error)
 * - Hedera blockchain errors (502 Bad Gateway)
 */

import { Request, Response, NextFunction } from 'express';
import { Prisma } from '@prisma/client';
import { logger } from '@/config/logger';

/**
 * Custom error class for application-specific errors
 * Extends the standard Error class with HTTP status codes
 */
export class AppError extends Error {
    public readonly statusCode: number;
    public readonly isOperational: boolean;

    constructor(
        message: string,
        statusCode: number = 500,
        isOperational: boolean = true
    ) {
        super(message);
        this.statusCode = statusCode;
        this.isOperational = isOperational;

        // Maintain proper stack trace for debugging
        Error.captureStackTrace(this, this.constructor);
    }
}

/**
 * Common application errors with predefined status codes
 */
export class ValidationError extends AppError {
    constructor(message: string) {
        super(message, 400);
    }
}

export class AuthenticationError extends AppError {
    constructor(message: string = 'Authentication required') {
        super(message, 401);
    }
}

export class AuthorizationError extends AppError {
    constructor(message: string = 'Insufficient permissions') {
        super(message, 403);
    }
}

export class NotFoundError extends AppError {
    constructor(message: string = 'Resource not found') {
        super(message, 404);
    }
}

export class ConflictError extends AppError {
    constructor(message: string) {
        super(message, 409);
    }
}

export class HederaError extends AppError {
    constructor(message: string) {
        super(`Hedera blockchain error: ${message}`, 502);
    }
}

/**
 * Standard error response format
 * Consistent structure makes it easier for frontend to handle errors
 */
interface ErrorResponse {
    error: {
        message: string;
        code?: string;
        details?: any;
        timestamp: string;
        path: string;
        method: string;
        requestId?: string;
    };
}

/**
 * Main error handling middleware
 * This function is called whenever an error occurs in our Express routes
 * 
 * @param err - The error that occurred
 * @param req - Express request object
 * @param res - Express response object
 * @param next - Next middleware function
 */
export const errorHandler = (
    err: Error | AppError,
    req: Request,
    res: Response,
    next: NextFunction
): void => {
    // Generate unique request ID for tracking
    const requestId = req.headers['x-request-id'] || 
                     req.headers['x-correlation-id'] || 
                     Math.random().toString(36).substring(7);

    // Default error values
    let statusCode = 500;
    let message = 'Internal Server Error';
    let code: string | undefined;
    let details: any;

    // Handle different types of errors
    if (err instanceof AppError) {
        // Our custom application errors
        statusCode = err.statusCode;
        message = err.message;
        code = err.constructor.name;
    } else if (err instanceof Prisma.PrismaClientKnownRequestError) {
        // Database errors from Prisma
        const prismaError = handlePrismaError(err);
        statusCode = prismaError.statusCode;
        message = prismaError.message;
        code = prismaError.code;
    } else if (err instanceof Prisma.PrismaClientValidationError) {
        // Prisma validation errors
        statusCode = 400;
        message = 'Invalid request data';
        code = 'VALIDATION_ERROR';
        details = process.env.NODE_ENV === 'development' ? err.message : undefined;
    } else if (err.name === 'ValidationError') {
        // Joi validation errors
        statusCode = 400;
        message = err.message;
        code = 'VALIDATION_ERROR';
    } else if (err.name === 'JsonWebTokenError') {
        // JWT token errors
        statusCode = 401;
        message = 'Invalid authentication token';
        code = 'INVALID_TOKEN';
    } else if (err.name === 'TokenExpiredError') {
        // JWT token expiration
        statusCode = 401;
        message = 'Authentication token has expired';
        code = 'EXPIRED_TOKEN';
    } else if (err.name === 'CastError') {
        // MongoDB ObjectId casting errors (if using MongoDB)
        statusCode = 400;
        message = 'Invalid resource ID format';
        code = 'INVALID_ID';
    }

    // Log error details for debugging
    const errorLog = {
        requestId,
        error: {
            name: err.name,
            message: err.message,
            stack: err.stack,
        },
        request: {
            method: req.method,
            url: req.originalUrl,
            headers: req.headers,
            body: req.body,
            query: req.query,
            params: req.params,
            ip: req.ip,
            userAgent: req.get('User-Agent'),
        },
        statusCode,
    };

    // Log error based on severity
    if (statusCode >= 500) {
        logger.error('Server error occurred', errorLog);
    } else if (statusCode >= 400) {
        logger.warn('Client error occurred', errorLog);
    }

    // Prepare response
    const errorResponse: ErrorResponse = {
        error: {
            message,
            code,
            details,
            timestamp: new Date().toISOString(),
            path: req.originalUrl,
            method: req.method,
            requestId: requestId as string,
        },
    };

    // Remove sensitive information in production
    if (process.env.NODE_ENV === 'production') {
        // Don't expose internal error details
        if (statusCode >= 500) {
            errorResponse.error.message = 'Internal Server Error';
        }
        // Remove error details
        delete errorResponse.error.details;
    }

    // Send error response
    res.status(statusCode).json(errorResponse);
};

/**
 * Handle Prisma database errors
 * Maps Prisma error codes to HTTP status codes and user-friendly messages
 * 
 * @param err - Prisma error
 * @returns Formatted error details
 */
function handlePrismaError(err: Prisma.PrismaClientKnownRequestError): {
    statusCode: number;
    message: string;
    code: string;
} {
    switch (err.code) {
        case 'P2002':
            // Unique constraint violation
            const field = err.meta?.target as string[] | undefined;
            const fieldName = field?.[0] || 'field';
            return {
                statusCode: 409,
                message: `A record with this ${fieldName} already exists`,
                code: 'DUPLICATE_ENTRY',
            };
        
        case 'P2025':
            // Record not found
            return {
                statusCode: 404,
                message: 'The requested resource was not found',
                code: 'NOT_FOUND',
            };
        
        case 'P2003':
            // Foreign key constraint violation
            return {
                statusCode: 400,
                message: 'Invalid reference to related resource',
                code: 'INVALID_REFERENCE',
            };
        
        case 'P2014':
            // Required relation violation
            return {
                statusCode: 400,
                message: 'Required relationship is missing',
                code: 'MISSING_RELATION',
            };
        
        case 'P2011':
            // Null constraint violation
            return {
                statusCode: 400,
                message: 'Required field cannot be empty',
                code: 'REQUIRED_FIELD',
            };
        
        case 'P2012':
            // Missing required value
            return {
                statusCode: 400,
                message: 'Missing required field',
                code: 'MISSING_FIELD',
            };
        
        default:
            // Generic database error
            return {
                statusCode: 500,
                message: 'Database operation failed',
                code: 'DATABASE_ERROR',
            };
    }
}

/**
 * Async error wrapper
 * Wraps async route handlers to catch promise rejections
 * and pass them to the error handler
 * 
 * @param fn - Async route handler function
 * @returns Wrapped function that catches errors
 */
export const asyncHandler = (
    fn: (req: Request, res: Response, next: NextFunction) => Promise<any>
) => {
    return (req: Request, res: Response, next: NextFunction) => {
        Promise.resolve(fn(req, res, next)).catch(next);
    };
};

/**
 * 404 handler for routes that don't exist
 * This should be added after all route definitions
 * 
 * @param req - Express request object
 * @param res - Express response object
 * @param next - Next middleware function
 */
export const notFoundHandler = (
    req: Request,
    res: Response,
    next: NextFunction
): void => {
    const error = new NotFoundError(`Route ${req.method} ${req.originalUrl} not found`);
    next(error);
};

/**
 * Process uncaught exceptions and unhandled promise rejections
 * These should ideally never happen, but we want to log them
 */
export const setupGlobalErrorHandlers = (): void => {
    // Handle uncaught exceptions
    process.on('uncaughtException', (error: Error) => {
        logger.error('Uncaught Exception - shutting down gracefully', {
            error: {
                name: error.name,
                message: error.message,
                stack: error.stack,
            },
        });
        
        // Close server gracefully
        process.exit(1);
    });

    // Handle unhandled promise rejections
    process.on('unhandledRejection', (reason: any, promise: Promise<any>) => {
        logger.error('Unhandled Promise Rejection - shutting down gracefully', {
            reason,
            promise,
        });
        
        // Close server gracefully
        process.exit(1);
    });
};
