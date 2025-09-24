/**
 * Database Configuration and Connection Management
 * 
 * This module handles database connectivity using Prisma ORM.
 * Prisma provides type-safe database access and automatic migrations.
 * 
 * Key features:
 * - Connection pooling for optimal performance
 * - Automatic reconnection on connection loss
 * - Query logging for debugging
 * - Graceful shutdown handling
 */

import { PrismaClient } from '@prisma/client';
import { logger } from './logger';

/**
 * Global Prisma client instance
 * We use a singleton pattern to ensure we don't create multiple connections
 */
let prisma: PrismaClient;

/**
 * Prisma client configuration based on environment
 */
const prismaConfig = {
    // Enable query logging in development
    log: process.env.NODE_ENV === 'development' 
        ? ['query', 'info', 'warn', 'error'] as const
        : ['info', 'warn', 'error'] as const,
    
    // Error formatting for better debugging
    errorFormat: 'pretty' as const,
};

/**
 * Initialize Prisma client with error handling and logging
 * 
 * @returns Configured Prisma client instance
 */
function createPrismaClient(): PrismaClient {
    const client = new PrismaClient(prismaConfig);

    // Custom query logging for better insights
    client.$on('query' as never, (event: any) => {
        logger.debug('Database Query', {
            query: event.query,
            params: event.params,
            duration: `${event.duration}ms`,
            target: event.target,
        });
    });

    // Log slow queries (>1000ms) as warnings
    client.$on('query' as never, (event: any) => {
        if (event.duration > 1000) {
            logger.warn('Slow database query detected', {
                query: event.query,
                duration: `${event.duration}ms`,
                params: event.params,
            });
        }
    });

    return client;
}

/**
 * Get or create Prisma client instance
 * Uses singleton pattern to prevent multiple database connections
 * 
 * @returns Prisma client instance
 */
export function getPrismaClient(): PrismaClient {
    if (!prisma) {
        prisma = createPrismaClient();
    }
    return prisma;
}

/**
 * Connect to the database and verify the connection
 * This function should be called during application startup
 * 
 * @returns Promise that resolves when connection is established
 */
export async function connectDatabase(): Promise<void> {
    try {
        // Get or create client
        if (!prisma) {
            prisma = createPrismaClient();
        }

        // Test the connection
        await prisma.$connect();
        logger.info('✅ Database connected successfully');

        // Verify we can query the database
        await prisma.$queryRaw`SELECT 1 as connection_test`;
        logger.info('✅ Database query test successful');

    } catch (error) {
        logger.error('❌ Database connection failed:', error);
        
        // In development, provide helpful error messages
        if (process.env.NODE_ENV === 'development') {
            logger.error('💡 Make sure PostgreSQL is running and DATABASE_URL is correct');
            logger.error('💡 Run "npm run migrate" to ensure database schema is up to date');
        }
        
        throw error;
    }
}

/**
 * Gracefully disconnect from the database
 * This function should be called during application shutdown
 * 
 * @returns Promise that resolves when disconnection is complete
 */
export async function disconnectDatabase(): Promise<void> {
    try {
        if (prisma) {
            await prisma.$disconnect();
            logger.info('✅ Database disconnected successfully');
        }
    } catch (error) {
        logger.error('❌ Error during database disconnection:', error);
        throw error;
    }
}

/**
 * Health check for database connectivity
 * Used by health check endpoints to verify database is accessible
 * 
 * @returns Promise that resolves to connection status
 */
export async function checkDatabaseHealth(): Promise<{
    status: 'healthy' | 'unhealthy';
    latency?: number;
    error?: string;
}> {
    try {
        const startTime = Date.now();
        
        // Simple query to test connectivity
        await prisma.$queryRaw`SELECT 1 as health_check`;
        
        const latency = Date.now() - startTime;
        
        return {
            status: 'healthy',
            latency,
        };
    } catch (error) {
        logger.error('Database health check failed:', error);
        return {
            status: 'unhealthy',
            error: error instanceof Error ? error.message : 'Unknown database error',
        };
    }
}

/**
 * Execute database operations with retry logic
 * Useful for operations that might fail due to temporary connectivity issues
 * 
 * @param operation - Function that performs database operation
 * @param maxRetries - Maximum number of retry attempts
 * @param retryDelay - Delay between retries in milliseconds
 * @returns Promise with operation result
 */
export async function withRetry<T>(
    operation: () => Promise<T>,
    maxRetries: number = 3,
    retryDelay: number = 1000
): Promise<T> {
    let lastError: Error;

    for (let attempt = 1; attempt <= maxRetries; attempt++) {
        try {
            return await operation();
        } catch (error) {
            lastError = error as Error;
            
            if (attempt === maxRetries) {
                logger.error(`Database operation failed after ${maxRetries} attempts:`, error);
                throw error;
            }

            logger.warn(`Database operation failed (attempt ${attempt}/${maxRetries}), retrying...`, {
                error: error instanceof Error ? error.message : error,
                nextRetryIn: `${retryDelay}ms`
            });

            // Wait before retrying
            await new Promise(resolve => setTimeout(resolve, retryDelay));
        }
    }

    throw lastError!;
}

/**
 * Transaction helper with automatic rollback on errors
 * Ensures data consistency when performing multiple database operations
 * 
 * @param operations - Function containing database operations to run in transaction
 * @returns Promise with transaction result
 */
export async function runTransaction<T>(
    operations: (tx: PrismaClient) => Promise<T>
): Promise<T> {
    try {
        return await prisma.$transaction(async (tx) => {
            logger.debug('Starting database transaction');
            const result = await operations(tx);
            logger.debug('Database transaction completed successfully');
            return result;
        });
    } catch (error) {
        logger.error('Database transaction failed, rolling back:', error);
        throw error;
    }
}

// Export the client for direct access when needed
export { prisma };

// Default export for convenience
export default getPrismaClient;
