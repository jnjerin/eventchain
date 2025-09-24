/**
 * EventChain Backend Server Entry Point
 * 
 * This file initializes and starts the Express server with all necessary
 * middleware, routes, and error handlers. It serves as the main entry point
 * for our Web3 ticketing platform backend.
 * 
 * Key responsibilities:
 * - Initialize Express app with security middleware
 * - Connect to PostgreSQL database via Prisma
 * - Set up API routes for authentication, events, tickets, loyalty
 * - Configure error handling and logging
 * - Start server on specified port
 */

import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import dotenv from 'dotenv';
import { createServer } from 'http';

// Import internal modules
import { logger } from '@/config/logger';
import { connectDatabase } from '@/config/database';
import { errorHandler } from '@/middleware/errorHandler';

// Import route modules
import authRoutes from '@/routes/authRoutes';
import eventRoutes from '@/routes/eventRoutes';
import ticketRoutes from '@/routes/ticketRoutes';
import loyaltyRoutes from '@/routes/loyaltyRoutes';
import smsRoutes from '@/routes/smsRoutes';

// Load environment variables
dotenv.config();

/**
 * Create Express application instance
 * We use express() to create our main app that will handle all HTTP requests
 */
const app = express();

// Get port from environment or default to 3001
const PORT = process.env.PORT || 3001;

/**
 * Security Middleware Configuration
 * 
 * These middleware functions protect our API from common vulnerabilities:
 * - helmet(): Sets security headers like CSP, HSTS, X-Frame-Options
 * - cors(): Enables cross-origin requests from our frontend
 * - rateLimit(): Prevents abuse by limiting requests per IP
 */
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'"],
            scriptSrc: ["'self'"],
            imgSrc: ["'self'", "data:", "https:"],
        },
    },
}));

app.use(cors({
    origin: process.env.FRONTEND_URL || 'http://localhost:3000',
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
}));

// Rate limiting - max 100 requests per 15 minutes per IP
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // limit each IP to 100 requests per windowMs
    message: {
        error: 'Too many requests from this IP, please try again later.',
        retryAfter: '15 minutes'
    },
    standardHeaders: true, // Return rate limit info in the `RateLimit-*` headers
    legacyHeaders: false, // Disable the `X-RateLimit-*` headers
});
app.use('/api/', limiter);

/**
 * Body parsing middleware
 * These enable our API to parse different types of request bodies:
 * - JSON payloads (most common for our API)
 * - URL-encoded form data
 * - Raw text for webhooks
 */
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

/**
 * API Routes Configuration
 * 
 * All our API endpoints are prefixed with /api/v1 for versioning.
 * This allows us to introduce breaking changes in v2 while maintaining v1.
 */
const API_PREFIX = '/api/v1';

app.use(`${API_PREFIX}/auth`, authRoutes);
app.use(`${API_PREFIX}/events`, eventRoutes);
app.use(`${API_PREFIX}/tickets`, ticketRoutes);
app.use(`${API_PREFIX}/loyalty`, loyaltyRoutes);
app.use(`${API_PREFIX}/sms`, smsRoutes);

/**
 * Health check endpoint
 * Used by load balancers and monitoring systems to check if the server is alive
 */
app.get('/health', (req, res) => {
    res.status(200).json({
        status: 'healthy',
        timestamp: new Date().toISOString(),
        uptime: process.uptime(),
        environment: process.env.NODE_ENV || 'development'
    });
});

/**
 * Root endpoint with API documentation
 */
app.get('/', (req, res) => {
    res.json({
        message: 'EventChain Backend API',
        version: '1.0.0',
        documentation: '/api/v1/docs',
        health: '/health',
        endpoints: {
            auth: `${API_PREFIX}/auth`,
            events: `${API_PREFIX}/events`,
            tickets: `${API_PREFIX}/tickets`,
            loyalty: `${API_PREFIX}/loyalty`,
            sms: `${API_PREFIX}/sms`
        }
    });
});

/**
 * 404 handler for unknown routes
 */
app.use('*', (req, res) => {
    res.status(404).json({
        error: 'Route not found',
        message: `Cannot ${req.method} ${req.originalUrl}`,
        availableRoutes: [
            `${API_PREFIX}/auth`,
            `${API_PREFIX}/events`,
            `${API_PREFIX}/tickets`,
            `${API_PREFIX}/loyalty`,
            `${API_PREFIX}/sms`
        ]
    });
});

/**
 * Global error handling middleware
 * This catches any unhandled errors and returns a consistent error response
 */
app.use(errorHandler);

/**
 * Initialize server and start listening
 */
async function startServer() {
    try {
        // Connect to database before starting the server
        logger.info('Connecting to database...');
        await connectDatabase();
        
        // Create HTTP server instance
        const server = createServer(app);
        
        // Start listening on the specified port
        server.listen(PORT, () => {
            logger.info(`🚀 EventChain Backend running on port ${PORT}`);
            logger.info(`📚 API Documentation: http://localhost:${PORT}/`);
            logger.info(`🔍 Health Check: http://localhost:${PORT}/health`);
            logger.info(`🌍 Environment: ${process.env.NODE_ENV || 'development'}`);
        });

        // Graceful shutdown handling
        const gracefulShutdown = (signal: string) => {
            logger.info(`Received ${signal}. Starting graceful shutdown...`);
            
            server.close(() => {
                logger.info('HTTP server closed.');
                process.exit(0);
            });

            // Force shutdown after 30 seconds
            setTimeout(() => {
                logger.error('Could not close connections in time, forcefully shutting down');
                process.exit(1);
            }, 30000);
        };

        // Listen for termination signals
        process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
        process.on('SIGINT', () => gracefulShutdown('SIGINT'));

    } catch (error) {
        logger.error('Failed to start server:', error);
        process.exit(1);
    }
}

// Start the server
if (require.main === module) {
    startServer();
}

export default app;
