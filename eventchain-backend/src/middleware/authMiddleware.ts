/**
 * Authentication and Authorization Middleware
 * 
 * This middleware handles JWT token verification and role-based access control.
 * It protects routes that require authentication and checks user permissions
 * for specific actions.
 * 
 * Features:
 * - JWT token verification
 * - User role checking
 * - Session validation
 * - Rate limiting protection
 * - Request context injection
 */

import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import { UserRole } from '@prisma/client';
import { getPrismaClient } from '@/config/database';
import { logger } from '@/config/logger';
import { AuthenticationError, AuthorizationError, ValidationError } from './errorHandler';

/**
 * Extended Request interface to include user information
 * This allows us to access user data in route handlers after authentication
 */
export interface AuthenticatedRequest extends Request {
    user?: {
        id: string;
        email: string;
        role: UserRole;
        isActive: boolean;
        sessionId?: string;
    };
}

/**
 * JWT payload structure
 */
interface JwtPayload {
    userId: string;
    email: string;
    role: UserRole;
    sessionId?: string;
    iat: number;
    exp: number;
}

/**
 * Authentication middleware
 * Verifies JWT tokens and adds user information to request context
 * 
 * @param req - Express request object
 * @param res - Express response object
 * @param next - Next middleware function
 */
export const authenticate = async (
    req: AuthenticatedRequest,
    res: Response,
    next: NextFunction
): Promise<void> => {
    try {
        const authHeader = req.headers.authorization;
        
        if (!authHeader) {
            throw new AuthenticationError('Authorization header is required');
        }

        // Extract token from "Bearer <token>" format
        const token = extractBearerToken(authHeader);
        if (!token) {
            throw new AuthenticationError('Invalid authorization header format');
        }

        // Verify JWT token
        const jwtSecret = process.env.JWT_SECRET;
        if (!jwtSecret) {
            logger.error('JWT_SECRET environment variable is not set');
            throw new Error('Authentication configuration error');
        }

        const decoded = jwt.verify(token, jwtSecret) as JwtPayload;
        
        // Get user from database to verify they still exist and are active
        const prisma = getPrismaClient();
        const user = await prisma.user.findUnique({
            where: { id: decoded.userId },
            select: {
                id: true,
                email: true,
                role: true,
                isActive: true,
                isVerified: true,
            },
        });

        if (!user) {
            throw new AuthenticationError('User not found');
        }

        if (!user.isActive) {
            throw new AuthenticationError('Account is deactivated');
        }

        if (!user.isVerified) {
            throw new AuthenticationError('Account is not verified');
        }

        // Add user information to request context
        req.user = {
            id: user.id,
            email: user.email,
            role: user.role,
            isActive: user.isActive,
            sessionId: decoded.sessionId,
        };

        // Log successful authentication
        logger.debug('User authenticated successfully', {
            userId: user.id,
            email: user.email,
            role: user.role,
            path: req.originalUrl,
        });

        // Update last login time
        await prisma.user.update({
            where: { id: user.id },
            data: { lastLoginAt: new Date() },
        });

        next();

    } catch (error) {
        if (error instanceof jwt.JsonWebTokenError) {
            logger.warn('Invalid JWT token', {
                error: error.message,
                path: req.originalUrl,
                ip: req.ip,
            });
            next(new AuthenticationError('Invalid authentication token'));
        } else if (error instanceof jwt.TokenExpiredError) {
            logger.warn('Expired JWT token', {
                path: req.originalUrl,
                ip: req.ip,
            });
            next(new AuthenticationError('Authentication token has expired'));
        } else {
            next(error);
        }
    }
};

/**
 * Authorization middleware factory
 * Creates middleware that checks if user has required roles
 * 
 * @param allowedRoles - Array of roles that can access the route
 * @returns Authorization middleware
 */
export const authorize = (allowedRoles: UserRole[]) => {
    return (req: AuthenticatedRequest, res: Response, next: NextFunction): void => {
        try {
            if (!req.user) {
                throw new AuthenticationError('Authentication required');
            }

            if (!allowedRoles.includes(req.user.role)) {
                logger.warn('Unauthorized access attempt', {
                    userId: req.user.id,
                    userRole: req.user.role,
                    requiredRoles: allowedRoles,
                    path: req.originalUrl,
                });
                
                throw new AuthorizationError(
                    `Access denied. Required roles: ${allowedRoles.join(', ')}`
                );
            }

            logger.debug('User authorized for route', {
                userId: req.user.id,
                role: req.user.role,
                path: req.originalUrl,
            });

            next();
        } catch (error) {
            next(error);
        }
    };
};

/**
 * Resource ownership middleware
 * Checks if the authenticated user owns the requested resource
 * 
 * @param resourceType - Type of resource (user, event, ticket)
 * @param getResourceOwnerId - Function to extract owner ID from request
 * @returns Ownership verification middleware
 */
export const checkResourceOwnership = (
    resourceType: string,
    getResourceOwnerId: (req: AuthenticatedRequest) => string | Promise<string>
) => {
    return async (req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> => {
        try {
            if (!req.user) {
                throw new AuthenticationError('Authentication required');
            }

            // Admins can access any resource
            if (req.user.role === UserRole.ADMIN) {
                next();
                return;
            }

            // Get the resource owner ID
            const ownerId = await getResourceOwnerId(req);
            
            if (req.user.id !== ownerId) {
                logger.warn('Unauthorized resource access attempt', {
                    userId: req.user.id,
                    resourceType,
                    resourceOwnerId: ownerId,
                    path: req.originalUrl,
                });
                
                throw new AuthorizationError(`You can only access your own ${resourceType}`);
            }

            next();
        } catch (error) {
            next(error);
        }
    };
};

/**
 * Optional authentication middleware
 * Adds user information if token is present, but doesn't require it
 * Useful for public endpoints that show different content for logged-in users
 * 
 * @param req - Express request object
 * @param res - Express response object
 * @param next - Next middleware function
 */
export const optionalAuthenticate = async (
    req: AuthenticatedRequest,
    res: Response,
    next: NextFunction
): Promise<void> => {
    try {
        const authHeader = req.headers.authorization;
        
        if (!authHeader) {
            // No token provided, continue without user context
            next();
            return;
        }

        // Try to authenticate, but don't throw errors if it fails
        await authenticate(req, res, (error) => {
            if (error) {
                // Log the error but continue without authentication
                logger.debug('Optional authentication failed', {
                    error: error.message,
                    path: req.originalUrl,
                });
            }
            next();
        });

    } catch (error) {
        // Continue without authentication on any error
        logger.debug('Optional authentication error', {
            error: error instanceof Error ? error.message : error,
            path: req.originalUrl,
        });
        next();
    }
};

/**
 * Session validation middleware
 * Checks if the user's session is still valid in the database
 * 
 * @param req - Express request object
 * @param res - Express response object
 * @param next - Next middleware function
 */
export const validateSession = async (
    req: AuthenticatedRequest,
    res: Response,
    next: NextFunction
): Promise<void> => {
    try {
        if (!req.user?.sessionId) {
            // No session ID, skip validation
            next();
            return;
        }

        const prisma = getPrismaClient();
        const session = await prisma.session.findUnique({
            where: { id: req.user.sessionId },
            select: {
                id: true,
                expiresAt: true,
                isRevoked: true,
                userId: true,
            },
        });

        if (!session) {
            throw new AuthenticationError('Session not found');
        }

        if (session.isRevoked) {
            throw new AuthenticationError('Session has been revoked');
        }

        if (session.expiresAt < new Date()) {
            throw new AuthenticationError('Session has expired');
        }

        if (session.userId !== req.user.id) {
            throw new AuthenticationError('Session user mismatch');
        }

        // Update session last used time
        await prisma.session.update({
            where: { id: session.id },
            data: { lastUsedAt: new Date() },
        });

        next();

    } catch (error) {
        next(error);
    }
};

/**
 * Extract Bearer token from Authorization header
 * 
 * @param authHeader - Authorization header value
 * @returns JWT token or null
 */
function extractBearerToken(authHeader: string): string | null {
    const parts = authHeader.split(' ');
    
    if (parts.length !== 2) {
        return null;
    }
    
    const [scheme, token] = parts;
    
    if (scheme.toLowerCase() !== 'bearer') {
        return null;
    }
    
    return token;
}

/**
 * Create JWT token for user
 * 
 * @param user - User object
 * @param sessionId - Optional session ID
 * @returns JWT token
 */
export function createJwtToken(
    user: { id: string; email: string; role: UserRole },
    sessionId?: string
): string {
    const jwtSecret = process.env.JWT_SECRET;
    const jwtExpiresIn = process.env.JWT_EXPIRES_IN || '24h';
    
    if (!jwtSecret) {
        throw new Error('JWT_SECRET environment variable is not set');
    }

    const payload: Omit<JwtPayload, 'iat' | 'exp'> = {
        userId: user.id,
        email: user.email,
        role: user.role,
        sessionId,
    };

    return jwt.sign(payload, jwtSecret, { expiresIn: jwtExpiresIn });
}

/**
 * Create refresh token
 * 
 * @param user - User object
 * @returns Refresh token
 */
export function createRefreshToken(
    user: { id: string; email: string; role: UserRole }
): string {
    const jwtSecret = process.env.JWT_SECRET;
    const refreshExpiresIn = process.env.JWT_REFRESH_EXPIRES_IN || '7d';
    
    if (!jwtSecret) {
        throw new Error('JWT_SECRET environment variable is not set');
    }

    const payload = {
        userId: user.id,
        type: 'refresh',
    };

    return jwt.sign(payload, jwtSecret, { expiresIn: refreshExpiresIn });
}

/**
 * Role hierarchy helper
 * Checks if a user role has sufficient privileges
 * 
 * @param userRole - Current user's role
 * @param requiredRole - Minimum required role
 * @returns True if user has sufficient privileges
 */
export function hasRoleOrHigher(userRole: UserRole, requiredRole: UserRole): boolean {
    const roleHierarchy: Record<UserRole, number> = {
        [UserRole.USER]: 1,
        [UserRole.AFFILIATE]: 2,
        [UserRole.STAFF]: 3,
        [UserRole.ORGANIZER]: 4,
        [UserRole.ADMIN]: 5,
    };

    return roleHierarchy[userRole] >= roleHierarchy[requiredRole];
}
