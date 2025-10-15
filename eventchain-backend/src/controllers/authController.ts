/**
 * Authentication Controller
 * 
 * This controller handles HTTP requests for authentication endpoints.
 * Controllers are the bridge between HTTP layer and business logic:
 * - Parse and validate incoming requests
 * - Call service layer for business logic
 * - Format and send HTTP responses
 * - Handle errors appropriately
 * 
 * Why separate controllers from services?
 * - Controllers handle HTTP concerns (req/res)
 * - Services handle business logic
 * - Makes code more testable and maintainable
 */

import { Response } from 'express';
import { AuthenticatedRequest } from '@/middleware/authMiddleware';
import {
    registerUser,
    loginUser,
    logoutUser,
    getUserById,
    updateUserProfile,
    changePassword,
    requestPasswordReset,
    resetPassword,
} from '@/services/authService';
import { asyncHandler } from '@/middleware/errorHandler';
import { logger, logBusinessEvent } from '@/config/logger';

/**
 * Register new user
 * 
 * POST /api/v1/auth/register
 * 
 * Request body:
 * - email: string (required)
 * - password: string (required)
 * - firstName: string (required)
 * - lastName: string (required)
 * - phone: string (optional)
 * - role: UserRole (optional, defaults to USER)
 * 
 * Response: 201 Created
 * - user: User object
 * - tokens: { accessToken, refreshToken }
 */
export const register = asyncHandler(
    async (req: AuthenticatedRequest, res: Response) => {
        const { email, password, firstName, lastName, phone, role } = req.body;

        logger.info('Registration request received', { email });

        // Call service layer to handle registration
        const result = await registerUser({
            email,
            password,
            firstName,
            lastName,
            phone,
            role,
        });

        // Log business event for analytics
        logBusinessEvent('user_registered', {
            userId: result.user.id,
            email: result.user.email,
            role: result.user.role,
        });

        // Send success response
        res.status(201).json({
            success: true,
            message: 'Registration successful',
            data: {
                user: result.user,
                tokens: result.tokens,
            },
        });
    }
);

/**
 * Login user
 * 
 * POST /api/v1/auth/login
 * 
 * Request body:
 * - email: string (required)
 * - password: string (required)
 * 
 * Response: 200 OK
 * - user: User object
 * - tokens: { accessToken, refreshToken }
 */
export const login = asyncHandler(
    async (req: AuthenticatedRequest, res: Response) => {
        const { email, password } = req.body;

        logger.info('Login request received', { email });

        // Call service layer to handle login
        const result = await loginUser({ email, password });

        // Log business event
        logBusinessEvent('user_logged_in', {
            userId: result.user.id,
            email: result.user.email,
        });

        // Send success response
        res.status(200).json({
            success: true,
            message: 'Login successful',
            data: {
                user: result.user,
                tokens: result.tokens,
            },
        });
    }
);

/**
 * Logout user
 * 
 * POST /api/v1/auth/logout
 * 
 * Headers:
 * - Authorization: Bearer <token> (required)
 * 
 * Response: 200 OK
 */
export const logout = asyncHandler(
    async (req: AuthenticatedRequest, res: Response) => {
        // User is already authenticated by middleware
        const userId = req.user!.id;
        const sessionId = req.user!.sessionId;

        logger.info('Logout request received', { userId, sessionId });

        // Revoke session
        await logoutUser(userId, sessionId);

        // Log business event
        logBusinessEvent('user_logged_out', { userId });

        // Send success response
        res.status(200).json({
            success: true,
            message: 'Logout successful',
        });
    }
);

/**
 * Get current user profile
 * 
 * GET /api/v1/auth/me
 * 
 * Headers:
 * - Authorization: Bearer <token> (required)
 * 
 * Response: 200 OK
 * - user: User object
 */
export const getProfile = asyncHandler(
    async (req: AuthenticatedRequest, res: Response) => {
        const userId = req.user!.id;

        logger.debug('Get profile request', { userId });

        // Get user data from service
        const user = await getUserById(userId);

        // Send success response
        res.status(200).json({
            success: true,
            data: { user },
        });
    }
);

/**
 * Update user profile
 * 
 * PUT /api/v1/auth/profile
 * 
 * Headers:
 * - Authorization: Bearer <token> (required)
 * 
 * Request body:
 * - firstName: string (optional)
 * - lastName: string (optional)
 * - phone: string (optional)
 * 
 * Response: 200 OK
 * - user: Updated user object
 */
export const updateProfile = asyncHandler(
    async (req: AuthenticatedRequest, res: Response) => {
        const userId = req.user!.id;
        const { firstName, lastName, phone } = req.body;

        logger.info('Update profile request', { userId });

        // Update user profile via service
        const user = await updateUserProfile(userId, {
            firstName,
            lastName,
            phone,
        });

        // Log business event
        logBusinessEvent('profile_updated', { userId });

        // Send success response
        res.status(200).json({
            success: true,
            message: 'Profile updated successfully',
            data: { user },
        });
    }
);

/**
 * Change password
 * 
 * POST /api/v1/auth/change-password
 * 
 * Headers:
 * - Authorization: Bearer <token> (required)
 * 
 * Request body:
 * - currentPassword: string (required)
 * - newPassword: string (required)
 * - confirmPassword: string (required)
 * 
 * Response: 200 OK
 */
export const changePasswordHandler = asyncHandler(
    async (req: AuthenticatedRequest, res: Response) => {
        const userId = req.user!.id;
        const { currentPassword, newPassword } = req.body;

        logger.info('Change password request', { userId });

        // Change password via service
        await changePassword(userId, currentPassword, newPassword);

        // Log business event
        logBusinessEvent('password_changed', { userId });

        // Send success response
        res.status(200).json({
            success: true,
            message: 'Password changed successfully. Please login again.',
        });
    }
);

/**
 * Request password reset
 * 
 * POST /api/v1/auth/forgot-password
 * 
 * Request body:
 * - email: string (required)
 * 
 * Response: 200 OK
 * - message: Instructions sent to email
 * 
 * Note: In production, this would send an email with reset link
 */
export const forgotPassword = asyncHandler(
    async (req: AuthenticatedRequest, res: Response) => {
        const { email } = req.body;

        logger.info('Password reset request', { email });

        // Request password reset via service
        const resetToken = await requestPasswordReset(email);

        // Log business event
        logBusinessEvent('password_reset_requested', { email });

        // In development, return the token directly
        // In production, only send confirmation message
        if (process.env.NODE_ENV === 'development') {
            res.status(200).json({
                success: true,
                message: 'Password reset instructions sent to your email',
                data: {
                    resetToken, // Only for development/testing
                },
            });
        } else {
            res.status(200).json({
                success: true,
                message: 'If an account with this email exists, a reset link has been sent',
            });
        }
    }
);

/**
 * Reset password with token
 * 
 * POST /api/v1/auth/reset-password
 * 
 * Request body:
 * - token: string (required)
 * - password: string (required)
 * - confirmPassword: string (required)
 * 
 * Response: 200 OK
 */
export const resetPasswordHandler = asyncHandler(
    async (req: AuthenticatedRequest, res: Response) => {
        const { token, password } = req.body;

        logger.info('Password reset confirmation');

        // Reset password via service
        await resetPassword(token, password);

        // Log business event
        logBusinessEvent('password_reset_completed', { token: '***' });

        // Send success response
        res.status(200).json({
            success: true,
            message: 'Password reset successful. You can now login with your new password.',
        });
    }
);

/**
 * Verify email (placeholder for future implementation)
 * 
 * GET /api/v1/auth/verify/:token
 * 
 * Response: 200 OK
 */
export const verifyEmail = asyncHandler(
    async (req: AuthenticatedRequest, res: Response) => {
        const { token } = req.params;

        // TODO: Implement email verification
        logger.info('Email verification request', { token });

        res.status(200).json({
            success: true,
            message: 'Email verification successful',
        });
    }
);

/**
 * Refresh access token
 * 
 * POST /api/v1/auth/refresh
 * 
 * Request body:
 * - refreshToken: string (required)
 * 
 * Response: 200 OK
 * - accessToken: New access token
 * 
 * Note: This allows getting a new access token without logging in again
 */
export const refreshToken = asyncHandler(
    async (req: AuthenticatedRequest, res: Response) => {
        const { refreshToken } = req.body;

        // TODO: Implement token refresh logic
        logger.info('Token refresh request');

        res.status(200).json({
            success: true,
            message: 'Token refresh endpoint - coming soon',
        });
    }
);
