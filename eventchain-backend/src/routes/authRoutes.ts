/**
 * Authentication Routes
 * 
 * Handles user registration, login, logout, and password management.
 * These routes are the entry point for user authentication in our system.
 * 
 * Route Structure:
 * - Public routes: register, login, forgot-password, reset-password
 * - Protected routes: logout, profile, change-password (require authentication)
 */

import { Router } from 'express';
import {
    register,
    login,
    logout,
    getProfile,
    updateProfile,
    changePasswordHandler,
    forgotPassword,
    resetPasswordHandler,
    verifyEmail,
    refreshToken,
} from '@/controllers/authController';
import { authenticate } from '@/middleware/authMiddleware';
import {
    validate,
    registerSchema,
    loginSchema,
    updateProfileSchema,
    changePasswordSchema,
    forgotPasswordSchema,
    resetPasswordSchema,
} from '@/utils/validators';

const router = Router();

// ==============================================================================
// PUBLIC ROUTES - No authentication required
// ==============================================================================

/**
 * POST /api/v1/auth/register
 * Register a new user account
 * 
 * Body: { email, password, firstName, lastName, phone?, role? }
 * Returns: User object and JWT tokens
 */
router.post('/register', validate(registerSchema), register);

/**
 * POST /api/v1/auth/login
 * Login with email and password
 * 
 * Body: { email, password }
 * Returns: User object and JWT tokens
 */
router.post('/login', validate(loginSchema), login);

/**
 * POST /api/v1/auth/forgot-password
 * Request password reset
 * 
 * Body: { email }
 * Returns: Success message (reset link sent to email)
 */
router.post('/forgot-password', validate(forgotPasswordSchema), forgotPassword);

/**
 * POST /api/v1/auth/reset-password
 * Reset password with token
 * 
 * Body: { token, password, confirmPassword }
 * Returns: Success message
 */
router.post('/reset-password', validate(resetPasswordSchema), resetPasswordHandler);

/**
 * GET /api/v1/auth/verify/:token
 * Verify email address
 * 
 * Params: { token }
 * Returns: Success message
 */
router.get('/verify/:token', verifyEmail);

/**
 * POST /api/v1/auth/refresh
 * Refresh access token
 * 
 * Body: { refreshToken }
 * Returns: New access token
 */
router.post('/refresh', refreshToken);

// ==============================================================================
// PROTECTED ROUTES - Authentication required
// ==============================================================================

/**
 * POST /api/v1/auth/logout
 * Logout user (revoke session)
 * 
 * Headers: Authorization: Bearer <token>
 * Returns: Success message
 */
router.post('/logout', authenticate, logout);

/**
 * GET /api/v1/auth/me
 * Get current user profile
 * 
 * Headers: Authorization: Bearer <token>
 * Returns: User object
 */
router.get('/me', authenticate, getProfile);

/**
 * PUT /api/v1/auth/profile
 * Update user profile
 * 
 * Headers: Authorization: Bearer <token>
 * Body: { firstName?, lastName?, phone? }
 * Returns: Updated user object
 */
router.put('/profile', authenticate, validate(updateProfileSchema), updateProfile);

/**
 * POST /api/v1/auth/change-password
 * Change password
 * 
 * Headers: Authorization: Bearer <token>
 * Body: { currentPassword, newPassword, confirmPassword }
 * Returns: Success message
 */
router.post(
    '/change-password',
    authenticate,
    validate(changePasswordSchema),
    changePasswordHandler
);

export default router;
