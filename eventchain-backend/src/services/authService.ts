/**
 * Authentication Service
 * 
 * This service handles all authentication-related business logic:
 * - User registration with password hashing
 * - Login with JWT token generation
 * - Password reset functionality
 * - Session management
 * 
 * Why separate service layer?
 * - Keeps controllers thin and focused on HTTP concerns
 * - Business logic can be reused across different endpoints
 * - Easier to test business logic in isolation
 * - Clear separation of concerns
 */

import bcrypt from 'bcryptjs';
import { User, UserRole, Prisma } from '@prisma/client';
import { getPrismaClient } from '@/config/database';
import { logger } from '@/config/logger';
import { createJwtToken, createRefreshToken } from '@/middleware/authMiddleware';
import {
    AuthenticationError,
    ValidationError,
    ConflictError,
    NotFoundError,
} from '@/middleware/errorHandler';

/**
 * User registration data transfer object
 */
interface RegisterUserDto {
    email: string;
    password: string;
    firstName: string;
    lastName: string;
    phone?: string;
    role?: UserRole;
}

/**
 * User login data transfer object
 */
interface LoginUserDto {
    email: string;
    password: string;
}

/**
 * Authentication response with user and tokens
 */
interface AuthResponse {
    user: {
        id: string;
        email: string;
        firstName: string;
        lastName: string;
        role: UserRole;
        isVerified: boolean;
    };
    tokens: {
        accessToken: string;
        refreshToken: string;
    };
}

/**
 * Register a new user
 * 
 * Steps:
 * 1. Check if email already exists (prevent duplicates)
 * 2. Hash the password securely with bcrypt
 * 3. Create user in database
 * 4. Generate JWT access and refresh tokens
 * 5. Create session record for token tracking
 * 6. Return user data and tokens
 * 
 * @param userData - User registration data
 * @returns User object and authentication tokens
 */
export async function registerUser(userData: RegisterUserDto): Promise<AuthResponse> {
    const prisma = getPrismaClient();

    try {
        // Step 1: Check if user already exists
        const existingUser = await prisma.user.findUnique({
            where: { email: userData.email.toLowerCase() },
        });

        if (existingUser) {
            logger.warn('Registration attempt with existing email', {
                email: userData.email,
            });
            throw new ConflictError('An account with this email already exists');
        }

        // Step 2: Hash password using bcrypt
        // Salt rounds = 10 (good balance between security and performance)
        const hashedPassword = await bcrypt.hash(userData.password, 10);

        logger.info('Creating new user account', {
            email: userData.email,
            role: userData.role || UserRole.USER,
        });

        // Step 3: Create user in database
        const user = await prisma.user.create({
            data: {
                email: userData.email.toLowerCase(),
                password: hashedPassword,
                firstName: userData.firstName,
                lastName: userData.lastName,
                phone: userData.phone,
                role: userData.role || UserRole.USER,
                isActive: true,
                isVerified: false, // Email verification needed
            },
            select: {
                id: true,
                email: true,
                firstName: true,
                lastName: true,
                role: true,
                isVerified: true,
                createdAt: true,
            },
        });

        // Step 4: Generate JWT tokens
        const accessToken = createJwtToken(user);
        const refreshToken = createRefreshToken(user);

        // Step 5: Create session record
        const session = await prisma.session.create({
            data: {
                userId: user.id,
                token: accessToken,
                refreshToken: refreshToken,
                expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000), // 7 days
            },
        });

        logger.info('User registered successfully', {
            userId: user.id,
            email: user.email,
            sessionId: session.id,
        });

        // Step 6: Return user and tokens
        return {
            user: {
                id: user.id,
                email: user.email,
                firstName: user.firstName,
                lastName: user.lastName,
                role: user.role,
                isVerified: user.isVerified,
            },
            tokens: {
                accessToken,
                refreshToken,
            },
        };

    } catch (error) {
        logger.error('User registration failed', { error });
        throw error;
    }
}

/**
 * Login user with email and password
 * 
 * Steps:
 * 1. Find user by email
 * 2. Verify password using bcrypt
 * 3. Check account status (active, verified)
 * 4. Generate new JWT tokens
 * 5. Create new session
 * 6. Update last login timestamp
 * 7. Return user data and tokens
 * 
 * @param credentials - Login credentials (email and password)
 * @returns User object and authentication tokens
 */
export async function loginUser(credentials: LoginUserDto): Promise<AuthResponse> {
    const prisma = getPrismaClient();

    try {
        // Step 1: Find user by email
        const user = await prisma.user.findUnique({
            where: { email: credentials.email.toLowerCase() },
        });

        if (!user) {
            logger.warn('Login attempt with non-existent email', {
                email: credentials.email,
            });
            throw new AuthenticationError('Invalid email or password');
        }

        // Step 2: Verify password
        const isPasswordValid = await bcrypt.compare(
            credentials.password,
            user.password
        );

        if (!isPasswordValid) {
            logger.warn('Login attempt with incorrect password', {
                userId: user.id,
                email: user.email,
            });
            throw new AuthenticationError('Invalid email or password');
        }

        // Step 3: Check account status
        if (!user.isActive) {
            logger.warn('Login attempt on deactivated account', {
                userId: user.id,
            });
            throw new AuthenticationError('Your account has been deactivated');
        }

        // Note: In development, we'll allow unverified users to login
        // In production, uncomment this:
        // if (!user.isVerified) {
        //     throw new AuthenticationError('Please verify your email before logging in');
        // }

        // Step 4: Generate JWT tokens
        const accessToken = createJwtToken(user);
        const refreshToken = createRefreshToken(user);

        // Step 5: Create new session
        const session = await prisma.session.create({
            data: {
                userId: user.id,
                token: accessToken,
                refreshToken: refreshToken,
                expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000), // 7 days
            },
        });

        // Step 6: Update last login time
        await prisma.user.update({
            where: { id: user.id },
            data: { lastLoginAt: new Date() },
        });

        logger.info('User logged in successfully', {
            userId: user.id,
            email: user.email,
            sessionId: session.id,
        });

        // Step 7: Return user and tokens
        return {
            user: {
                id: user.id,
                email: user.email,
                firstName: user.firstName,
                lastName: user.lastName,
                role: user.role,
                isVerified: user.isVerified,
            },
            tokens: {
                accessToken,
                refreshToken,
            },
        };

    } catch (error) {
        logger.error('User login failed', { error });
        throw error;
    }
}

/**
 * Logout user by invalidating their session
 * 
 * @param userId - ID of user to logout
 * @param sessionId - Optional specific session to logout
 */
export async function logoutUser(
    userId: string,
    sessionId?: string
): Promise<void> {
    const prisma = getPrismaClient();

    try {
        if (sessionId) {
            // Revoke specific session
            await prisma.session.update({
                where: { id: sessionId },
                data: { isRevoked: true },
            });

            logger.info('User session revoked', { userId, sessionId });
        } else {
            // Revoke all user sessions
            await prisma.session.updateMany({
                where: { userId, isRevoked: false },
                data: { isRevoked: true },
            });

            logger.info('All user sessions revoked', { userId });
        }

    } catch (error) {
        logger.error('Logout failed', { error, userId, sessionId });
        throw error;
    }
}

/**
 * Get user by ID (without password)
 * 
 * @param userId - User ID
 * @returns User object without sensitive data
 */
export async function getUserById(userId: string) {
    const prisma = getPrismaClient();

    const user = await prisma.user.findUnique({
        where: { id: userId },
        select: {
            id: true,
            email: true,
            firstName: true,
            lastName: true,
            phone: true,
            role: true,
            isActive: true,
            isVerified: true,
            lastLoginAt: true,
            createdAt: true,
            updatedAt: true,
        },
    });

    if (!user) {
        throw new NotFoundError('User not found');
    }

    return user;
}

/**
 * Update user profile
 * 
 * @param userId - User ID
 * @param updateData - Fields to update
 * @returns Updated user object
 */
export async function updateUserProfile(
    userId: string,
    updateData: Partial<Pick<User, 'firstName' | 'lastName' | 'phone'>>
) {
    const prisma = getPrismaClient();

    const user = await prisma.user.update({
        where: { id: userId },
        data: updateData,
        select: {
            id: true,
            email: true,
            firstName: true,
            lastName: true,
            phone: true,
            role: true,
            isVerified: true,
        },
    });

    logger.info('User profile updated', { userId });

    return user;
}

/**
 * Change user password
 * 
 * @param userId - User ID
 * @param currentPassword - Current password for verification
 * @param newPassword - New password to set
 */
export async function changePassword(
    userId: string,
    currentPassword: string,
    newPassword: string
): Promise<void> {
    const prisma = getPrismaClient();

    // Get user with password
    const user = await prisma.user.findUnique({
        where: { id: userId },
    });

    if (!user) {
        throw new NotFoundError('User not found');
    }

    // Verify current password
    const isPasswordValid = await bcrypt.compare(currentPassword, user.password);

    if (!isPasswordValid) {
        throw new AuthenticationError('Current password is incorrect');
    }

    // Hash new password
    const hashedPassword = await bcrypt.hash(newPassword, 10);

    // Update password
    await prisma.user.update({
        where: { id: userId },
        data: { password: hashedPassword },
    });

    // Revoke all sessions to force re-login
    await prisma.session.updateMany({
        where: { userId },
        data: { isRevoked: true },
    });

    logger.info('User password changed', { userId });
}

/**
 * Request password reset (sends reset token)
 * In a real app, this would send an email with reset link
 * 
 * @param email - User email
 * @returns Reset token (in production, this would be sent via email)
 */
export async function requestPasswordReset(email: string): Promise<string> {
    const prisma = getPrismaClient();

    const user = await prisma.user.findUnique({
        where: { email: email.toLowerCase() },
    });

    if (!user) {
        // Don't reveal if email exists (security best practice)
        logger.warn('Password reset requested for non-existent email', { email });
        throw new NotFoundError('If an account with this email exists, a reset link has been sent');
    }

    // Generate reset token (simplified for development)
    // In production, use crypto.randomBytes() and store hashed version
    const resetToken = Buffer.from(`${user.id}:${Date.now()}`).toString('base64');

    logger.info('Password reset requested', { userId: user.id, email });

    // TODO: Send email with reset link
    // await sendPasswordResetEmail(user.email, resetToken);

    return resetToken;
}

/**
 * Reset password using reset token
 * 
 * @param token - Reset token
 * @param newPassword - New password
 */
export async function resetPassword(
    token: string,
    newPassword: string
): Promise<void> {
    const prisma = getPrismaClient();

    try {
        // Decode token (simplified for development)
        const decoded = Buffer.from(token, 'base64').toString();
        const [userId, timestamp] = decoded.split(':');

        // Check if token is expired (1 hour validity)
        const tokenAge = Date.now() - parseInt(timestamp);
        if (tokenAge > 3600000) {
            throw new AuthenticationError('Reset token has expired');
        }

        // Hash new password
        const hashedPassword = await bcrypt.hash(newPassword, 10);

        // Update password
        await prisma.user.update({
            where: { id: userId },
            data: { password: hashedPassword },
        });

        // Revoke all sessions
        await prisma.session.updateMany({
            where: { userId },
            data: { isRevoked: true },
        });

        logger.info('Password reset successful', { userId });

    } catch (error) {
        logger.error('Password reset failed', { error });
        throw new AuthenticationError('Invalid or expired reset token');
    }
}
