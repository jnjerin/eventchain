/**
 * Input Validation Schemas
 * 
 * This module defines validation rules for all API inputs using Joi.
 * Joi validates data before it reaches our business logic, preventing
 * invalid data from entering the database or causing errors.
 * 
 * Why Joi?
 * - Declarative validation rules
 * - Clear error messages for users
 * - Type safety with TypeScript
 * - Reusable schemas across endpoints
 */

import Joi from 'joi';
import { UserRole } from '@prisma/client';

/**
 * Common validation patterns
 * These are reusable across different schemas
 */
const commonValidation = {
    // Email must be valid format
    email: Joi.string()
        .email()
        .lowercase()
        .trim()
        .required()
        .messages({
            'string.email': 'Please provide a valid email address',
            'any.required': 'Email is required',
        }),

    // Password must be strong (8+ chars, mix of letters and numbers)
    password: Joi.string()
        .min(8)
        .pattern(/^(?=.*[A-Za-z])(?=.*\d)/)
        .required()
        .messages({
            'string.min': 'Password must be at least 8 characters long',
            'string.pattern.base': 'Password must contain both letters and numbers',
            'any.required': 'Password is required',
        }),

    // Phone number (international format)
    phone: Joi.string()
        .pattern(/^\+?[1-9]\d{1,14}$/)
        .messages({
            'string.pattern.base': 'Please provide a valid phone number (e.g., +1234567890)',
        }),

    // Names should only contain letters and basic punctuation
    name: Joi.string()
        .min(2)
        .max(50)
        .pattern(/^[a-zA-Z\s'-]+$/)
        .trim()
        .messages({
            'string.min': 'Name must be at least 2 characters',
            'string.max': 'Name cannot exceed 50 characters',
            'string.pattern.base': 'Name can only contain letters, spaces, hyphens, and apostrophes',
        }),
};

/**
 * User Registration Validation Schema
 * 
 * Validates data when a new user signs up.
 * All fields are required for registration.
 */
export const registerSchema = Joi.object({
    email: commonValidation.email,
    password: commonValidation.password,
    firstName: commonValidation.name.required().messages({
        'any.required': 'First name is required',
    }),
    lastName: commonValidation.name.required().messages({
        'any.required': 'Last name is required',
    }),
    phone: commonValidation.phone.optional(),
    role: Joi.string()
        .valid(...Object.values(UserRole))
        .default(UserRole.USER)
        .messages({
            'any.only': `Role must be one of: ${Object.values(UserRole).join(', ')}`,
        }),
});

/**
 * User Login Validation Schema
 * 
 * Validates login credentials.
 * Only email and password are needed.
 */
export const loginSchema = Joi.object({
    email: commonValidation.email,
    password: Joi.string().required().messages({
        'any.required': 'Password is required',
    }),
});

/**
 * Password Reset Request Schema
 * 
 * Validates email for password reset.
 */
export const forgotPasswordSchema = Joi.object({
    email: commonValidation.email,
});

/**
 * Password Reset Confirmation Schema
 * 
 * Validates new password and reset token.
 */
export const resetPasswordSchema = Joi.object({
    token: Joi.string().required().messages({
        'any.required': 'Reset token is required',
    }),
    password: commonValidation.password,
    confirmPassword: Joi.string()
        .valid(Joi.ref('password'))
        .required()
        .messages({
            'any.only': 'Passwords do not match',
            'any.required': 'Password confirmation is required',
        }),
});

/**
 * Update Profile Schema
 * 
 * Validates user profile updates.
 * All fields are optional since user can update selectively.
 */
export const updateProfileSchema = Joi.object({
    firstName: commonValidation.name.optional(),
    lastName: commonValidation.name.optional(),
    phone: commonValidation.phone.optional(),
}).min(1).messages({
    'object.min': 'At least one field must be provided for update',
});

/**
 * Change Password Schema
 * 
 * Validates password change request.
 * Requires current password for security.
 */
export const changePasswordSchema = Joi.object({
    currentPassword: Joi.string().required().messages({
        'any.required': 'Current password is required',
    }),
    newPassword: commonValidation.password.messages({
        'any.required': 'New password is required',
    }),
    confirmPassword: Joi.string()
        .valid(Joi.ref('newPassword'))
        .required()
        .messages({
            'any.only': 'Password confirmation does not match',
            'any.required': 'Password confirmation is required',
        }),
});

/**
 * Validation Middleware Factory
 * 
 * Creates Express middleware that validates request body against a schema.
 * If validation fails, returns 400 error with detailed messages.
 * If validation succeeds, continues to next middleware.
 * 
 * @param schema - Joi validation schema
 * @returns Express middleware function
 */
export const validate = (schema: Joi.ObjectSchema) => {
    return (req: any, res: any, next: any) => {
        // Validate request body against schema
        const { error, value } = schema.validate(req.body, {
            abortEarly: false, // Return all errors, not just the first one
            stripUnknown: true, // Remove fields not in schema
        });

        if (error) {
            // Extract error messages
            const errors = error.details.map((detail) => ({
                field: detail.path.join('.'),
                message: detail.message,
            }));

            return res.status(400).json({
                error: {
                    message: 'Validation failed',
                    code: 'VALIDATION_ERROR',
                    details: errors,
                },
            });
        }

        // Replace request body with validated/sanitized value
        req.body = value;
        next();
    };
};

/**
 * Sanitize user input
 * 
 * Removes potentially dangerous characters from user input.
 * Used as an additional security layer beyond Joi validation.
 * 
 * @param input - User input string
 * @returns Sanitized string
 */
export function sanitizeInput(input: string): string {
    return input
        .trim()
        .replace(/[<>]/g, '') // Remove potential HTML/script tags
        .substring(0, 1000); // Limit length to prevent DOS attacks
}

/**
 * Validate email format (standalone function)
 * 
 * Quick email validation without Joi schema.
 * Useful for pre-checks before database queries.
 * 
 * @param email - Email to validate
 * @returns true if valid, false otherwise
 */
export function isValidEmail(email: string): boolean {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
}

/**
 * Validate phone number format (standalone function)
 * 
 * @param phone - Phone number to validate
 * @returns true if valid, false otherwise
 */
export function isValidPhone(phone: string): boolean {
    const phoneRegex = /^\+?[1-9]\d{1,14}$/;
    return phoneRegex.test(phone);
}
