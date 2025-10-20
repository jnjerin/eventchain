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

// ==============================================================================
// EVENT VALIDATION SCHEMAS
// ==============================================================================

/**
 * Event Creation Validation Schema
 * 
 * Validates data when an organizer creates a new event.
 * Ensures all required event details are provided correctly.
 */
export const createEventSchema = Joi.object({
    title: Joi.string()
        .min(5)
        .max(200)
        .trim()
        .required()
        .messages({
            'string.min': 'Event title must be at least 5 characters',
            'string.max': 'Event title cannot exceed 200 characters',
            'any.required': 'Event title is required',
        }),

    description: Joi.string()
        .min(20)
        .max(5000)
        .trim()
        .required()
        .messages({
            'string.min': 'Event description must be at least 20 characters',
            'string.max': 'Event description cannot exceed 5000 characters',
            'any.required': 'Event description is required',
        }),

    location: Joi.string()
        .min(5)
        .max(500)
        .trim()
        .required()
        .messages({
            'string.min': 'Location must be at least 5 characters',
            'string.max': 'Location cannot exceed 500 characters',
            'any.required': 'Event location is required',
        }),

    // Start date must be in the future
    startDate: Joi.date()
        .iso()
        .min('now')
        .required()
        .messages({
            'date.base': 'Start date must be a valid date',
            'date.min': 'Start date must be in the future',
            'any.required': 'Start date is required',
        }),

    // End date must be after start date
    endDate: Joi.date()
        .iso()
        .min(Joi.ref('startDate'))
        .required()
        .messages({
            'date.base': 'End date must be a valid date',
            'date.min': 'End date must be after start date',
            'any.required': 'End date is required',
        }),

    // Timezone (e.g., "Africa/Lagos", "America/New_York")
    timezone: Joi.string()
        .default('UTC')
        .messages({
            'string.base': 'Timezone must be a valid string',
        }),

    // Optional event imagery
    imageUrl: Joi.string()
        .uri()
        .optional()
        .messages({
            'string.uri': 'Image URL must be a valid URL',
        }),

    bannerUrl: Joi.string()
        .uri()
        .optional()
        .messages({
            'string.uri': 'Banner URL must be a valid URL',
        }),

    // Event capacity
    maxCapacity: Joi.number()
        .integer()
        .positive()
        .optional()
        .messages({
            'number.base': 'Max capacity must be a number',
            'number.positive': 'Max capacity must be positive',
            'number.integer': 'Max capacity must be a whole number',
        }),

    // Event visibility
    isPublic: Joi.boolean()
        .default(true)
        .messages({
            'boolean.base': 'isPublic must be true or false',
        }),

    // Approval requirement
    requiresApproval: Joi.boolean()
        .default(false)
        .messages({
            'boolean.base': 'requiresApproval must be true or false',
        }),
});

/**
 * Event Update Validation Schema
 * 
 * Validates data when updating an existing event.
 * All fields are optional since organizer can update selectively.
 */
export const updateEventSchema = Joi.object({
    title: Joi.string()
        .min(5)
        .max(200)
        .trim()
        .optional()
        .messages({
            'string.min': 'Event title must be at least 5 characters',
            'string.max': 'Event title cannot exceed 200 characters',
        }),

    description: Joi.string()
        .min(20)
        .max(5000)
        .trim()
        .optional()
        .messages({
            'string.min': 'Event description must be at least 20 characters',
            'string.max': 'Event description cannot exceed 5000 characters',
        }),

    location: Joi.string()
        .min(5)
        .max(500)
        .trim()
        .optional()
        .messages({
            'string.min': 'Location must be at least 5 characters',
            'string.max': 'Location cannot exceed 500 characters',
        }),

    startDate: Joi.date()
        .iso()
        .optional()
        .messages({
            'date.base': 'Start date must be a valid date',
        }),

    endDate: Joi.date()
        .iso()
        .optional()
        .messages({
            'date.base': 'End date must be a valid date',
        }),

    timezone: Joi.string()
        .optional()
        .messages({
            'string.base': 'Timezone must be a valid string',
        }),

    imageUrl: Joi.string()
        .uri()
        .allow(null, '')
        .optional()
        .messages({
            'string.uri': 'Image URL must be a valid URL',
        }),

    bannerUrl: Joi.string()
        .uri()
        .allow(null, '')
        .optional()
        .messages({
            'string.uri': 'Banner URL must be a valid URL',
        }),

    maxCapacity: Joi.number()
        .integer()
        .positive()
        .optional()
        .messages({
            'number.base': 'Max capacity must be a number',
            'number.positive': 'Max capacity must be positive',
        }),

    isPublic: Joi.boolean()
        .optional()
        .messages({
            'boolean.base': 'isPublic must be true or false',
        }),

    requiresApproval: Joi.boolean()
        .optional()
        .messages({
            'boolean.base': 'requiresApproval must be true or false',
        }),

    status: Joi.string()
        .valid('DRAFT', 'PUBLISHED', 'ONGOING', 'COMPLETED', 'CANCELLED')
        .optional()
        .messages({
            'any.only': 'Status must be one of: DRAFT, PUBLISHED, ONGOING, COMPLETED, CANCELLED',
        }),
}).min(1).messages({
    'object.min': 'At least one field must be provided for update',
});

/**
 * Event Search/Filter Validation Schema
 * 
 * Validates query parameters for event listing and search.
 */
export const getEventsQuerySchema = Joi.object({
    // Pagination
    page: Joi.number()
        .integer()
        .positive()
        .default(1)
        .messages({
            'number.base': 'Page must be a number',
            'number.positive': 'Page must be positive',
        }),

    limit: Joi.number()
        .integer()
        .positive()
        .max(100)
        .default(20)
        .messages({
            'number.base': 'Limit must be a number',
            'number.positive': 'Limit must be positive',
            'number.max': 'Limit cannot exceed 100',
        }),

    // Search query
    search: Joi.string()
        .trim()
        .optional()
        .messages({
            'string.base': 'Search query must be a string',
        }),

    // Filter by status
    status: Joi.string()
        .valid('DRAFT', 'PUBLISHED', 'ONGOING', 'COMPLETED', 'CANCELLED')
        .optional()
        .messages({
            'any.only': 'Status must be one of: DRAFT, PUBLISHED, ONGOING, COMPLETED, CANCELLED',
        }),

    // Filter by date range
    startDate: Joi.date()
        .iso()
        .optional()
        .messages({
            'date.base': 'Start date must be a valid date',
        }),

    endDate: Joi.date()
        .iso()
        .optional()
        .messages({
            'date.base': 'End date must be a valid date',
        }),

    // Sort options
    sortBy: Joi.string()
        .valid('startDate', 'createdAt', 'title')
        .default('startDate')
        .messages({
            'any.only': 'Sort by must be one of: startDate, createdAt, title',
        }),

    sortOrder: Joi.string()
        .valid('asc', 'desc')
        .default('asc')
        .messages({
            'any.only': 'Sort order must be asc or desc',
        }),
});

// ==============================================================================
// TICKET TYPE VALIDATION SCHEMAS
// ==============================================================================

/**
 * Ticket Type Creation Validation Schema
 * 
 * Validates data when creating ticket types for an event.
 * Each event can have multiple ticket types (General, VIP, Early Bird, etc.)
 */
export const createTicketTypeSchema = Joi.object({
    name: Joi.string()
        .min(3)
        .max(100)
        .trim()
        .required()
        .messages({
            'string.min': 'Ticket type name must be at least 3 characters',
            'string.max': 'Ticket type name cannot exceed 100 characters',
            'any.required': 'Ticket type name is required',
        }),

    description: Joi.string()
        .max(1000)
        .trim()
        .optional()
        .messages({
            'string.max': 'Description cannot exceed 1000 characters',
        }),

    // Price in decimal format (e.g., 25.99)
    price: Joi.number()
        .positive()
        .precision(2)
        .required()
        .messages({
            'number.base': 'Price must be a number',
            'number.positive': 'Price must be positive',
            'any.required': 'Price is required',
        }),

    // Currency code (ISO 4217: USD, EUR, NGN, etc.)
    currency: Joi.string()
        .length(3)
        .uppercase()
        .default('USD')
        .messages({
            'string.length': 'Currency must be a 3-letter code (e.g., USD, NGN)',
        }),

    // Maximum tickets of this type
    maxQuantity: Joi.number()
        .integer()
        .positive()
        .optional()
        .messages({
            'number.base': 'Max quantity must be a number',
            'number.positive': 'Max quantity must be positive',
            'number.integer': 'Max quantity must be a whole number',
        }),

    // Sale period
    saleStartDate: Joi.date()
        .iso()
        .optional()
        .messages({
            'date.base': 'Sale start date must be a valid date',
        }),

    saleEndDate: Joi.date()
        .iso()
        .optional()
        .messages({
            'date.base': 'Sale end date must be a valid date',
        }),

    // Ticket features
    isTransferable: Joi.boolean()
        .default(true)
        .messages({
            'boolean.base': 'isTransferable must be true or false',
        }),

    maxPerUser: Joi.number()
        .integer()
        .positive()
        .default(10)
        .messages({
            'number.base': 'Max per user must be a number',
            'number.positive': 'Max per user must be positive',
        }),
});

/**
 * Ticket Type Update Validation Schema
 * 
 * Validates updates to existing ticket types.
 */
export const updateTicketTypeSchema = Joi.object({
    name: Joi.string()
        .min(3)
        .max(100)
        .trim()
        .optional(),

    description: Joi.string()
        .max(1000)
        .trim()
        .optional(),

    price: Joi.number()
        .positive()
        .precision(2)
        .optional(),

    currency: Joi.string()
        .length(3)
        .uppercase()
        .optional(),

    maxQuantity: Joi.number()
        .integer()
        .positive()
        .optional(),

    saleStartDate: Joi.date()
        .iso()
        .optional(),

    saleEndDate: Joi.date()
        .iso()
        .optional(),

    isTransferable: Joi.boolean()
        .optional(),

    maxPerUser: Joi.number()
        .integer()
        .positive()
        .optional(),
}).min(1).messages({
    'object.min': 'At least one field must be provided for update',
});
