/**
 * Event Management Routes
 * 
 * Handles CRUD operations for events.
 * Events are the core entity around which tickets are created.
 * 
 * Route Structure:
 * - Public routes: GET /events (list), GET /events/:id (view single)
 * - Protected routes: POST, PUT, DELETE (require authentication)
 * - Organizer routes: Create and manage own events
 * 
 * Permission levels:
 * - Anyone: View published events
 * - Authenticated: View own draft events
 * - ORGANIZER/ADMIN: Create events
 * - Owner/ADMIN: Update, delete, publish, cancel own events
 */

import { Router } from 'express';
import {
    createEventHandler,
    getEventsHandler,
    getEventByIdHandler,
    updateEventHandler,
    deleteEventHandler,
    publishEventHandler,
    cancelEventHandler,
    getMyEventsHandler,
} from '@/controllers/eventController';
import { authenticate, authorize, optionalAuthenticate } from '@/middleware/authMiddleware';
import {
    validate,
    createEventSchema,
    updateEventSchema,
    getEventsQuerySchema,
} from '@/utils/validators';
import { UserRole } from '@prisma/client';

const router = Router();

// ==============================================================================
// PUBLIC ROUTES - No authentication required (but can use optional auth)
// ==============================================================================

/**
 * GET /api/v1/events
 * List all events with filtering, search, and pagination
 * 
 * Query params: page, limit, search, status, startDate, endDate, sortBy, sortOrder
 * 
 * Note: Uses optionalAuthenticate to show draft events to authenticated owners
 * 
 * Returns: Paginated list of events
 */
router.get(
    '/',
    optionalAuthenticate,
    // Validation middleware for query params
    (req, res, next) => {
        const { error, value } = getEventsQuerySchema.validate(req.query, {
            stripUnknown: true,
        });
        if (error) {
            return res.status(400).json({
                error: {
                    message: 'Invalid query parameters',
                    details: error.details.map(d => ({
                        field: d.path.join('.'),
                        message: d.message,
                    })),
                },
            });
        }
        req.query = value;
        next();
    },
    getEventsHandler
);

/**
 * GET /api/v1/events/:id
 * Get single event by ID
 * 
 * Path params: id (event ID)
 * 
 * Note: Uses optionalAuthenticate to show draft events to authenticated owners
 * 
 * Returns: Event object with full details
 */
router.get('/:id', optionalAuthenticate, getEventByIdHandler);

// ==============================================================================
// PROTECTED ROUTES - Authentication required
// ==============================================================================

/**
 * POST /api/v1/events
 * Create a new event
 * 
 * Headers: Authorization: Bearer <token>
 * Body: Event creation data (see createEventSchema)
 * 
 * Permissions: ORGANIZER or ADMIN roles only
 * 
 * Returns: Created event object
 */
router.post(
    '/',
    authenticate,
    authorize([UserRole.ORGANIZER, UserRole.ADMIN]),
    validate(createEventSchema),
    createEventHandler
);

/**
 * GET /api/v1/events/my-events
 * Get events created by current user
 * 
 * Headers: Authorization: Bearer <token>
 * Query params: Same as GET /events
 * 
 * Permissions: ORGANIZER or ADMIN
 * 
 * Returns: Paginated list of user's events
 * 
 * Note: This route must be defined BEFORE /:id to avoid path conflicts
 */
router.get(
    '/my-events',
    authenticate,
    authorize([UserRole.ORGANIZER, UserRole.ADMIN]),
    getMyEventsHandler
);

/**
 * PUT /api/v1/events/:id
 * Update an existing event
 * 
 * Headers: Authorization: Bearer <token>
 * Path params: id (event ID)
 * Body: Event update data (see updateEventSchema)
 * 
 * Permissions: Event owner or ADMIN
 * 
 * Returns: Updated event object
 */
router.put(
    '/:id',
    authenticate,
    validate(updateEventSchema),
    updateEventHandler
);

/**
 * DELETE /api/v1/events/:id
 * Delete an event
 * 
 * Headers: Authorization: Bearer <token>
 * Path params: id (event ID)
 * 
 * Permissions: Event owner or ADMIN
 * 
 * Note: Can only delete events with no sold tickets
 * 
 * Returns: Success message
 */
router.delete(
    '/:id',
    authenticate,
    deleteEventHandler
);

/**
 * POST /api/v1/events/:id/publish
 * Publish an event (change status from DRAFT to PUBLISHED)
 * 
 * Headers: Authorization: Bearer <token>
 * Path params: id (event ID)
 * 
 * Permissions: Event owner or ADMIN
 * 
 * Returns: Updated event object
 */
router.post(
    '/:id/publish',
    authenticate,
    publishEventHandler
);

/**
 * POST /api/v1/events/:id/cancel
 * Cancel an event
 * 
 * Headers: Authorization: Bearer <token>
 * Path params: id (event ID)
 * 
 * Permissions: Event owner or ADMIN
 * 
 * Note: Triggers refund process for sold tickets
 * 
 * Returns: Updated event object
 */
router.post(
    '/:id/cancel',
    authenticate,
    cancelEventHandler
);

export default router;
