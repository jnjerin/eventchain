/**
 * Event Controller
 * 
 * This controller handles HTTP requests for event management endpoints.
 * It bridges the HTTP layer with the event service business logic.
 * 
 * Responsibilities:
 * - Parse and validate incoming HTTP requests
 * - Extract authentication context from middleware
 * - Call event service for business logic
 * - Format and send HTTP responses
 * - Handle errors appropriately
 * 
 * Endpoints:
 * - POST /events - Create new event (ORGANIZER+)
 * - GET /events - List events with filtering/search
 * - GET /events/:id - Get event details
 * - PUT /events/:id - Update event (Owner/Admin)
 * - DELETE /events/:id - Delete event (Owner/Admin)
 * - POST /events/:id/publish - Publish event
 * - POST /events/:id/cancel - Cancel event
 */

import { Response } from 'express';
import { AuthenticatedRequest } from '@/middleware/authMiddleware';
import {
    createEvent,
    getEvents,
    getEventById,
    updateEvent,
    deleteEvent,
    publishEvent,
    cancelEvent,
} from '@/services/eventService';
import { asyncHandler } from '@/middleware/errorHandler';
import { logger } from '@/config/logger';

/**
 * Create a new event
 * 
 * POST /api/v1/events
 * 
 * Headers:
 * - Authorization: Bearer <token> (required)
 * 
 * Request body:
 * - title: string (required)
 * - description: string (required)
 * - location: string (required)
 * - startDate: ISO date (required)
 * - endDate: ISO date (required)
 * - timezone: string (optional, defaults to UTC)
 * - imageUrl: string (optional)
 * - bannerUrl: string (optional)
 * - maxCapacity: number (optional)
 * - isPublic: boolean (optional, defaults to true)
 * - requiresApproval: boolean (optional, defaults to false)
 * 
 * Response: 201 Created
 * - event: Event object with organizer details
 */
export const createEventHandler = asyncHandler(
    async (req: AuthenticatedRequest, res: Response) => {
        // User is already authenticated by middleware
        const organizerId = req.user!.id;
        
        const {
            title,
            description,
            location,
            startDate,
            endDate,
            timezone,
            imageUrl,
            bannerUrl,
            maxCapacity,
            isPublic,
            requiresApproval,
        } = req.body;

        logger.info('Create event request', {
            title,
            organizerId,
        });

        // Call service to create event
        const event = await createEvent({
            title,
            description,
            location,
            startDate: new Date(startDate),
            endDate: new Date(endDate),
            timezone,
            imageUrl,
            bannerUrl,
            maxCapacity,
            isPublic,
            requiresApproval,
            organizerId,
        });

        // Send success response
        res.status(201).json({
            success: true,
            message: 'Event created successfully',
            data: { event },
        });
    }
);

/**
 * Get list of events with filtering and pagination
 * 
 * GET /api/v1/events
 * 
 * Query parameters:
 * - page: number (optional, default 1)
 * - limit: number (optional, default 20, max 100)
 * - search: string (optional, searches title/description/location)
 * - status: EventStatus (optional)
 * - startDate: ISO date (optional, filter events starting after this date)
 * - endDate: ISO date (optional, filter events ending before this date)
 * - sortBy: startDate|createdAt|title (optional, default startDate)
 * - sortOrder: asc|desc (optional, default asc)
 * 
 * Response: 200 OK
 * - data: Event[] with pagination metadata
 */
export const getEventsHandler = asyncHandler(
    async (req: AuthenticatedRequest, res: Response) => {
        // Extract query parameters
        const {
            page,
            limit,
            search,
            status,
            startDate,
            endDate,
            sortBy,
            sortOrder,
        } = req.query;

        // Get requesting user ID (if authenticated)
        const requestingUserId = req.user?.id;

        logger.debug('Get events request', {
            page,
            limit,
            search,
            requestingUserId,
        });

        // Call service to get events
        const result = await getEvents(
            {
                page: page ? Number(page) : undefined,
                limit: limit ? Number(limit) : undefined,
                search: search as string,
                status: status as any,
                startDate: startDate ? new Date(startDate as string) : undefined,
                endDate: endDate ? new Date(endDate as string) : undefined,
                sortBy: sortBy as any,
                sortOrder: sortOrder as any,
            },
            requestingUserId
        );

        // Send success response
        res.status(200).json({
            success: true,
            data: result.data,
            pagination: result.pagination,
        });
    }
);

/**
 * Get single event by ID
 * 
 * GET /api/v1/events/:id
 * 
 * Path parameters:
 * - id: Event ID (required)
 * 
 * Response: 200 OK
 * - event: Event object with full details
 */
export const getEventByIdHandler = asyncHandler(
    async (req: AuthenticatedRequest, res: Response) => {
        const { id } = req.params;
        const requestingUserId = req.user?.id;

        logger.debug('Get event by ID request', {
            eventId: id,
            requestingUserId,
        });

        // Call service to get event
        const event = await getEventById(id, requestingUserId);

        // Send success response
        res.status(200).json({
            success: true,
            data: { event },
        });
    }
);

/**
 * Update an existing event
 * 
 * PUT /api/v1/events/:id
 * 
 * Headers:
 * - Authorization: Bearer <token> (required)
 * 
 * Path parameters:
 * - id: Event ID (required)
 * 
 * Request body: (all fields optional)
 * - title: string
 * - description: string
 * - location: string
 * - startDate: ISO date
 * - endDate: ISO date
 * - timezone: string
 * - imageUrl: string
 * - bannerUrl: string
 * - maxCapacity: number
 * - isPublic: boolean
 * - requiresApproval: boolean
 * - status: EventStatus
 * 
 * Response: 200 OK
 * - event: Updated event object
 */
export const updateEventHandler = asyncHandler(
    async (req: AuthenticatedRequest, res: Response) => {
        const { id } = req.params;
        const requestingUserId = req.user!.id;
        
        const {
            title,
            description,
            location,
            startDate,
            endDate,
            timezone,
            imageUrl,
            bannerUrl,
            maxCapacity,
            isPublic,
            requiresApproval,
            status,
        } = req.body;

        logger.info('Update event request', {
            eventId: id,
            requestingUserId,
            updateFields: Object.keys(req.body),
        });

        // Call service to update event
        const event = await updateEvent(
            id,
            {
                title,
                description,
                location,
                startDate: startDate ? new Date(startDate) : undefined,
                endDate: endDate ? new Date(endDate) : undefined,
                timezone,
                imageUrl,
                bannerUrl,
                maxCapacity,
                isPublic,
                requiresApproval,
                status,
            },
            requestingUserId
        );

        // Send success response
        res.status(200).json({
            success: true,
            message: 'Event updated successfully',
            data: { event },
        });
    }
);

/**
 * Delete an event
 * 
 * DELETE /api/v1/events/:id
 * 
 * Headers:
 * - Authorization: Bearer <token> (required)
 * 
 * Path parameters:
 * - id: Event ID (required)
 * 
 * Response: 200 OK
 * - message: Success message
 */
export const deleteEventHandler = asyncHandler(
    async (req: AuthenticatedRequest, res: Response) => {
        const { id } = req.params;
        const requestingUserId = req.user!.id;

        logger.info('Delete event request', {
            eventId: id,
            requestingUserId,
        });

        // Call service to delete event
        await deleteEvent(id, requestingUserId);

        // Send success response
        res.status(200).json({
            success: true,
            message: 'Event deleted successfully',
        });
    }
);

/**
 * Publish an event (change status to PUBLISHED)
 * 
 * POST /api/v1/events/:id/publish
 * 
 * Headers:
 * - Authorization: Bearer <token> (required)
 * 
 * Path parameters:
 * - id: Event ID (required)
 * 
 * Response: 200 OK
 * - event: Updated event object
 */
export const publishEventHandler = asyncHandler(
    async (req: AuthenticatedRequest, res: Response) => {
        const { id } = req.params;
        const requestingUserId = req.user!.id;

        logger.info('Publish event request', {
            eventId: id,
            requestingUserId,
        });

        // Call service to publish event
        const event = await publishEvent(id, requestingUserId);

        // Send success response
        res.status(200).json({
            success: true,
            message: 'Event published successfully',
            data: { event },
        });
    }
);

/**
 * Cancel an event (change status to CANCELLED)
 * 
 * POST /api/v1/events/:id/cancel
 * 
 * Headers:
 * - Authorization: Bearer <token> (required)
 * 
 * Path parameters:
 * - id: Event ID (required)
 * 
 * Response: 200 OK
 * - event: Updated event object
 * 
 * Note: In production, this should trigger refund process for sold tickets
 */
export const cancelEventHandler = asyncHandler(
    async (req: AuthenticatedRequest, res: Response) => {
        const { id } = req.params;
        const requestingUserId = req.user!.id;

        logger.info('Cancel event request', {
            eventId: id,
            requestingUserId,
        });

        // Call service to cancel event
        const event = await cancelEvent(id, requestingUserId);

        // Send success response
        res.status(200).json({
            success: true,
            message: 'Event cancelled successfully. Refunds will be processed shortly.',
            data: { event },
        });
    }
);

/**
 * Get events organized by current user
 * 
 * GET /api/v1/events/my-events
 * 
 * Headers:
 * - Authorization: Bearer <token> (required)
 * 
 * Query parameters: (same as getEventsHandler)
 * 
 * Response: 200 OK
 * - data: Event[] created by current user
 */
export const getMyEventsHandler = asyncHandler(
    async (req: AuthenticatedRequest, res: Response) => {
        const organizerId = req.user!.id;
        
        const {
            page,
            limit,
            search,
            status,
            startDate,
            endDate,
            sortBy,
            sortOrder,
        } = req.query;

        logger.debug('Get my events request', {
            organizerId,
        });

        // Call service with organizer filter
        const result = await getEvents(
            {
                page: page ? Number(page) : undefined,
                limit: limit ? Number(limit) : undefined,
                search: search as string,
                status: status as any,
                startDate: startDate ? new Date(startDate as string) : undefined,
                endDate: endDate ? new Date(endDate as string) : undefined,
                sortBy: sortBy as any,
                sortOrder: sortOrder as any,
                organizerId, // Filter by current user
            },
            organizerId
        );

        // Send success response
        res.status(200).json({
            success: true,
            data: result.data,
            pagination: result.pagination,
        });
    }
);
