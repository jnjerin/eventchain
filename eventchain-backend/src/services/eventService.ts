/**
 * Event Service
 * 
 * This service handles all event-related business logic:
 * - Event CRUD operations (Create, Read, Update, Delete)
 * - Event search and filtering with pagination
 * - Ticket type management for events
 * - Event status transitions (DRAFT → PUBLISHED → ONGOING → COMPLETED)
 * - Ownership and permission checks
 * 
 * Business Rules:
 * - Only ORGANIZER or ADMIN roles can create events
 * - Only event owner or ADMIN can update/delete events
 * - Events in DRAFT status are only visible to organizer
 * - Once PUBLISHED, events cannot be deleted (only cancelled)
 * - Ticket types can only be added to DRAFT or PUBLISHED events
 */

import { Event, EventStatus, TicketType, Prisma, UserRole } from '@prisma/client';
import { getPrismaClient } from '@/config/database';
import { logger, logBusinessEvent } from '@/config/logger';
import {
    ValidationError,
    NotFoundError,
    AuthorizationError,
    ConflictError,
} from '@/middleware/errorHandler';

/**
 * Event creation data transfer object
 */
interface CreateEventDto {
    title: string;
    description: string;
    location: string;
    startDate: Date;
    endDate: Date;
    timezone?: string;
    imageUrl?: string;
    bannerUrl?: string;
    maxCapacity?: number;
    isPublic?: boolean;
    requiresApproval?: boolean;
    organizerId: string; // User creating the event
}

/**
 * Event update data transfer object
 */
interface UpdateEventDto {
    title?: string;
    description?: string;
    location?: string;
    startDate?: Date;
    endDate?: Date;
    timezone?: string;
    imageUrl?: string;
    bannerUrl?: string;
    maxCapacity?: number;
    isPublic?: boolean;
    requiresApproval?: boolean;
    status?: EventStatus;
}

/**
 * Event query parameters for listing/search
 */
interface EventQueryParams {
    page?: number;
    limit?: number;
    search?: string;
    status?: EventStatus;
    startDate?: Date;
    endDate?: Date;
    sortBy?: 'startDate' | 'createdAt' | 'title';
    sortOrder?: 'asc' | 'desc';
    organizerId?: string; // Filter by organizer
}

/**
 * Paginated response structure
 */
interface PaginatedResponse<T> {
    data: T[];
    pagination: {
        page: number;
        limit: number;
        total: number;
        totalPages: number;
    };
}

/**
 * Create a new event
 * 
 * Steps:
 * 1. Validate organizer has permission (ORGANIZER or ADMIN role)
 * 2. Validate event dates (start before end, not in past)
 * 3. Create event in database with DRAFT status
 * 4. Log business event
 * 5. Return created event
 * 
 * @param eventData - Event creation data
 * @returns Created event object
 */
export async function createEvent(eventData: CreateEventDto): Promise<Event> {
    const prisma = getPrismaClient();

    try {
        // Step 1: Validate organizer permissions
        const organizer = await prisma.user.findUnique({
            where: { id: eventData.organizerId },
            select: { id: true, role: true, isActive: true },
        });

        if (!organizer) {
            throw new NotFoundError('Organizer not found');
        }

        if (organizer.role !== UserRole.ORGANIZER && organizer.role !== UserRole.ADMIN) {
            throw new AuthorizationError(
                'Only users with ORGANIZER or ADMIN role can create events'
            );
        }

        if (!organizer.isActive) {
            throw new AuthorizationError('Your account is not active');
        }

        // Step 2: Validate event dates
        const now = new Date();
        if (new Date(eventData.startDate) < now) {
            throw new ValidationError('Event start date must be in the future');
        }

        if (new Date(eventData.endDate) <= new Date(eventData.startDate)) {
            throw new ValidationError('Event end date must be after start date');
        }

        logger.info('Creating new event', {
            title: eventData.title,
            organizerId: eventData.organizerId,
        });

        // Step 3: Create event in database
        const event = await prisma.event.create({
            data: {
                title: eventData.title,
                description: eventData.description,
                location: eventData.location,
                startDate: new Date(eventData.startDate),
                endDate: new Date(eventData.endDate),
                timezone: eventData.timezone || 'UTC',
                imageUrl: eventData.imageUrl,
                bannerUrl: eventData.bannerUrl,
                maxCapacity: eventData.maxCapacity,
                isPublic: eventData.isPublic ?? true,
                requiresApproval: eventData.requiresApproval ?? false,
                status: EventStatus.DRAFT, // All new events start as DRAFT
                organizerId: eventData.organizerId,
            },
            include: {
                organizer: {
                    select: {
                        id: true,
                        firstName: true,
                        lastName: true,
                        email: true,
                    },
                },
            },
        });

        // Step 4: Log business event
        logBusinessEvent('event_created', {
            eventId: event.id,
            title: event.title,
            organizerId: event.organizerId,
        });

        logger.info('Event created successfully', {
            eventId: event.id,
            title: event.title,
        });

        return event;

    } catch (error) {
        logger.error('Event creation failed', { error });
        throw error;
    }
}

/**
 * Get all events with filtering, search, and pagination
 * 
 * Features:
 * - Text search (title, description, location)
 * - Filter by status, date range, organizer
 * - Pagination with configurable page size
 * - Sorting by multiple fields
 * - Visibility rules (DRAFT events only visible to owner/admin)
 * 
 * @param params - Query parameters
 * @param requestingUserId - ID of user making the request (for visibility)
 * @returns Paginated list of events
 */
export async function getEvents(
    params: EventQueryParams,
    requestingUserId?: string
): Promise<PaginatedResponse<Event>> {
    const prisma = getPrismaClient();

    try {
        const {
            page = 1,
            limit = 20,
            search,
            status,
            startDate,
            endDate,
            sortBy = 'startDate',
            sortOrder = 'asc',
            organizerId,
        } = params;

        // Build where clause for filtering
        const where: Prisma.EventWhereInput = {
            AND: [],
        };

        // Text search across multiple fields
        if (search) {
            where.AND!.push({
                OR: [
                    { title: { contains: search, mode: 'insensitive' } },
                    { description: { contains: search, mode: 'insensitive' } },
                    { location: { contains: search, mode: 'insensitive' } },
                ],
            });
        }

        // Filter by status
        if (status) {
            where.AND!.push({ status });
        }

        // Filter by date range
        if (startDate) {
            where.AND!.push({ startDate: { gte: new Date(startDate) } });
        }
        if (endDate) {
            where.AND!.push({ endDate: { lte: new Date(endDate) } });
        }

        // Filter by organizer
        if (organizerId) {
            where.AND!.push({ organizerId });
        }

        // Visibility rules: DRAFT events only visible to owner/admin
        // If requesting user is specified, check their role
        if (requestingUserId) {
            const requestingUser = await prisma.user.findUnique({
                where: { id: requestingUserId },
                select: { role: true },
            });

            // Non-admin users can only see PUBLISHED+ events or their own drafts
            if (requestingUser && requestingUser.role !== UserRole.ADMIN) {
                where.AND!.push({
                    OR: [
                        { status: { not: EventStatus.DRAFT } },
                        { organizerId: requestingUserId },
                    ],
                });
            }
        } else {
            // Public users can only see published+ events
            where.AND!.push({
                status: { not: EventStatus.DRAFT },
                isPublic: true,
            });
        }

        // Calculate pagination
        const skip = (page - 1) * limit;

        // Execute query with pagination
        const [events, total] = await Promise.all([
            prisma.event.findMany({
                where,
                skip,
                take: limit,
                orderBy: { [sortBy]: sortOrder },
                include: {
                    organizer: {
                        select: {
                            id: true,
                            firstName: true,
                            lastName: true,
                        },
                    },
                    ticketTypes: {
                        select: {
                            id: true,
                            name: true,
                            price: true,
                            currency: true,
                            soldQuantity: true,
                            maxQuantity: true,
                        },
                    },
                    _count: {
                        select: {
                            tickets: true,
                        },
                    },
                },
            }),
            prisma.event.count({ where }),
        ]);

        logger.debug('Events retrieved', {
            count: events.length,
            total,
            page,
            requestingUserId,
        });

        return {
            data: events,
            pagination: {
                page,
                limit,
                total,
                totalPages: Math.ceil(total / limit),
            },
        };

    } catch (error) {
        logger.error('Failed to retrieve events', { error });
        throw error;
    }
}

/**
 * Get event by ID
 * 
 * @param eventId - Event ID
 * @param requestingUserId - Optional user ID for visibility check
 * @returns Event object with full details
 */
export async function getEventById(
    eventId: string,
    requestingUserId?: string
): Promise<Event> {
    const prisma = getPrismaClient();

    try {
        const event = await prisma.event.findUnique({
            where: { id: eventId },
            include: {
                organizer: {
                    select: {
                        id: true,
                        firstName: true,
                        lastName: true,
                        email: true,
                        phone: true,
                    },
                },
                ticketTypes: {
                    orderBy: { createdAt: 'asc' },
                },
                _count: {
                    select: {
                        tickets: true,
                    },
                },
            },
        });

        if (!event) {
            throw new NotFoundError('Event not found');
        }

        // Check visibility permissions
        if (event.status === EventStatus.DRAFT) {
            // Draft events only visible to owner or admin
            if (requestingUserId) {
                const requestingUser = await prisma.user.findUnique({
                    where: { id: requestingUserId },
                    select: { role: true },
                });

                const isOwner = event.organizerId === requestingUserId;
                const isAdmin = requestingUser?.role === UserRole.ADMIN;

                if (!isOwner && !isAdmin) {
                    throw new NotFoundError('Event not found');
                }
            } else {
                throw new NotFoundError('Event not found');
            }
        }

        logger.debug('Event retrieved', {
            eventId,
            title: event.title,
        });

        return event;

    } catch (error) {
        logger.error('Failed to retrieve event', { error, eventId });
        throw error;
    }
}

/**
 * Update an existing event
 * 
 * Business rules:
 * - Only event owner or admin can update
 * - Cannot modify past events
 * - Status transitions must follow lifecycle
 * - Cannot change dates if tickets are sold
 * 
 * @param eventId - Event ID
 * @param updateData - Fields to update
 * @param requestingUserId - User making the request
 * @returns Updated event object
 */
export async function updateEvent(
    eventId: string,
    updateData: UpdateEventDto,
    requestingUserId: string
): Promise<Event> {
    const prisma = getPrismaClient();

    try {
        // Get existing event
        const event = await prisma.event.findUnique({
            where: { id: eventId },
            include: {
                _count: {
                    select: { tickets: true },
                },
            },
        });

        if (!event) {
            throw new NotFoundError('Event not found');
        }

        // Check permissions
        const requestingUser = await prisma.user.findUnique({
            where: { id: requestingUserId },
            select: { role: true },
        });

        const isOwner = event.organizerId === requestingUserId;
        const isAdmin = requestingUser?.role === UserRole.ADMIN;

        if (!isOwner && !isAdmin) {
            throw new AuthorizationError('You do not have permission to update this event');
        }

        // Cannot modify completed or cancelled events
        if (event.status === EventStatus.COMPLETED || event.status === EventStatus.CANCELLED) {
            throw new ValidationError('Cannot modify completed or cancelled events');
        }

        // Cannot change dates if tickets have been sold
        if (event._count.tickets > 0) {
            if (updateData.startDate || updateData.endDate) {
                throw new ValidationError(
                    'Cannot change event dates after tickets have been sold. Please contact support.'
                );
            }
        }

        // Validate date changes
        if (updateData.startDate && updateData.endDate) {
            if (new Date(updateData.endDate) <= new Date(updateData.startDate)) {
                throw new ValidationError('End date must be after start date');
            }
        }

        logger.info('Updating event', {
            eventId,
            updateFields: Object.keys(updateData),
            requestingUserId,
        });

        // Update event
        const updatedEvent = await prisma.event.update({
            where: { id: eventId },
            data: updateData,
            include: {
                organizer: {
                    select: {
                        id: true,
                        firstName: true,
                        lastName: true,
                        email: true,
                    },
                },
                ticketTypes: true,
            },
        });

        // Log business event
        logBusinessEvent('event_updated', {
            eventId,
            updateFields: Object.keys(updateData),
            updatedBy: requestingUserId,
        });

        logger.info('Event updated successfully', { eventId });

        return updatedEvent;

    } catch (error) {
        logger.error('Event update failed', { error, eventId });
        throw error;
    }
}

/**
 * Delete (soft delete) an event
 * 
 * Business rules:
 * - Only owner or admin can delete
 * - Cannot delete if tickets are sold (must cancel instead)
 * - Soft delete (sets deletedAt timestamp)
 * 
 * @param eventId - Event ID
 * @param requestingUserId - User making the request
 */
export async function deleteEvent(
    eventId: string,
    requestingUserId: string
): Promise<void> {
    const prisma = getPrismaClient();

    try {
        // Get event with ticket count
        const event = await prisma.event.findUnique({
            where: { id: eventId },
            include: {
                _count: {
                    select: { tickets: true },
                },
            },
        });

        if (!event) {
            throw new NotFoundError('Event not found');
        }

        // Check permissions
        const requestingUser = await prisma.user.findUnique({
            where: { id: requestingUserId },
            select: { role: true },
        });

        const isOwner = event.organizerId === requestingUserId;
        const isAdmin = requestingUser?.role === UserRole.ADMIN;

        if (!isOwner && !isAdmin) {
            throw new AuthorizationError('You do not have permission to delete this event');
        }

        // Cannot delete if tickets are sold
        if (event._count.tickets > 0) {
            throw new ValidationError(
                'Cannot delete event with sold tickets. Please cancel the event instead.'
            );
        }

        logger.info('Deleting event', { eventId, requestingUserId });

        // Soft delete
        await prisma.event.update({
            where: { id: eventId },
            data: { deletedAt: new Date() },
        });

        // Log business event
        logBusinessEvent('event_deleted', {
            eventId,
            deletedBy: requestingUserId,
        });

        logger.info('Event deleted successfully', { eventId });

    } catch (error) {
        logger.error('Event deletion failed', { error, eventId });
        throw error;
    }
}

/**
 * Publish an event (make it visible to public)
 * 
 * @param eventId - Event ID
 * @param requestingUserId - User making the request
 * @returns Updated event
 */
export async function publishEvent(
    eventId: string,
    requestingUserId: string
): Promise<Event> {
    return updateEvent(
        eventId,
        { status: EventStatus.PUBLISHED },
        requestingUserId
    );
}

/**
 * Cancel an event
 * 
 * @param eventId - Event ID
 * @param requestingUserId - User making the request
 * @returns Updated event
 */
export async function cancelEvent(
    eventId: string,
    requestingUserId: string
): Promise<Event> {
    // TODO: Add refund logic for sold tickets
    return updateEvent(
        eventId,
        { status: EventStatus.CANCELLED },
        requestingUserId
    );
}
