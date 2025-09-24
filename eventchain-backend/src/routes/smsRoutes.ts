/**
 * SMS Affiliate Routes
 * 
 * Handles SMS marketing campaigns and affiliate tracking.
 * Affiliates use these endpoints to manage their promotional campaigns.
 */

import { Router } from 'express';

const router = Router();

// Placeholder routes
router.post('/send', (req, res) => {
    res.status(501).json({ message: 'Send SMS campaign endpoint - coming soon' });
});

router.get('/stats/:affiliateId', (req, res) => {
    res.status(501).json({ message: 'Get affiliate stats endpoint - coming soon' });
});

export default router;
