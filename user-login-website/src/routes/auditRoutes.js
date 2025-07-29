const express = require('express');
const auditController = require('../controllers/auditController');
const { requireAuth, requireAdministrator } = require('../middleware/auth');

const router = express.Router();

// View audit logs
router.get('/audit-logs', requireAuth, requireAdministrator, auditController.getAuditLogs);

// Export audit logs
router.get('/audit-logs/export', requireAuth, requireAdministrator, auditController.exportAuditLogs);

// Get recent security events (API endpoint)
router.get('/api/audit-logs/recent', requireAuth, requireAdministrator, auditController.getRecentSecurityEvents);

// Get user activity summary
router.get('/audit-logs/user/:id', requireAuth, requireAdministrator, auditController.getUserActivitySummary);

module.exports = router; 