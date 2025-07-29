const AuditLog = require('../models/auditLog');
const { logSecurityEvent } = require('../middleware/auth');
const { auditLogQuerySchema } = require('../validation/schemas');

class AuditController {
    // Get audit logs with filtering and pagination
    async getAuditLogs(req, res) {
        try {
            // Validate query parameters
            const { error } = auditLogQuerySchema.validate(req.query);
            if (error) {
                await logSecurityEvent(req, 'INPUT_VALIDATION_FAILED', `Audit log query validation failed: ${error.details[0].message}`, 'MEDIUM');
                return res.status(400).render('error', {
                    error: 'Invalid Query Parameters',
                    message: 'The provided query parameters are invalid.'
                });
            }

            const {
                startDate,
                endDate,
                eventType,
                severity,
                username,
                limit = 50,
                page = 1
            } = req.query;

            // Build query
            const query = {};
            
            if (startDate || endDate) {
                query.timestamp = {};
                if (startDate) query.timestamp.$gte = new Date(startDate);
                if (endDate) query.timestamp.$lte = new Date(endDate);
            }
            
            if (eventType) query.eventType = eventType;
            if (severity) query.severity = severity;
            if (username) query.username = { $regex: username, $options: 'i' };

            // Execute query with pagination
            const skip = (parseInt(page) - 1) * parseInt(limit);
            
            const logs = await AuditLog.find(query)
                .sort({ timestamp: -1 })
                .skip(skip)
                .limit(parseInt(limit))
                .populate('userId', 'username email role');

            const totalLogs = await AuditLog.countDocuments(query);
            const totalPages = Math.ceil(totalLogs / parseInt(limit));

            // Get summary statistics
            const stats = await this.getAuditStats(query);

            res.render('admin/auditLogs', {
                logs,
                stats,
                currentPage: parseInt(page),
                totalPages,
                totalLogs,
                filters: {
                    startDate,
                    endDate,
                    eventType,
                    severity,
                    username
                },
                user: req.user
            });

        } catch (err) {
            console.error('Get audit logs error:', err);
            await logSecurityEvent(req, 'ACCESS_DENIED', 'Error retrieving audit logs', 'HIGH');
            res.status(500).render('error', {
                error: 'Server Error',
                message: 'An error occurred while retrieving audit logs.'
            });
        }
    }

    // Get audit statistics
    async getAuditStats(query = {}) {
        try {
            const stats = await AuditLog.aggregate([
                { $match: query },
                {
                    $group: {
                        _id: null,
                        totalEvents: { $sum: 1 },
                        criticalEvents: {
                            $sum: { $cond: [{ $eq: ['$severity', 'CRITICAL'] }, 1, 0] }
                        },
                        highEvents: {
                            $sum: { $cond: [{ $eq: ['$severity', 'HIGH'] }, 1, 0] }
                        },
                        mediumEvents: {
                            $sum: { $cond: [{ $eq: ['$severity', 'MEDIUM'] }, 1, 0] }
                        },
                        lowEvents: {
                            $sum: { $cond: [{ $eq: ['$severity', 'LOW'] }, 1, 0] }
                        }
                    }
                }
            ]);

            return stats[0] || {
                totalEvents: 0,
                criticalEvents: 0,
                highEvents: 0,
                mediumEvents: 0,
                lowEvents: 0
            };
        } catch (err) {
            console.error('Get audit stats error:', err);
            return {
                totalEvents: 0,
                criticalEvents: 0,
                highEvents: 0,
                mediumEvents: 0,
                lowEvents: 0
            };
        }
    }

    // Get recent security events
    async getRecentSecurityEvents(req, res) {
        try {
            const recentEvents = await AuditLog.find({
                severity: { $in: ['HIGH', 'CRITICAL'] }
            })
            .sort({ timestamp: -1 })
            .limit(10)
            .populate('userId', 'username email role');

            res.json({
                success: true,
                events: recentEvents
            });
        } catch (err) {
            console.error('Get recent security events error:', err);
            res.status(500).json({
                error: 'An error occurred while retrieving recent security events.'
            });
        }
    }

    // Export audit logs (Administrators only)
    async exportAuditLogs(req, res) {
        try {
            const { startDate, endDate, eventType, severity } = req.query;

            // Build query
            const query = {};
            
            if (startDate || endDate) {
                query.timestamp = {};
                if (startDate) query.timestamp.$gte = new Date(startDate);
                if (endDate) query.timestamp.$lte = new Date(endDate);
            }
            
            if (eventType) query.eventType = eventType;
            if (severity) query.severity = severity;

            const logs = await AuditLog.find(query)
                .sort({ timestamp: -1 })
                .populate('userId', 'username email role');

            // Convert to CSV format
            const csvData = this.convertToCSV(logs);

            res.setHeader('Content-Type', 'text/csv');
            res.setHeader('Content-Disposition', `attachment; filename=audit-logs-${new Date().toISOString().split('T')[0]}.csv`);
            res.send(csvData);

            await logSecurityEvent(req, 'CRITICAL_OPERATION', 'Audit logs exported', 'MEDIUM');

        } catch (err) {
            console.error('Export audit logs error:', err);
            await logSecurityEvent(req, 'ACCESS_DENIED', 'Error exporting audit logs', 'HIGH');
            res.status(500).render('error', {
                error: 'Server Error',
                message: 'An error occurred while exporting audit logs.'
            });
        }
    }

    // Convert audit logs to CSV format
    convertToCSV(logs) {
        const headers = [
            'Timestamp',
            'Username',
            'IP Address',
            'Event Type',
            'Event Details',
            'Severity',
            'Resource',
            'Method',
            'Status Code'
        ];

        const csvRows = [headers.join(',')];

        logs.forEach(log => {
            const row = [
                log.timestamp.toISOString(),
                log.username || 'N/A',
                log.ipAddress,
                log.eventType,
                `"${log.eventDetails.replace(/"/g, '""')}"`,
                log.severity,
                log.resource || 'N/A',
                log.method || 'N/A',
                log.statusCode || 'N/A'
            ];
            csvRows.push(row.join(','));
        });

        return csvRows.join('\n');
    }

    // Get user activity summary
    async getUserActivitySummary(req, res) {
        try {
            const userId = req.params.id;

            const userActivity = await AuditLog.find({ userId })
                .sort({ timestamp: -1 })
                .limit(100);

            const activitySummary = await AuditLog.aggregate([
                { $match: { userId: userId } },
                {
                    $group: {
                        _id: '$eventType',
                        count: { $sum: 1 },
                        lastOccurrence: { $max: '$timestamp' }
                    }
                },
                { $sort: { count: -1 } }
            ]);

            res.render('admin/userActivity', {
                userActivity,
                activitySummary,
                user: req.user
            });

        } catch (err) {
            console.error('Get user activity summary error:', err);
            res.status(500).render('error', {
                error: 'Server Error',
                message: 'An error occurred while retrieving user activity.'
            });
        }
    }
}

module.exports = new AuditController(); 