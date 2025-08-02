const mongoose = require('mongoose');

const auditLogSchema = new mongoose.Schema({
    timestamp: {
        type: Date,
        default: Date.now,
        required: true
    },
    userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: false // Can be null for failed login attempts
    },
    username: {
        type: String,
        required: false
    },
    ipAddress: {
        type: String,
        required: true
    },
    userAgent: {
        type: String,
        required: true
    },
    eventType: {
        type: String,
        enum: [
            'LOGIN_SUCCESS',
            'LOGIN_FAILED',
            'LOGOUT',
            'PASSWORD_CHANGE',
            'PASSWORD_RESET',
            'ACCOUNT_LOCKED',
            'ACCOUNT_UNLOCKED',
            'USER_CREATED',
            'USER_UPDATED',
            'USER_DELETED',
            'ROLE_CHANGED',
            'ACCESS_DENIED',
            'INPUT_VALIDATION_FAILED',
            'CRITICAL_OPERATION',
            'PROFILE_VIEWED',
            'PASSWORD_RESET_SUCCESS',
            'PASSWORD_RESET_REQUEST',
            'REAUTH_SUCCESS' // Added this event type
        ],
        required: true
    },
    eventDetails: {
        type: String,
        required: true
    },
    severity: {
        type: String,
        enum: ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'],
        default: 'LOW'
    },
    resource: {
        type: String,
        required: false
    },
    method: {
        type: String,
        required: false
    },
    statusCode: {
        type: Number,
        required: false
    },
    additionalData: {
        type: mongoose.Schema.Types.Mixed,
        default: {}
    }
}, {
    timestamps: true
});

// Index for efficient querying
auditLogSchema.index({ timestamp: -1 });
auditLogSchema.index({ userId: 1, timestamp: -1 });
auditLogSchema.index({ eventType: 1, timestamp: -1 });
auditLogSchema.index({ severity: 1, timestamp: -1 });

const AuditLog = mongoose.model('AuditLog', auditLogSchema);

module.exports = AuditLog; 