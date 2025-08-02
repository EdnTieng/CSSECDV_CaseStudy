const User = require('../models/user');
const AuditLog = require('../models/auditLog');

// Authentication middleware
const requireAuth = async (req, res, next) => {
    try {
        if (!req.session.userId) {
            await logSecurityEvent(req, 'ACCESS_DENIED', 'Unauthenticated access attempt', 'HIGH');
            if (wantsJson(req)) {
                return res.status(401).json({ error: 'Authentication required' });
            }
            return res.status(401).render('error', { error: 'Authentication required', message: 'Please log in...' });
        }

        const user = await User.findById(req.session.userId).select('-password');
        
        if (!user || !user.isActive) {
            req.session.destroy();
            await logSecurityEvent(req, 'ACCESS_DENIED', 'Invalid or inactive user session', 'HIGH');
            return res.status(401).render('error', { 
                error: 'Authentication required',
                message: 'Please log in to access this resource'
            });
        }

        req.user = user;
        next();
    } catch (error) {
        await logSecurityEvent(req, 'ACCESS_DENIED', 'Authentication middleware error', 'HIGH');
        res.status(500).render('error', { 
            error: 'Server Error',
            message: 'An error occurred while processing your request'
        });
    }
};

// Role-based authorization middleware
const requireRole = (allowedRoles) => {
    return (req, res, next) => {
        if (!req.user) {
            return res.status(401).render('error', { 
                error: 'Authentication required',
                message: 'Please log in to access this resource'
            });
        }

        if (!allowedRoles.includes(req.user.role)) {
            logSecurityEvent(req, 'ACCESS_DENIED', `Unauthorized access attempt to role-restricted resource. User role: ${req.user.role}, Required roles: ${allowedRoles.join(', ')}`, 'HIGH');
            return res.status(403).render('error', { 
                error: 'Access Denied',
                message: 'You do not have permission to access this resource'
            });
        }

        next();
    };
};

// Specific role middleware
const requireAdministrator = (req, res, next) => {
    if (!req.user) {
        return res.status(401).render('error', { 
            error: 'Authentication required',
            message: 'Please log in to access this resource'
        });
    }

    if (req.user.role !== 'Administrator') {
        logSecurityEvent(req, 'ACCESS_DENIED', `Unauthorized access attempt to administrator resource. User role: ${req.user.role}`, 'HIGH');
        return res.status(403).render('error', { 
            error: 'Access Denied',
            message: 'You do not have permission to access this resource'
        });
    }

    next();
};

const requireRoleA = requireRole(['Administrator', 'RoleA']);
const requireRoleB = requireRole(['Administrator', 'RoleA', 'RoleB']);

// Re-authentication middleware for critical operations
const requireReAuth = async (req, res, next) => {
    try {
        if (!req.session.reAuthVerified) {
            return res.render('reauth', { 
                error: null,
                returnUrl: req.originalUrl
            });
        }
        
        // Don't reset the flag immediately - let the operation complete first
        next();
    } catch (error) {
        res.status(500).render('error', { 
            error: 'Server Error',
            message: 'An error occurred while processing your request'
        });
    }
};

// Input validation middleware
const validateInput = (schema) => {
    return (req, res, next) => {
        try {
            const { error } = schema.validate(req.body);
            if (error) {
                logSecurityEvent(req, 'INPUT_VALIDATION_FAILED', `Validation failed: ${error.details[0].message}`, 'MEDIUM');
                return res.status(400).render('error', { 
                    error: 'Invalid Input',
                    message: 'The provided data is invalid. Please check your input and try again.'
                });
            }
            next();
        } catch (error) {
            logSecurityEvent(req, 'INPUT_VALIDATION_FAILED', 'Input validation middleware error', 'HIGH');
            res.status(500).render('error', { 
                error: 'Server Error',
                message: 'An error occurred while processing your request'
            });
        }
    };
};

// Rate limiting middleware (basic implementation)
const rateLimit = (maxAttempts = 5, windowMs = 15 * 60 * 1000) => {
    return (req, res, next) => {
        // Initialize rate limit store in app.locals if it doesn't exist
        if (!req.app.locals.rateLimitStore) {
            req.app.locals.rateLimitStore = new Map();
        }
        
        const attempts = req.app.locals.rateLimitStore;
        const key = req.ip;
        const now = Date.now();
        const windowStart = now - windowMs;
        
        if (!attempts.has(key)) {
            attempts.set(key, []);
        }
        
        const userAttempts = attempts.get(key);
        const recentAttempts = userAttempts.filter(timestamp => timestamp > windowStart);
        
        if (recentAttempts.length >= maxAttempts) {
            logSecurityEvent(req, 'ACCESS_DENIED', 'Rate limit exceeded', 'MEDIUM');
            return res.status(429).render('error', { 
                error: 'Too Many Requests',
                message: 'Too many requests from this IP. Please try again later.'
            });
        }
        
        recentAttempts.push(now);
        attempts.set(key, recentAttempts);
        
        next();
    };
};

// Function to reset rate limits
const resetRateLimits = (req) => {
    if (req.app.locals.rateLimitStore) {
        req.app.locals.rateLimitStore.clear();
    }
};

// Security event logging helper
const logSecurityEvent = async (req, eventType, details, severity = 'LOW') => {
    try {
        const auditLog = new AuditLog({
            userId: req.user?._id || null,
            username: req.user?.username || req.body?.username || 'unknown',
            ipAddress: req.ip || req.connection.remoteAddress,
            userAgent: req.get('User-Agent') || 'unknown',
            eventType,
            eventDetails: details,
            severity,
            resource: req.originalUrl,
            method: req.method,
            statusCode: null // Fixed: removed the undefined res reference
        });
        
        await auditLog.save();
    } catch (error) {
        console.error('Failed to log security event:', error);
    }
};

const wantsJson = (req) => {
  const isApi = req.originalUrl.startsWith('/api/');
  const acceptsJson = req.get('Accept')?.includes('application/json');
  const isXhr = req.xhr;
  
  console.log('wantsJson check:', {
    url: req.originalUrl,
    isApi,
    accept: req.get('Accept'),
    acceptsJson,
    isXhr,
    result: isApi || acceptsJson || isXhr
  });
  
  return isApi || acceptsJson || isXhr;
};

module.exports = {
    requireAuth,
    requireRole,
    requireAdministrator,
    requireRoleA,
    requireRoleB,
    requireReAuth,
    validateInput,
    rateLimit,
    resetRateLimits, // Added resetRateLimits to exports
    logSecurityEvent
}; 