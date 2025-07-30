const Joi = require('joi');

// Login validation schema
const loginSchema = Joi.object({
    username: Joi.string()
        .alphanum()
        .min(3)
        .max(50)
        .required()
        .messages({
            'string.alphanum': 'Username must contain only alphanumeric characters',
            'string.min': 'Username must be at least 3 characters long',
            'string.max': 'Username cannot exceed 50 characters',
            'any.required': 'Username is required'
        }),
    password: Joi.string()
        .min(8)
        .required()
        .messages({
            'string.min': 'Password must be at least 8 characters long',
            'any.required': 'Password is required'
        })
});

// User creation validation schema
const createUserSchema = Joi.object({
    username: Joi.string()
        .alphanum()
        .min(3)
        .max(50)
        .required()
        .messages({
            'string.alphanum': 'Username must contain only alphanumeric characters',
            'string.min': 'Username must be at least 3 characters long',
            'string.max': 'Username cannot exceed 50 characters',
            'any.required': 'Username is required'
        }),
    email: Joi.string()
        .email()
        .required()
        .messages({
            'string.email': 'Please provide a valid email address',
            'any.required': 'Email is required'
        }),
    password: Joi.string()
        .pattern(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/)
        .required()
        .messages({
            'string.pattern.base': 'Password must contain at least 8 characters, including uppercase, lowercase, number, and special character',
            'any.required': 'Password is required'
        }),
    role: Joi.string()
        .valid('Administrator', 'RoleA', 'RoleB')
        .required()
        .messages({
            'any.only': 'Role must be Administrator, RoleA, or RoleB',
            'any.required': 'Role is required'
        }),
    confirmPassword: Joi.any().optional() // Allow confirmPassword in the body, but do not validate it
});

// User update validation schema
const updateUserSchema = Joi.object({
    username: Joi.string()
        .alphanum()
        .min(3)
        .max(50)
        .optional()
        .messages({
            'string.alphanum': 'Username must contain only alphanumeric characters',
            'string.min': 'Username must be at least 3 characters long',
            'string.max': 'Username cannot exceed 50 characters'
        }),
    email: Joi.string()
        .email()
        .optional()
        .messages({
            'string.email': 'Please provide a valid email address'
        }),
    role: Joi.string()
        .valid('Administrator', 'RoleA', 'RoleB')
        .optional()
        .messages({
            'any.only': 'Role must be Administrator, RoleA, or RoleB'
        }),
    isActive: Joi.boolean()
        .optional()
        .messages({
            'boolean.base': 'isActive must be a boolean value'
        })
});

// Password change validation schema
const changePasswordSchema = Joi.object({
    currentPassword: Joi.string()
        .required()
        .messages({
            'any.required': 'Current password is required'
        }),
    newPassword: Joi.string()
        .pattern(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/)
        .required()
        .messages({
            'string.pattern.base': 'New password must contain at least 8 characters, including uppercase, lowercase, number, and special character',
            'any.required': 'New password is required'
        }),
    confirmPassword: Joi.string()
        .valid(Joi.ref('newPassword'))
        .required()
        .messages({
            'any.only': 'Password confirmation must match new password',
            'any.required': 'Password confirmation is required'
        })
});

// Re-authentication validation schema
const reAuthSchema = Joi.object({
    password: Joi.string()
        .required()
        .messages({
            'any.required': 'Password is required'
        })
});

// Audit log query validation schema
const auditLogQuerySchema = Joi.object({
    startDate: Joi.date()
        .optional()
        .messages({
            'date.base': 'Start date must be a valid date'
        }),
    endDate: Joi.date()
        .min(Joi.ref('startDate'))
        .optional()
        .messages({
            'date.base': 'End date must be a valid date',
            'date.min': 'End date must be after start date'
        }),
    eventType: Joi.string()
        .valid('LOGIN_SUCCESS', 'LOGIN_FAILED', 'LOGOUT', 'PASSWORD_CHANGE', 'PASSWORD_RESET', 'ACCOUNT_LOCKED', 'ACCOUNT_UNLOCKED', 'USER_CREATED', 'USER_UPDATED', 'USER_DELETED', 'ROLE_CHANGED', 'ACCESS_DENIED', 'INPUT_VALIDATION_FAILED', 'CRITICAL_OPERATION', 'PROFILE_VIEWED')
        .optional()
        .messages({
            'any.only': 'Invalid event type'
        }),
    severity: Joi.string()
        .valid('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')
        .optional()
        .messages({
            'any.only': 'Invalid severity level'
        }),
    username: Joi.string()
        .optional()
        .messages({
            'string.base': 'Username must be a string'
        }),
    limit: Joi.number()
        .integer()
        .min(1)
        .max(1000)
        .default(50)
        .optional()
        .messages({
            'number.base': 'Limit must be a number',
            'number.integer': 'Limit must be an integer',
            'number.min': 'Limit must be at least 1',
            'number.max': 'Limit cannot exceed 1000'
        }),
    page: Joi.number()
        .integer()
        .min(1)
        .default(1)
        .optional()
        .messages({
            'number.base': 'Page must be a number',
            'number.integer': 'Page must be an integer',
            'number.min': 'Page must be at least 1'
        })
});

module.exports = {
    loginSchema,
    createUserSchema,
    updateUserSchema,
    changePasswordSchema,
    reAuthSchema,
    auditLogQuerySchema
}; 