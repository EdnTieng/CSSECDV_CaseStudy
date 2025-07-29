const mongoose = require('mongoose');
const bcrypt = require('bcrypt');

const userSchema = new mongoose.Schema({
    username: {
        type: String,
        required: true,
        unique: true,
        trim: true,
        minlength: 3,
        maxlength: 50,
        match: /^[a-zA-Z0-9_]+$/
    },
    password: {
        type: String,
        required: true,
        minlength: 8
    },
    role: {
        type: String,
        enum: ['Administrator', 'RoleA', 'RoleB'],
        required: true,
        default: 'RoleB'
    },
    email: {
        type: String,
        required: true,
        unique: true,
        lowercase: true,
        trim: true,
        match: /^[^\s@]+@[^\s@]+\.[^\s@]+$/
    },
    // Security fields
    failedLoginAttempts: {
        type: Number,
        default: 0
    },
    accountLocked: {
        type: Boolean,
        default: false
    },
    lockoutUntil: {
        type: Date,
        default: null
    },
    passwordHistory: [{
        password: String,
        changedAt: {
            type: Date,
            default: Date.now
        }
    }],
    passwordChangedAt: {
        type: Date,
        default: Date.now
    },
    lastLoginAt: {
        type: Date,
        default: null
    },
    lastLoginIp: {
        type: String,
        default: null
    },
    // Audit fields
    createdAt: {
        type: Date,
        default: Date.now
    },
    updatedAt: {
        type: Date,
        default: Date.now
    },
    createdBy: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        default: null
    },
    isActive: {
        type: Boolean,
        default: true
    }
}, {
    timestamps: true
});

// Password complexity validation
userSchema.pre('save', async function(next) {
    if (this.isModified('password')) {
        // Password complexity requirements
        const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;
        
        if (!passwordRegex.test(this.password)) {
            const error = new Error('Password must contain at least 8 characters, including uppercase, lowercase, number, and special character');
            return next(error);
        }

        // Check password history (prevent reuse of last 5 passwords)
        if (this.passwordHistory.length > 0) {
            for (let i = 0; i < Math.min(5, this.passwordHistory.length); i++) {
                const isMatch = await bcrypt.compare(this.password, this.passwordHistory[i].password);
                if (isMatch) {
                    const error = new Error('Password cannot be the same as your last 5 passwords');
                    return next(error);
                }
            }
        }

        // Hash password
        const saltRounds = 12;
        this.password = await bcrypt.hash(this.password, saltRounds);
        
        // Add to password history
        this.passwordHistory.push({
            password: this.password,
            changedAt: new Date()
        });

        // Keep only last 10 passwords in history
        if (this.passwordHistory.length > 10) {
            this.passwordHistory = this.passwordHistory.slice(-10);
        }

        this.passwordChangedAt = new Date();
    }
    next();
});

// Password comparison method
userSchema.methods.comparePassword = async function(candidatePassword) {
    try {
        const result = await bcrypt.compare(candidatePassword, this.password);
        return result;
    } catch (error) {
        console.error('bcrypt.compare error:', error);
        throw error;
    }
};

// Check if account is locked
userSchema.methods.isAccountLocked = function() {
    if (!this.accountLocked) return false;
    if (this.lockoutUntil && this.lockoutUntil > new Date()) return true;
    
    // Auto-unlock after 30 minutes
    if (this.lockoutUntil && this.lockoutUntil <= new Date()) {
        this.accountLocked = false;
        this.failedLoginAttempts = 0;
        this.lockoutUntil = null;
        return false;
    }
    return false;
};

// Increment failed login attempts
userSchema.methods.incrementFailedAttempts = function() {
    this.failedLoginAttempts += 1;
    if (this.failedLoginAttempts >= 5) {
        this.accountLocked = true;
        this.lockoutUntil = new Date(Date.now() + 30 * 60 * 1000); // 30 minutes
    }
};

// Reset failed login attempts
userSchema.methods.resetFailedAttempts = function() {
    this.failedLoginAttempts = 0;
    this.accountLocked = false;
    this.lockoutUntil = null;
};

// Check if password is old enough to change (minimum 1 day)
userSchema.methods.canChangePassword = function() {
    const oneDayAgo = new Date(Date.now() - 24 * 60 * 60 * 1000);
    return this.passwordChangedAt <= oneDayAgo;
};

// Update last login
userSchema.methods.updateLastLogin = function(ipAddress) {
    this.lastLoginAt = new Date();
    this.lastLoginIp = ipAddress;
};

const User = mongoose.model('User', userSchema);

module.exports = User;