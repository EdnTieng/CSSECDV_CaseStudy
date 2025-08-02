const mongoose = require('mongoose');
const bcrypt = require('bcrypt'); // Make sure bcrypt is imported

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
    // =======================================================
    // START: ENSURE THESE FIELDS ARE PRESENT AND CORRECT
    // =======================================================
    securityQuestion: {
        type: String,
        required: true, // IMPORTANT: Make sure this is true if you want it always set
        trim: true
    },
    securityAnswer: {
        type: String,
        required: true, // IMPORTANT: Make sure this is true
    },
    // =======================================================
    // END: ENSURE THESE FIELDS ARE PRESENT AND CORRECT
    // =======================================================
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

// Password complexity validation and hashing
userSchema.pre('save', async function(next) {
    if (this.isModified('password')) {
        const isHashed = /^\$2[aby]\$/.test(this.password);
        if (!isHashed) {
            const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;
            if (!passwordRegex.test(this.password)) {
                return next(new Error('Password must contain at least 8 characters, including uppercase, lowercase, number, and special character'));
            }

            if (this.passwordHistory && this.passwordHistory.length > 0) {
                const last5 = this.passwordHistory.slice(-5);
                for (let i = 0; i < last5.length; i++) {
                    const isMatch = await bcrypt.compare(this.password, last5[i].password);
                    if (isMatch) {
                        return next(new Error('Password cannot be the same as your last 5 passwords'));
                    }
                }
            }

            const saltRounds = 12;
            const hashed = await bcrypt.hash(this.password, saltRounds);

            if (this.isNew === false && this.isModified('password')) {
                this.passwordHistory = this.passwordHistory || [];
                this.passwordHistory.push({
                    password: hashed,
                    changedAt: new Date()
                });
                if (this.passwordHistory.length > 10) {
                    this.passwordHistory = this.passwordHistory.slice(-10);
                }
            }
            this.password = hashed;
            this.passwordChangedAt = new Date();
        }
    }
    next();
});

// =======================================================
// START: ENSURE THIS PRE-SAVE HOOK AND METHOD ARE PRESENT
// =======================================================
// Hash security answer before saving
userSchema.pre('save', async function(next) {
    // Only hash if the securityAnswer has been modified (or is new)
    if (this.isModified('securityAnswer')) {
        const saltRounds = 10; // Can be slightly lower than password salt
        this.securityAnswer = await bcrypt.hash(this.securityAnswer, saltRounds);
    }
    next();
});

// Method to compare security answer
userSchema.methods.compareSecurityAnswer = async function(candidateAnswer) {
    try {
        const result = await bcrypt.compare(candidateAnswer, this.securityAnswer);
        return result;
    } catch (error) {
        console.error('bcrypt.compare security answer error:', error);
        throw error;
    }
};
// =======================================================
// END: ENSURE THESE PRE-SAVE HOOK AND METHOD ARE PRESENT
// =======================================================

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

// Account lockout methods
userSchema.methods.isAccountLocked = function() {
    if (!this.accountLocked) return false;
    if (!this.lockoutUntil) return false;
    return new Date() < this.lockoutUntil;
};

userSchema.methods.incrementFailedAttempts = function() {
    this.failedLoginAttempts += 1;
    if (this.failedLoginAttempts >= 5) {
        this.accountLocked = true;
        this.lockoutUntil = new Date(Date.now() + 15 * 60 * 1000); // 15 minutes
    }
};

userSchema.methods.resetFailedAttempts = function() {
    this.failedLoginAttempts = 0;
    this.accountLocked = false;
    this.lockoutUntil = null;
};

// Password change validation
userSchema.methods.canChangePassword = function() {
    const oneDayAgo = new Date(Date.now() - 24 * 60 * 60 * 1000);
    return this.passwordChangedAt < oneDayAgo;
};

// Update last login information
userSchema.methods.updateLastLogin = function(ipAddress) {
    this.lastLoginAt = new Date();
    this.lastLoginIp = ipAddress;
};

const User = mongoose.model('User', userSchema);

module.exports = User;