const express = require('express');
const authController = require('../controllers/authController');
const { requireAuth, requireReAuth, validateInput, rateLimit } = require('../middleware/auth');
const { loginSchema, changePasswordSchema, reAuthSchema } = require('../validation/schemas');
const bcrypt = require('bcrypt');
const User = require('../models/user');

const router = express.Router();

// Public routes
router.get('/login', (req, res) => {
    if (req.session.userId) {
        return res.redirect('/dashboard');
    }
    res.render('login', { 
        error: null, 
        username: '',
        message: req.query.message || null
    });
});

router.post('/login', 
    rateLimit(5, 15 * 60 * 1000), // 5 attempts per 15 minutes
    validateInput(loginSchema),
    authController.login
);

// Protected routes
router.get('/logout', requireAuth, authController.logout);

router.get('/profile', requireAuth, authController.getProfile);

router.get('/change-password', requireAuth, (req, res) => {
    res.render('changePassword', { error: null, success: null, user: req.user });
});

router.post('/change-password', requireAuth, async (req, res) => {
    const { currentPassword, newPassword, confirmPassword } = req.body;
    const user = await User.findById(req.user._id);

    // 1. Check if password can be changed (once per day)
    if (!user.canChangePassword()) {
        return res.render('changePassword', {
            error: 'You can only change your password once every 24 hours.',
            success: null
        });
    }

    // 2. Check current password
    const isMatch = await user.comparePassword(currentPassword);
    if (!isMatch) {
        return res.render('changePassword', { error: 'Current password is incorrect.', success: null });
    }

    // 3. Check new password requirements
    const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&]).{8,}$/;
    if (!passwordRegex.test(newPassword)) {
        return res.render('changePassword', { error: 'New password does not meet requirements.', success: null });
    }

    // 4. Check new password matches confirmation
    if (newPassword !== confirmPassword) {
        return res.render('changePassword', { error: 'Passwords do not match.', success: null });
    }

    // 5. Set and save new password
    user.password = newPassword;
    await user.save();

    res.render('changePassword', { success: 'Password changed successfully!', error: null });
});

router.get('/reauth', requireAuth, (req, res) => {
    res.render('reauth', { error: null, returnUrl: req.query.returnUrl || '/dashboard' });
});

router.post('/reauth', 
    requireAuth,
    validateInput(reAuthSchema),
    authController.reAuthenticate
);

module.exports = router;