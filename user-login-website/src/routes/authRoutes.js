const express = require('express');
const authController = require('../controllers/authController');
const { requireAuth, requireReAuth, validateInput, rateLimit } = require('../middleware/auth');
const { loginSchema, changePasswordSchema, reAuthSchema } = require('../validation/schemas');
const bcrypt = require('bcrypt');
const User = require('../models/user');

const router = express.Router();

// =================================================================
// PUBLIC ROUTES (No Login Required)
// =================================================================

// --- Login ---
router.get('/login', (req, res) => {
    // This route is for users who are NOT logged in.
    if (req.session.userId) {
        return res.redirect('/dashboard');
    }
    // Render the login page, passing any success message from the password reset flow.
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

// =================================================================
// START: NEW PUBLIC ROUTES FOR PASSWORD RESET
// =================================================================

// --- Forgot Password Flow ---
// 1. Show the 'forgot password' form where the user enters their username.
router.get('/forgot-password', (req, res) => {
    if (req.session.userId) {
        return res.redirect('/dashboard'); // Redirect logged-in users away
    }
    res.render('forgotPassword', { error: null, success: null });
});

// 2. Handle the username submission.
router.post('/forgot-password', authController.handleForgotPassword);

// 3. Show the form to answer the security question and set a new password.
router.get('/reset-password', (req, res) => {
    if (req.session.userId) {
        return res.redirect('/dashboard'); // Redirect logged-in users away
    }
    authController.showResetPasswordForm(req, res);
});

// 4. Handle the final password reset submission.
router.post('/reset-password', authController.handleResetPassword);

// =================================================================
// END: NEW PUBLIC ROUTES
// =================================================================


// =================================================================
// PROTECTED ROUTES (Login Required via 'requireAuth' middleware)
// =================================================================

// --- Logout ---
router.get('/logout', requireAuth, authController.logout);

// --- User Profile ---
router.get('/profile', requireAuth, authController.getProfile);

// --- Re-authentication for sensitive actions ---
router.get('/reauth', requireAuth, (req, res) => {
    res.render('reauth', { error: null, returnUrl: req.query.returnUrl || '/dashboard' });
});

router.post('/reauth', 
    requireAuth,
    validateInput(reAuthSchema),
    authController.reAuthenticate
);

// =================================================================
// START: NEW PROTECTED ROUTE FOR UPDATING SECURITY INFO
// =================================================================

// --- Update Security Question & Answer from Profile Page ---
router.post('/update-security', requireAuth, authController.updateSecurityQuestion);

// =================================================================
// END: NEW PROTECTED ROUTE
// =================================================================

// --- Change Password (for logged-in users) ---
// Note: Your original file had the logic here. It's better practice to keep this logic
// in the controller. I've left your original implementation as is, but you could
// move it to authController.changePassword for consistency.
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
            success: null,
            user: req.user
        });
    }

    // 2. Check current password
    const isMatch = await user.comparePassword(currentPassword);
    if (!isMatch) {
        return res.render('changePassword', { error: 'Current password is incorrect.', success: null, user: req.user });
    }

    // 3. Check new password requirements
    const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&]).{8,}$/;
    if (!passwordRegex.test(newPassword)) {
        return res.render('changePassword', { error: 'New password does not meet requirements.', success: null, user: req.user });
    }

    // 4. Check new password matches confirmation
    if (newPassword !== confirmPassword) {
        return res.render('changePassword', { error: 'New passwords do not match.', success: null, user: req.user });
    }

    // 5. Check password history (prevent reuse of last 5 passwords)
    if (user.passwordHistory && user.passwordHistory.length > 0) {
        const last5 = user.passwordHistory.slice(-5);
        for (let i = 0; i < last5.length; i++) {
            const isPrev = await bcrypt.compare(newPassword, last5[i].password);
            if (isPrev) {
                return res.render('changePassword', {
                    error: 'You cannot reuse any of your last 5 passwords.',
                    success: null,
                    user: req.user
                });
            }
        }
    }

    // 6. Set and save new password
    try {
        user.password = newPassword;
        await user.save();
        res.render('changePassword', { success: 'Password changed successfully!', error: null, user: req.user });
    } catch (err) {
        res.render('changePassword', { error: err.message, success: null, user: req.user });
    }
});

module.exports = router;