const express = require('express');
const authController = require('../controllers/authController');
const { requireAuth, requireReAuth, validateInput, rateLimit } = require('../middleware/auth');
const { loginSchema, changePasswordSchema, reAuthSchema } = require('../validation/schemas');

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

router.post('/change-password', 
    requireAuth,
    requireReAuth,
    validateInput(changePasswordSchema),
    authController.changePassword
);

router.get('/reauth', requireAuth, (req, res) => {
    res.render('reauth', { error: null, returnUrl: req.query.returnUrl || '/dashboard' });
});

router.post('/reauth', 
    requireAuth,
    validateInput(reAuthSchema),
    authController.reAuthenticate
);

module.exports = router;