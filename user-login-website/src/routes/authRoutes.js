const express = require('express');
const authController = require('../controllers/authController');

const router = express.Router();

// Example route
router.get('/login', (req, res) => {
    res.send('Login Page');
});

router.post('/login', authController.login);
router.post('/logout', authController.logout);

module.exports = router;