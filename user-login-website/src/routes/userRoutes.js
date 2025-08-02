const express = require('express');
const userController = require('../controllers/userController');
const { requireAuth, requireAdministrator, requireRoleA, validateInput } = require('../middleware/auth');
const { createUserSchema } = require('../validation/schemas');

const router = express.Router();

// Administrator routes
router.get('/users', requireAuth, requireAdministrator, userController.getAllUsers);
router.get('/users/create', requireAuth, requireAdministrator, (req, res) => {
    res.render('admin/createUser', { error: null, user: req.user, formData: {}, success: undefined });
});
router.post('/users/create', 
    requireAuth,
    requireAdministrator,
    validateInput(createUserSchema),
    userController.createUser
);

// Role A routes (can manage Role B users)
router.get('/users/manage', requireAuth, requireRoleA, userController.getUsersByRole);
router.get('/users/manage/create', requireAuth, requireRoleA, (req, res) => {
    res.render('admin/createUser', { error: null, user: req.user, formData: {}, success: undefined });
});
router.post('/users/manage/create', 
    requireAuth,
    requireRoleA,
    validateInput(createUserSchema),
    userController.createUser
);

// Self-deletion routes (for Role B users) - Must come before /users/:id
router.get('/delete-account', requireAuth, userController.showDeleteAccountConfirmation);
router.post('/delete-account', requireAuth, userController.deleteOwnAccount);

router.get('/users/:id', requireAuth, requireRoleA, userController.getUserDetails);

// Test route to verify API is working
router.get('/api/test', (req, res) => {
    console.log('Test API route hit!');
    res.json({ success: true, message: 'API is working!' });
});

// API routes for user management
router.put('/api/users/:id', requireAuth, requireAdministrator, userController.updateUser);
// Show change role page
router.get('/users/:id/change-role', requireAuth, requireAdministrator, userController.showChangeRolePage);

// Update user role
router.post('/users/:id/role', requireAuth, requireAdministrator, userController.updateUserRole);
router.delete('/api/users/:id', requireAuth, requireRoleA, userController.deleteUser);

module.exports = router;