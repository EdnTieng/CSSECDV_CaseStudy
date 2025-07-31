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
router.get('/users/:id', requireAuth, requireRoleA, userController.getUserDetails);

// API routes for user management
router.put('/api/users/:id', requireAuth, requireRoleA, userController.updateUser);
router.delete('/api/users/:id', requireAuth, requireRoleA, userController.deleteUser);

module.exports = router;