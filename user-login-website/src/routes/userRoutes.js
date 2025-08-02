const express = require('express');
const userController = require('../controllers/userController');
const { requireAuth, requireAdministrator, requireRoleA, validateInput } = require('../middleware/auth');
const { createUserSchema } = require('../validation/schemas');
const User = require('../models/user'); // Assuming the User model is in models/User.js

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

// Edit user form
router.get('/users/:id/edit', requireAuth, requireAdministrator, async (req, res) => {
    const userToEdit = await User.findById(req.params.id);
    if (!userToEdit) return res.status(404).send('User not found');
    res.render('admin/editUser', { userToEdit, error: null, success: null });
});

// Handle edit user POST
router.post('/users/:id/edit', requireAuth, requireAdministrator, async (req, res) => {
    const userToEdit = await User.findById(req.params.id);
    if (!userToEdit) return res.status(404).send('User not found');
    const { role } = req.body;
    if (!['Administrator', 'RoleB'].includes(role)) {
        return res.render('admin/editUser', { userToEdit, error: 'Invalid role.', success: null });
    }
    userToEdit.role = role;
    await userToEdit.save();
    res.render('admin/editUser', { userToEdit, error: null, success: 'Role updated successfully.' });
});

// API routes for user management
router.put('/api/users/:id', requireAuth, requireRoleA, userController.updateUser);
router.delete('/api/users/:id', requireAuth, requireRoleA, userController.deleteUser);

module.exports = router;