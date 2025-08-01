const User = require('../models/user');
const { logSecurityEvent } = require('../middleware/auth');
const { createUserSchema, updateUserSchema } = require('../validation/schemas');
const mongoose = require('mongoose');

class UserController {
    // Get all users (Administrators only)
    async getAllUsers(req, res) {
        try {
            const page = parseInt(req.query.page) || 1;
            const limit = parseInt(req.query.limit) || 10;
            const skip = (page - 1) * limit;

            const users = await User.find({})
                .select('-password -passwordHistory')
                .sort({ createdAt: -1 })
                .skip(skip)
                .limit(limit);

            const totalUsers = await User.countDocuments({});
            const totalPages = Math.ceil(totalUsers / limit);

            res.render('admin/users', {
                users,
                currentPage: page,
                totalPages,
                totalUsers,
                user: req.user
            });
        } catch (err) {
            console.error('Get all users error:', err);
            await logSecurityEvent(req, 'ACCESS_DENIED', 'Error retrieving users', 'HIGH');
            res.status(500).render('error', {
                error: 'Server Error',
                message: 'An error occurred while retrieving users'
            });
        }
    }

    // Get users by role (Role A users can manage Role B users)
    async getUsersByRole(req, res) {
        try {
            let query = {};
            
            // Role A users can only see Role B users
            if (req.user.role === 'RoleA') {
                query.role = 'RoleB';
            }

            const users = await User.find(query)
                .select('-password -passwordHistory')
                .sort({ createdAt: -1 });

            // Render the same view as admin for consistency
            res.render('admin/users', {
                users,
                user: req.user,
                currentPage: 1,
                totalPages: 1,
                totalUsers: users.length
            });
        } catch (err) {
            console.error('Get users by role error:', err);
            await logSecurityEvent(req, 'ACCESS_DENIED', 'Error retrieving users by role', 'HIGH');
            res.status(500).render('error', {
                error: 'Server Error',
                message: 'An error occurred while retrieving users'
            });
        }
    }

    // Create new user
    async createUser(req, res) {
        try {
            // Remove confirmPassword before validation
            const { confirmPassword, ...userData } = req.body;
            const { error } = createUserSchema.validate(userData);
            if (error) {
                await logSecurityEvent(req, 'INPUT_VALIDATION_FAILED', `User creation validation failed: ${error.details[0].message}`, 'MEDIUM');
                return res.render('admin/createUser', {
                    error: 'Invalid input. Please check your data.',
                    user: req.user,
                    formData: req.body,
                    success: undefined
                });
            }

            const { username, email, password, role } = userData;

            if (!password || !confirmPassword || password !== confirmPassword) {
                return res.render('admin/createUser', {
                    error: 'Passwords do not match.',
                    user: req.user,
                    formData: req.body,
                    success: undefined
                });
            }

            // Check role permissions
            if (req.user.role === 'RoleA' && role !== 'RoleB') {
                await logSecurityEvent(req, 'ACCESS_DENIED', `Role A user attempted to create user with role: ${role}`, 'HIGH');
                return res.render('admin/createUser', {
                    error: 'You can only create Role B users.',
                    user: req.user,
                    formData: req.body,
                    success: undefined
                });
            }

            // Check if user already exists
            const existingUser = await User.findOne({
                $or: [{ username }, { email }]
            });

            if (existingUser) {
                return res.render('admin/createUser', {
                    error: 'Username or email already exists.',
                    user: req.user,
                    formData: req.body,
                    success: undefined
                });
            }

            // Create user
            const newUser = new User({
                username,
                email,
                password,
                role,
                createdBy: req.user._id
            });

            await newUser.save();

            await logSecurityEvent(req, 'USER_CREATED', `User created: ${username} with role: ${role}`, 'MEDIUM');

            // Render the form with a success message and empty formData
            res.render('admin/createUser', {
                error: null,
                user: req.user,
                formData: {},
                success: `User '${username}' created successfully.`
            });
        } catch (err) {
            console.error('Create user error:', err);
            await logSecurityEvent(req, 'USER_CREATED', 'User creation system error', 'HIGH');
            res.render('admin/createUser', {
                error: 'An error occurred while creating the user. Please try again.',
                user: req.user,
                formData: req.body,
                success: undefined
            });
        }
    }

    // Update user
    async updateUser(req, res) {
        try {
            const userId = req.params.id;
            const { error } = updateUserSchema.validate(req.body);
            
            if (error) {
                await logSecurityEvent(req, 'INPUT_VALIDATION_FAILED', `User update validation failed: ${error.details[0].message}`, 'MEDIUM');
                return res.status(400).json({
                    error: 'Invalid input. Please check your data.'
                });
            }

            const userToUpdate = await User.findById(userId);
            if (!userToUpdate) {
                return res.status(404).json({
                    error: 'User not found.'
                });
            }

            // Check permissions
            if (req.user.role === 'RoleA') {
                if (userToUpdate.role !== 'RoleB') {
                    await logSecurityEvent(req, 'ACCESS_DENIED', `Role A user attempted to update user with role: ${userToUpdate.role}`, 'HIGH');
                    return res.status(403).json({
                        error: 'You can only update Role B users.'
                    });
                }
                if (req.body.role && req.body.role !== 'RoleB') {
                    await logSecurityEvent(req, 'ACCESS_DENIED', `Role A user attempted to change user role to: ${req.body.role}`, 'HIGH');
                    return res.status(403).json({
                        error: 'You can only assign Role B to users.'
                    });
                }
            }

            // Update user
            const updateData = { ...req.body };
            delete updateData.password; // Password changes handled separately

            const updatedUser = await User.findByIdAndUpdate(
                userId,
                updateData,
                { new: true, runValidators: true }
            ).select('-password -passwordHistory');

            await logSecurityEvent(req, 'USER_UPDATED', `User updated: ${updatedUser.username}`, 'MEDIUM');

            res.json({
                success: true,
                user: updatedUser
            });
        } catch (err) {
            console.error('Update user error:', err);
            await logSecurityEvent(req, 'USER_UPDATED', 'User update system error', 'HIGH');
            res.status(500).json({
                error: 'An error occurred while updating the user.'
            });
        }
    }

    // Delete user
    async deleteUser(req, res) {
        try {
            const userId = req.params.id;
            console.log('Delete user request for ID:', userId, 'by user:', req.user.username);

            const userToDelete = await User.findById(userId);
            if (!userToDelete) {
                console.log('User not found:', userId);
                return res.status(404).json({
                    error: 'User not found.'
                });
            }

            console.log('Found user to delete:', userToDelete.username, 'role:', userToDelete.role);

            // Check permissions
            if (req.user.role === 'RoleA') {
                if (userToDelete.role !== 'RoleB') {
                    await logSecurityEvent(req, 'ACCESS_DENIED', `Role A user attempted to delete user with role: ${userToDelete.role}`, 'HIGH');
                    return res.status(403).json({
                        error: 'You can only delete Role B users.'
                    });
                }
            }

            // Allow self-deletion for Role B users, prevent for others
            if (userId === req.user._id.toString()) {
                if (req.user.role !== 'RoleB') {
                    await logSecurityEvent(req, 'ACCESS_DENIED', `${req.user.role} user attempted to delete their own account`, 'HIGH');
                    return res.status(403).json({
                        error: 'You cannot delete your own account.'
                    });
                }
                // Role B users can delete their own account
                console.log('Role B user self-deletion request:', userToDelete.username);
            }
            else{
                console.log('User deletion request is valid for user:', userToDelete.username);
            }
            await User.findByIdAndDelete(userId);
            console.log('User deleted successfully:', userToDelete.username);

            await logSecurityEvent(req, 'USER_DELETED', `User deleted: ${userToDelete.username}`, 'HIGH');

            res.json({
                success: true,
                message: 'User deleted successfully.'
            });
        } catch (err) {
            console.error('Delete user error:', err);
            await logSecurityEvent(req, 'USER_DELETED', 'User deletion system error', 'HIGH');
            res.status(500).json({
                error: 'An error occurred while deleting the user: ' + err.message
            });
        }
    }

    // Self-delete account (for Role B users)
    async deleteOwnAccount(req, res) {
        try {
            const userId = req.user._id;

            // Only Role B users can delete their own account
            if (req.user.role !== 'RoleB') {
                await logSecurityEvent(req, 'ACCESS_DENIED', `${req.user.role} user attempted to delete their own account`, 'HIGH');
                return res.status(403).render('error', {
                    error: 'Access Denied',
                    message: 'Only Role B users can delete their own account.'
                });
            }

            // Check if confirmation was provided
            if (!req.body.confirmation || req.body.confirmation !== 'DELETE') {
                return res.status(400).render('users/deleteAccount', {
                    user: req.user,
                    error: 'Please type "DELETE" to confirm account deletion.'
                });
            }

            // Delete the user account
            const result = await User.findByIdAndDelete(userId);
            
            if (!result) {
                return res.status(404).render('error', {
                    error: 'User Not Found',
                    message: 'User account not found.'
                });
            }

            await logSecurityEvent(req, 'USER_DELETED', `User self-deleted: ${req.user.username}`, 'HIGH');

            // Destroy the session
            req.session.destroy((err) => {
                if (err) {
                    console.error('Error destroying session:', err);
                }
                
                // Redirect to login page with success message
                res.redirect('/auth/login?message=Account deleted successfully');
            });

        } catch (err) {
            console.error('Self-delete error:', err);
            await logSecurityEvent(req, 'USER_DELETED', 'User self-deletion system error', 'HIGH');
            res.status(500).render('error', {
                error: 'Server Error',
                message: 'An error occurred while deleting your account: ' + err.message
            });
        }
    }

    // Show delete account confirmation page
    async showDeleteAccountConfirmation(req, res) {
        try {
            // Only Role B users can access this page
            if (req.user.role !== 'RoleB') {
                await logSecurityEvent(req, 'ACCESS_DENIED', `${req.user.role} user attempted to access delete account page`, 'HIGH');
                return res.status(403).render('error', {
                    error: 'Access Denied',
                    message: 'Only Role B users can delete their own account.'
                });
            }

            res.render('users/deleteAccount', {
                user: req.user,
                error: null
            });
        } catch (err) {
            console.error('Show delete account confirmation error:', err);
            res.status(500).render('error', {
                error: 'Server Error',
                message: 'An error occurred while loading the page.'
            });
        }
    }

    // Get user details
    async getUserDetails(req, res) {
        try {
            const userId = req.params.id;

            const user = await User.findById(userId).select('-password -passwordHistory');
            if (!user) {
                return res.status(404).render('error', {
                    error: 'User Not Found',
                    message: 'The requested user does not exist.'
                });
            }

            // Check permissions
            if (req.user.role === 'RoleA' && user.role !== 'RoleB') {
                await logSecurityEvent(req, 'ACCESS_DENIED', `Role A user attempted to view user with role: ${user.role}`, 'HIGH');
                return res.status(403).render('error', {
                    error: 'Access Denied',
                    message: 'You do not have permission to view this user.'
                });
            }

            res.render('users/details', {
                user,
                currentUser: req.user
            });
        } catch (err) {
            console.error('Get user details error:', err);
            res.status(500).render('error', {
                error: 'Server Error',
                message: 'An error occurred while retrieving user details.'
            });
        }
    }
}

module.exports = new UserController(); 