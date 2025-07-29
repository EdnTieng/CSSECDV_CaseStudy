const User = require('../models/user');
const { logSecurityEvent } = require('../middleware/auth');
const { loginSchema, changePasswordSchema, reAuthSchema } = require('../validation/schemas');
const Joi = require('joi');

class AuthController {
    async login(req, res) {
        try {
            // Validate input
            const { error } = loginSchema.validate(req.body);
            if (error) {
                await logSecurityEvent(req, 'INPUT_VALIDATION_FAILED', `Login validation failed: ${error.details[0].message}`, 'MEDIUM');
                return res.render('login', { 
                    error: 'Invalid username and/or password',
                    username: req.body.username 
                });
            }

            const { username, password } = req.body;

            // Find user
            const user = await User.findOne({ username, isActive: true });
            
            if (!user) {
                await logSecurityEvent(req, 'LOGIN_FAILED', `Failed login attempt for username: ${username}`, 'MEDIUM');
                return res.render('login', { 
                    error: 'Invalid username and/or password',
                    username: req.body.username 
                });
            }

            // Check if account is locked
            if (user.isAccountLocked()) {
                await logSecurityEvent(req, 'ACCESS_DENIED', `Login attempt on locked account: ${username}`, 'HIGH');
                return res.render('login', { 
                    error: 'Account is temporarily locked due to multiple failed login attempts. Please try again later.',
                    username: req.body.username 
                });
            }

            // Verify password
            const isMatch = await user.comparePassword(password);
            
            if (!isMatch) {
                user.incrementFailedAttempts();
                await user.save();
                
                await logSecurityEvent(req, 'LOGIN_FAILED', `Failed login attempt for user: ${username}`, 'MEDIUM');
                
                if (user.accountLocked) {
                    await logSecurityEvent(req, 'ACCOUNT_LOCKED', `Account locked for user: ${username}`, 'HIGH');
                    return res.render('login', { 
                        error: 'Account is temporarily locked due to multiple failed login attempts. Please try again later.',
                        username: req.body.username 
                    });
                }
                
                return res.render('login', { 
                    error: 'Invalid username and/or password',
                    username: req.body.username 
                });
            }

            // Reset failed attempts on successful login
            user.resetFailedAttempts();
            user.updateLastLogin(req.ip);
            await user.save();

            // Set session
            req.session.userId = user._id;
            req.session.userRole = user.role;
            req.session.lastLoginAt = user.lastLoginAt;

            await logSecurityEvent(req, 'LOGIN_SUCCESS', `Successful login for user: ${username}`, 'LOW');
            res.redirect('/dashboard');
        } catch (err) {
            console.error('Login error:', err);
            await logSecurityEvent(req, 'CRITICAL_OPERATION', `Login error: ${err.message}`, 'HIGH');
            res.render('login', { 
                error: 'An error occurred during login. Please try again.',
                username: req.body.username 
            });
        }
    }

    async logout(req, res) {
        try {
            await logSecurityEvent(req, 'LOGOUT', `User logged out: ${req.user?.username}`, 'LOW');
            req.session.destroy((err) => {
                if (err) {
                    console.error('Session destruction error:', err);
                }
                res.redirect('/auth/login');
            });
        } catch (error) {
            console.error('Logout error:', error);
            res.redirect('/auth/login');
        }
    }

    async changePassword(req, res) {
        try {
            const { error } = changePasswordSchema.validate(req.body);
            if (error) {
                await logSecurityEvent(req, 'INPUT_VALIDATION_FAILED', `Change password validation failed: ${error.details[0].message}`, 'MEDIUM');
                return res.render('changePassword', { 
                    error: 'Invalid input. Please check your password requirements.',
                    user: req.user 
                });
            }

            const { currentPassword, newPassword } = req.body;
            const user = await User.findById(req.user._id);

            const isCurrentPasswordValid = await user.comparePassword(currentPassword);
            if (!isCurrentPasswordValid) {
                await logSecurityEvent(req, 'ACCESS_DENIED', `Change password attempt with incorrect current password for user: ${user.username}`, 'MEDIUM');
                return res.render('changePassword', { 
                    error: 'Current password is incorrect.',
                    user: req.user 
                });
            }

            if (!user.canChangePassword()) {
                await logSecurityEvent(req, 'ACCESS_DENIED', `Change password attempt on user: ${user.username} before password age`, 'MEDIUM');
                return res.render('changePassword', { 
                    error: 'Password must be at least one day old before it can be changed.',
                    user: req.user 
                });
            }

            user.password = newPassword;
            await user.save();

            await logSecurityEvent(req, 'PASSWORD_CHANGED', `Password changed for user: ${user.username}`, 'LOW');
            res.render('changePassword', { 
                success: 'Password changed successfully.',
                user: req.user 
            });
        } catch (err) {
            console.error('Password change error:', err);
            await logSecurityEvent(req, 'CRITICAL_OPERATION', `Password change error: ${err.message}`, 'HIGH');
            res.render('changePassword', { 
                error: 'An error occurred while changing password. Please try again.',
                user: req.user 
            });
        }
    }

    async reAuthenticate(req, res) {
        try {
            const { error } = reAuthSchema.validate(req.body);
            if (error) {
                await logSecurityEvent(req, 'INPUT_VALIDATION_FAILED', `Re-authentication validation failed: ${error.details[0].message}`, 'MEDIUM');
                return res.render('reauth', { 
                    error: 'Password is required.',
                    returnUrl: req.body.returnUrl 
                });
            }

            const { password, returnUrl } = req.body;
            const user = await User.findById(req.user._id);

            const isPasswordValid = await user.comparePassword(password);
            if (!isPasswordValid) {
                await logSecurityEvent(req, 'ACCESS_DENIED', `Re-authentication attempt with incorrect password for user: ${user.username}`, 'MEDIUM');
                return res.render('reauth', { 
                    error: 'Password is incorrect.',
                    returnUrl: returnUrl 
                });
            }

            req.session.reAuthVerified = true;
            await logSecurityEvent(req, 'REAUTH_SUCCESS', `User re-authenticated: ${user.username}`, 'LOW');
            res.redirect(returnUrl || '/dashboard');
        } catch (err) {
            console.error('Re-authentication error:', err);
            await logSecurityEvent(req, 'CRITICAL_OPERATION', `Re-authentication error: ${err.message}`, 'HIGH');
            res.render('reauth', { 
                error: 'An error occurred during re-authentication. Please try again.',
                returnUrl: req.body.returnUrl 
            });
        }
    }

    async getProfile(req, res) {
        try {
            const user = await User.findById(req.user._id).select('-password -passwordHistory');
            await logSecurityEvent(req, 'PROFILE_VIEWED', `User profile viewed: ${user.username}`, 'LOW');
            res.render('profile', { user });
        } catch (err) {
            console.error('Profile error:', err);
            await logSecurityEvent(req, 'CRITICAL_OPERATION', `Profile error: ${err.message}`, 'HIGH');
            res.status(500).render('error', { 
                error: 'Server Error',
                message: 'An error occurred while loading your profile'
            });
        }
    }
}

module.exports = new AuthController();