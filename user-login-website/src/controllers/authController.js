const User = require('../models/user');
const { logSecurityEvent } = require('../middleware/auth');
const { loginSchema, changePasswordSchema, reAuthSchema } = require('../validation/schemas');
const Joi = require('joi');

class AuthController {
    async login(req, res) {
        try {
            const { error } = loginSchema.validate(req.body);
            if (error) {
                await logSecurityEvent(req, 'INPUT_VALIDATION_FAILED', `Login validation failed: ${error.details[0].message}`, 'MEDIUM');
                return res.render('login', { 
                    error: 'Invalid username and/or password',
                    username: req.body.username 
                });
            }

            const { username, password } = req.body;
            const user = await User.findOne({ username, isActive: true });
            
            if (!user) {
                await logSecurityEvent(req, 'LOGIN_FAILED', `Failed login attempt for username: ${username}`, 'MEDIUM');
                return res.render('login', { 
                    error: 'Invalid username and/or password',
                    username: req.body.username 
                });
            }

            if (user.isAccountLocked()) {
                await logSecurityEvent(req, 'ACCESS_DENIED', `Login attempt on locked account: ${username}`, 'HIGH');
                return res.render('login', { 
                    error: 'Account is temporarily locked due to multiple failed login attempts. Please try again later.',
                    username: req.body.username 
                });
            }

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

            user.resetFailedAttempts();
            user.updateLastLogin(req.ip);
            await user.save();

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

            const { currentPassword, newPassword, confirmPassword } = req.body;
            
            if (newPassword !== confirmPassword) {
                return res.render('changePassword', { 
                    error: 'New password and confirm password do not match.',
                    user: req.user 
                });
            }

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

            req.session.reAuthVerified = false;

            await logSecurityEvent(req, 'PASSWORD_CHANGE', `Password changed for user: ${user.username}`, 'LOW');
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
            
            const redirectUrl = returnUrl || '/auth/change-password';
            res.redirect(redirectUrl);
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
            
            // FIX: Flash messages return arrays, so get the first element or use empty string
            const errorMessages = req.flash('error');
            const successMessages = req.flash('success');
            
            res.render('profile', {
                user,
                error: errorMessages.length > 0 ? errorMessages[0] : null,
                success: successMessages.length > 0 ? successMessages[0] : null
            });
        } catch (err) {
            console.error('Profile error:', err);
            await logSecurityEvent(req, 'CRITICAL_OPERATION', `Profile error: ${err.message}`, 'HIGH');
            res.status(500).render('error', { 
                error: 'Server Error',
                message: 'An error occurred while loading your profile'
            });
        }
    }

    // =================================================================
    // START: NEW METHODS FOR PASSWORD RESET AND SECURITY UPDATES
    // =================================================================

    async handleForgotPassword(req, res) {
        try {
            const { username } = req.body;
            if (!username) {
                return res.render('forgotPassword', { error: 'Username is required.', success: null });
            }

            const user = await User.findOne({ username });

            // To prevent username enumeration, show a generic message whether the user exists or not.
            // Also check if they have a security question set.
            if (!user || !user.securityQuestion) {
                await logSecurityEvent(req, 'PASSWORD_RESET_FAILED', `Forgot password attempt for non-existent user or user without security question: ${username}`, 'MEDIUM');
                return res.render('forgotPassword', {
                    error: null,
                    success: 'If an account with that username exists and has a security question set, you will be redirected to the next step.'
                });
            }

            await logSecurityEvent(req, 'PASSWORD_RESET_REQUEST', `Password reset initiated for user: ${username}`, 'LOW');
            // Redirect to the next step, passing the username and question via URL query parameters.
            res.redirect(`/auth/reset-password?username=${encodeURIComponent(user.username)}&question=${encodeURIComponent(user.securityQuestion)}`);

        } catch (err) {
            console.error('Forgot Password error:', err);
            await logSecurityEvent(req, 'CRITICAL_OPERATION', `Forgot password error: ${err.message}`, 'HIGH');
            res.render('forgotPassword', { error: 'An unexpected error occurred.', success: null });
        }
    }

    async showResetPasswordForm(req, res) {
        try {
            const { username, question } = req.query;
            // If the required query parameters are missing, redirect back to the start.
            if (!username || !question) {
                return res.redirect('/auth/forgot-password');
            }

            res.render('resetPassword', {
                error: null,
                success: null,
                username,
                question
            });
        } catch (err) {
            console.error('Show Reset Password Form error:', err);
            res.status(500).render('error', {
                error: 'Server Error',
                message: 'Could not load the password reset page.'
            });
        }
    }

    async handleResetPassword(req, res) {
        try {
            const { username, securityAnswer, newPassword, confirmPassword } = req.body;
            const question = req.body.question; // Keep the question for re-rendering on error

            if (!securityAnswer || !newPassword || !confirmPassword) {
                return res.render('resetPassword', { error: 'All fields are required.', question, username });
            }
            if (newPassword !== confirmPassword) {
                return res.render('resetPassword', { error: 'Passwords do not match.', question, username });
            }

            const user = await User.findOne({ username });
            if (!user) {
                await logSecurityEvent(req, 'PASSWORD_RESET_FAILED', `Password reset attempt for invalid user: ${username}`, 'HIGH');
                return res.render('resetPassword', { error: 'Invalid request.', question, username });
            }

            // Use the model's method to compare the submitted answer with the stored hash.
            const isAnswerCorrect = await user.compareSecurityAnswer(securityAnswer);
            if (!isAnswerCorrect) {
                await logSecurityEvent(req, 'PASSWORD_RESET_FAILED', `Incorrect security answer for user: ${username}`, 'HIGH');
                return res.render('resetPassword', { error: 'The security answer is incorrect.', question: user.securityQuestion, username });
            }
            
            // Set the new password. The pre-save hook in user.js will handle hashing and history checks.
            user.password = newPassword;
            await user.save();

            await logSecurityEvent(req, 'PASSWORD_RESET_SUCCESS', `Password has been reset for user: ${username}`, 'MEDIUM');
            
            // Redirect to the login page with a success message in the URL query.
            res.redirect('/auth/login?message=Password+has+been+reset+successfully.+You+can+now+log+in.');

        } catch (err) {
            console.error('Handle Reset Password error:', err);
            // Handle specific errors from the model (like password complexity or history).
            if (err.message.includes('Password')) {
                return res.render('resetPassword', { error: err.message, question: req.body.question, username: req.body.username });
            }
            await logSecurityEvent(req, 'CRITICAL_OPERATION', `Password reset system error: ${err.message}`, 'HIGH');
            res.render('resetPassword', { error: 'An error occurred. Please try again.', question: req.body.question, username: req.body.username });
        }
    }

    async updateSecurityQuestion(req, res) {
        try {
            const { securityQuestion, securityAnswer, currentPassword } = req.body;
            const userId = req.user._id;

            if (!securityQuestion || !securityAnswer || !currentPassword) {
                req.flash('error', 'All fields are required to update your security question.');
                return res.redirect('/profile');
            }

            const user = await User.findById(userId);

            // For security, verify the user's current password before allowing changes.
            const isPasswordValid = await user.comparePassword(currentPassword);
            if (!isPasswordValid) {
                await logSecurityEvent(req, 'ACCESS_DENIED', `Update security question failed due to incorrect password for user: ${user.username}`, 'MEDIUM');
                req.flash('error', 'Your current password was incorrect.');
                return res.redirect('/profile');
            }

            // Update the user's security info. The pre-save hook will hash the answer.
            user.securityQuestion = securityQuestion;
            user.securityAnswer = securityAnswer;
            await user.save();

            await logSecurityEvent(req, 'SECURITY_INFO_UPDATED', `Security question updated for user: ${user.username}`, 'LOW');
            req.flash('success', 'Your security question and answer have been updated successfully.');
            res.redirect('/profile');

        } catch (err) {
            console.error('Update Security Question error:', err);
            await logSecurityEvent(req, 'CRITICAL_OPERATION', `Update security question error: ${err.message}`, 'HIGH');
            req.flash('error', 'An unexpected error occurred. Please try again.');
            res.redirect('/profile');
        }
    }
    // =================================================================
    // END: NEW METHODS
    // =================================================================
}

module.exports = new AuthController();