const User = require('../models/user');

class AuthController {
    async login(req, res) {
        const { username, password } = req.body;

        try {
            const user = await User.findOne({ username });
            if (!user) {
                return res.render('login', { error: 'User not found' });
            }

            // If you use bcrypt, implement comparePassword accordingly
            const isMatch = await user.comparePassword(password);
            if (!isMatch) {
                console.log(`Password mismatch for user "${username}". Entered: "${password}", Stored: "${user.password}"`);
                return res.render('login', { error: 'Password mismatch' });
            }

            // Store user info in session if needed
            req.session.user = {
                id: user._id,
                username: user.username,
                role: user.role
            };

            res.redirect('/dashboard');
        } catch (err) {
            console.error(err);
            res.render('login', { error: 'An error occurred. Please try again.' });
        }
    }

    async logout(req, res) {
        req.session.destroy(() => {
            res.redirect('/login');
        });
    }
}

module.exports = new AuthController();