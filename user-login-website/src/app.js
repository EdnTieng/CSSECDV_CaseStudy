const express = require('express');
const session = require('express-session');
const bodyParser = require('body-parser');
const authRoutes = require('./routes/authRoutes.js');
const authController = require('./controllers/authController');
const User = require('./models/user');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(session({
    secret: 'your_secret_key',
    resave: false,
    saveUninitialized: true
}));

app.set('view engine', 'ejs');
app.set('views', __dirname + '/views');

// Routes
app.use('/auth', authRoutes);
app.post('/login', authController.login);

app.get('/', (req, res) => {
    res.render('login');
});
app.get('/login', (req, res) => {
    res.render('login', { error: null });
});

app.get('/dashboard', (req, res) => {
    res.render('dashboard');
});

app.get('/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            return console.log(err);
        }
        res.redirect('/login');
    });
});

// Sample users creation (for demo/testing)
async function createSampleUsers() {
    const users = [
        { username: 'admin', password: 'adminpass', role: 'Admin' },
        { username: 'manager', password: 'managerpass', role: 'manager' },
        { username: 'user', password: 'userpass', role: 'user' }
    ];

    for (const userData of users) {
        const existing = await User.findOne({ username: userData.username });
        if (!existing) {
            await User.create(userData);
            console.log(`Created user: ${userData.username}`);
        }
    }
}

// Connect to MongoDB and create sample users
const mongoose = require('mongoose');
mongoose.connect('mongodb://localhost:27017/user-login-db', { useNewUrlParser: true, useUnifiedTopology: true })
    .then(async () => {
        console.log('Connected to MongoDB');
        await createSampleUsers();
        app.listen(PORT, () => {
            console.log(`Server is running on http://localhost:${PORT}`);
        });
    })
    .catch(err => {
        console.error('MongoDB connection error:', err);
    });