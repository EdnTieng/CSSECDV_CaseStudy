const express = require('express');
const session = require('express-session');
const bodyParser = require('body-parser');
const authRoutes = require('./routes/authRoutes.js');
const authController = require('./controllers/authController');

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
    res.render('login');
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

// Start the server
app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});