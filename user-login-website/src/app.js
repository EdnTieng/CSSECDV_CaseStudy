const express = require('express');
const session = require('express-session');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');
const path = require('path');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

// Import routes
const authRoutes = require('./routes/authRoutes');
const userRoutes = require('./routes/userRoutes');
const auditRoutes = require('./routes/auditRoutes');

// Import middleware
const { logSecurityEvent } = require('./middleware/auth');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.static(path.join(__dirname, "..", "public")));

// Security middleware
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'"],
            scriptSrc: ["'self'"],
            imgSrc: ["'self'", "data:", "https:"],
        },
    },
    hsts: {
        maxAge: 31536000,
        includeSubDomains: true,
        preload: true
    }
}));

// Rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // limit each IP to 100 requests per windowMs
    message: 'Too many requests from this IP, please try again later.',
    standardHeaders: true,
    legacyHeaders: false,
});
app.use(limiter);

// Body parsing middleware
app.use(bodyParser.urlencoded({ extended: true, limit: '10mb' }));
app.use(bodyParser.json({ limit: '10mb' }));

// Session configuration
app.use(session({
    secret: process.env.SESSION_SECRET || 'your-super-secret-key-change-in-production',
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: process.env.NODE_ENV === 'production', // Use secure cookies in production
        httpOnly: true,
        maxAge: 24 * 60 * 60 * 1000, // 24 hours
        sameSite: 'strict'
    },
    name: 'sessionId' // Change default session name
}));

// View engine setup
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Static files
app.use(express.static(path.join(__dirname, 'public')));

// Request logging middleware
app.use((req, res, next) => {
    console.log(`${new Date().toISOString()} - ${req.method} ${req.originalUrl} - ${req.ip}`);
    next();
});

// Routes
app.use('/auth', authRoutes);
app.use('/admin', userRoutes); // Changed from '/' to '/admin'
app.use('/admin', auditRoutes); // Changed from '/' to '/admin'

// Public routes
app.get('/', (req, res) => {
    if (req.session.userId) {
        res.redirect('/dashboard');
    } else {
        res.redirect('/auth/login');
    }
});

app.get('/login', (req, res) => {
    res.redirect('/auth/login');
});

// Dashboard route with authentication
app.get('/dashboard', async (req, res) => {
    try {
        if (!req.session.userId) {
            return res.redirect('/auth/login');
        }

        const User = require('./models/user');
        const user = await User.findById(req.session.userId).select('-password -passwordHistory');
        
        if (!user || !user.isActive) {
            req.session.destroy();
            return res.redirect('/auth/login');
        }

        res.render('dashboard', { 
            user,
            lastLoginAt: req.session.lastLoginAt
        });
    } catch (error) {
        console.error('Dashboard error:', error);
        res.status(500).render('error', {
            error: 'Server Error',
            message: 'An error occurred while loading the dashboard.'
        });
    }
});

// 404 handler
app.use((req, res) => {
    res.status(404).render('error', {
        error: 'Page Not Found',
        message: 'The requested page does not exist.'
    });
});

// Global error handling middleware
app.use(async (err, req, res, next) => {
    console.error('Global error:', err);
    
    // Log security event for errors
    try {
        await logSecurityEvent(req, 'CRITICAL_OPERATION', `System error: ${err.message}`, 'HIGH');
    } catch (logError) {
        console.error('Failed to log security event:', logError);
    }

    // Don't expose error details to client
    res.status(500).render('error', {
        error: 'Server Error',
        message: 'An unexpected error occurred. Please try again later.'
    });
});

// Sample users creation (for demo/testing)
async function createSampleUsers() {
    const User = require('./models/user');
    
    // Clear existing users to ensure clean state
    await User.deleteMany({});
    
    const users = [
        { 
            username: 'admin', 
            email: 'admin@example.com',
            password: 'AdminPass123!', 
            role: 'Administrator' 
        },
        { 
            username: 'manager', 
            email: 'manager@example.com',
            password: 'ManagerPass123!', 
            role: 'RoleA' 
        },
        { 
            username: 'user', 
            email: 'user@example.com',
            password: 'UserPass123!', 
            role: 'RoleB' 
        }
    ];

    for (const userData of users) {
        try {
            const user = new User(userData);
            await user.save();
            console.log(`Created user: ${userData.username} (${userData.role})`);
        } catch (error) {
            console.error(`Error creating user ${userData.username}:`, error.message);
        }
    }
}

// Connect to MongoDB and start server
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/user-login-db', { 
    useNewUrlParser: true, 
    useUnifiedTopology: true 
})
.then(async () => {
    console.log('Connected to MongoDB');
    await createSampleUsers();
    
    app.listen(PORT, () => {
        console.log(`Secure Web Application is running on http://localhost:${PORT}`);
        console.log('Sample users created:');
        console.log('- admin (Administrator): AdminPass123!');
        console.log('- manager (RoleA): ManagerPass123!');
        console.log('- user (RoleB): UserPass123!');
    });
})
.catch(err => {
    console.error('MongoDB connection error:', err);
    process.exit(1);
});

module.exports = app;