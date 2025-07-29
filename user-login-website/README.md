# Secure Web Application - CSSECDV Case Study

This project is a comprehensive secure web application built as part of a university-level machine project focused on applying security best practices. The application implements robust authentication, authorization, input validation, and audit logging systems that comply with the CSSECDV Case Project Specifications and Checklist.

## 🛡️ Security Features Implemented

### Authentication & Authorization
- **Cryptographically Strong Password Hashing**: Uses bcrypt with 12 salt rounds
- **Account Lockout**: Automatic lockout after 5 failed login attempts (30-minute duration)
- **Password Complexity Requirements**: Minimum 8 characters with uppercase, lowercase, number, and special character
- **Password History**: Prevents reuse of last 5 passwords
- **Password Age Requirements**: Passwords must be at least 1 day old before changing
- **Re-authentication**: Required for critical operations (password changes, etc.)
- **Session Management**: Secure session configuration with HTTP-only cookies
- **Last Login Tracking**: Shows timestamp of last successful login

### Role-Based Access Control
- **Three Distinct User Roles**:
  - **Administrator**: Full system control, user management, audit log access
  - **Role A (Manager)**: Can manage Role B users within their scope
  - **Role B (Employee/Customer)**: Can view and update own data only
- **Centralized Access Control**: Middleware-based role verification
- **Fail-Secure Authorization**: All authorization checks fail securely

### Input Validation & Security
- **Strict Server-Side Validation**: Joi schema validation for all inputs
- **Input Rejection**: Invalid data is rejected outright, not sanitized
- **Type, Range, and Length Validation**: Comprehensive validation rules
- **Generic Error Messages**: No specific field error disclosure during login
- **Rate Limiting**: Global and endpoint-specific rate limiting
- **Security Headers**: Helmet.js for comprehensive security headers

### Audit Logging & Monitoring
- **Comprehensive Security Event Logging**:
  - Login attempts (successful and failed)
  - Access control violations
  - Input validation failures
  - User management operations
  - Critical operations
- **Audit Log Access**: Administrators only can view logs
- **Log Export**: CSV export functionality for audit logs
- **Real-time Monitoring**: Recent security events dashboard

### Error Handling & Security
- **Global Error Handling**: Catches all exceptions without exposing stack traces
- **Generic Error Messages**: No debug information exposed to clients
- **Custom Error Pages**: Professional 404 and 500 error pages
- **Security Event Logging**: All errors logged as security events

## 🏗️ Project Structure

```
secure-user-login-website/
├── src/
│   ├── app.js                    # Main application entry point
│   ├── controllers/              # Business logic controllers
│   │   ├── authController.js     # Authentication controller
│   │   ├── userController.js     # User management controller
│   │   └── auditController.js    # Audit log controller
│   ├── middleware/               # Security middleware
│   │   └── auth.js               # Authentication & authorization middleware
│   ├── models/                   # Database models
│   │   ├── user.js               # User model with security features
│   │   └── auditLog.js           # Audit log model
│   ├── routes/                   # Route definitions
│   │   ├── authRoutes.js         # Authentication routes
│   │   ├── userRoutes.js         # User management routes
│   │   └── auditRoutes.js        # Audit log routes
│   ├── validation/               # Input validation schemas
│   │   └── schemas.js            # Joi validation schemas
│   └── views/                    # EJS templates
│       ├── login.ejs             # Secure login page
│       ├── dashboard.ejs         # Role-based dashboard
│       └── error.ejs             # Generic error page
├── package.json                  # Dependencies and scripts
└── README.md                     # Project documentation
```

## 🚀 Installation & Setup

### Prerequisites
- Node.js (>= 14.0.0)
- MongoDB (running on localhost:27017)

### Installation Steps

1. **Clone the repository**:
   ```bash
   git clone <repository-url>
   cd secure-user-login-website
   ```

2. **Install dependencies**:
   ```bash
   npm install
   ```

3. **Start MongoDB**:
   ```bash
   # Ensure MongoDB is running on localhost:27017
   ```

4. **Start the application**:
   ```bash
   npm start
   ```

5. **Access the application**:
   - Open browser and go to `http://localhost:3000`
   - Login with sample credentials (see below)

## 👥 Sample Users

The application automatically creates three sample users for testing:

| Username | Password | Role | Permissions |
|----------|----------|------|-------------|
| `admin` | `AdminPass123!` | Administrator | Full system control, user management, audit logs |
| `manager` | `ManagerPass123!` | Role A | Manage Role B users |
| `user` | `UserPass123!` | Role B | View and update own profile |

## 🔐 Security Implementation Details

### Password Security
- **Hashing**: bcrypt with 12 salt rounds
- **Complexity**: Regex pattern `/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/`
- **History**: Prevents reuse of last 5 passwords
- **Age**: Minimum 1 day before password change allowed

### Session Security
- **Secret**: Environment variable `SESSION_SECRET`
- **Cookies**: HTTP-only, secure in production, SameSite strict
- **Duration**: 24 hours maximum
- **Name**: Custom session name (not default 'connect.sid')

### Rate Limiting
- **Global**: 100 requests per 15 minutes per IP
- **Login**: 5 attempts per 15 minutes per IP
- **Account Lockout**: 5 failed attempts = 30-minute lockout

### Input Validation
- **Username**: 3-50 characters, alphanumeric + underscore only
- **Email**: Standard email format validation
- **Password**: Complex pattern matching
- **All Inputs**: Type, range, and length validation

## 📊 Audit Logging

### Logged Events
- `LOGIN_SUCCESS` / `LOGIN_FAILED`
- `LOGOUT`
- `PASSWORD_CHANGE` / `PASSWORD_RESET`
- `ACCOUNT_LOCKED` / `ACCOUNT_UNLOCKED`
- `USER_CREATED` / `USER_UPDATED` / `USER_DELETED`
- `ROLE_CHANGED`
- `ACCESS_DENIED`
- `INPUT_VALIDATION_FAILED`
- `CRITICAL_OPERATION`

### Log Fields
- Timestamp, User ID, Username, IP Address, User Agent
- Event Type, Event Details, Severity Level
- Resource, HTTP Method, Status Code
- Additional contextual data

## 🛠️ API Endpoints

### Authentication
- `GET /auth/login` - Login page
- `POST /auth/login` - Login (with rate limiting)
- `GET /auth/logout` - Logout
- `GET /auth/profile` - User profile
- `GET /auth/change-password` - Change password page
- `POST /auth/change-password` - Change password (requires re-auth)
- `GET /auth/reauth` - Re-authentication page
- `POST /auth/reauth` - Re-authentication

### User Management (Role-based)
- `GET /admin/users` - List all users (Administrator only)
- `GET /admin/users/create` - Create user page (Administrator only)
- `POST /admin/users/create` - Create user (Administrator only)
- `GET /users` - List users by role (Role A+)
- `GET /users/:id` - User details (Role A+)
- `PUT /api/users/:id` - Update user (Role A+)
- `DELETE /api/users/:id` - Delete user (Role A+)

### Audit Logs (Administrator only)
- `GET /admin/audit-logs` - View audit logs
- `GET /admin/audit-logs/export` - Export audit logs as CSV
- `GET /api/audit-logs/recent` - Recent security events
- `GET /admin/audit-logs/user/:id` - User activity summary

## 🔧 Environment Variables

```env
PORT=3000                          # Application port
MONGODB_URI=mongodb://localhost:27017/user-login-db  # MongoDB connection
SESSION_SECRET=your-super-secret-key-change-in-production  # Session secret
NODE_ENV=production                # Environment (production/development)
```

## 🧪 Testing Security Features

### Test Account Lockout
1. Try logging in with wrong password 5 times
2. Account should be locked for 30 minutes
3. Check audit logs for lockout events

### Test Password Requirements
1. Try changing password to simple password
2. Should be rejected with validation error
3. Try reusing recent password
4. Should be rejected with history error

### Test Role-Based Access
1. Login as Role B user
2. Try accessing admin pages
3. Should be denied with 403 error
4. Check audit logs for access denied events

### Test Input Validation
1. Submit forms with invalid data
2. Should be rejected with validation errors
3. Check audit logs for validation failures

## 📋 CSSECDV Compliance Checklist

- ✅ **Authentication**: Robust password hashing, account lockout, complexity requirements
- ✅ **Authorization**: Role-based access control, fail-secure implementation
- ✅ **Input Validation**: Strict server-side validation, input rejection
- ✅ **Error Handling**: Generic error messages, no debug information exposure
- ✅ **Audit Logging**: Comprehensive security event logging
- ✅ **Session Management**: Secure session configuration
- ✅ **Rate Limiting**: Global and endpoint-specific rate limiting
- ✅ **Security Headers**: Comprehensive security headers implementation

## 🤝 Contributing

This project is designed for educational purposes as part of the CSSECDV Case Study. For security improvements or bug fixes, please ensure all changes maintain the security requirements outlined in the specifications.

## 📄 License

This project is licensed under the ISC License - see the LICENSE file for details.

## ⚠️ Security Notice

This application implements comprehensive security measures for educational purposes. In production environments, additional security considerations should be implemented including:

- HTTPS/TLS encryption
- Database connection encryption
- Regular security audits
- Penetration testing
- Security monitoring and alerting
- Backup and disaster recovery procedures