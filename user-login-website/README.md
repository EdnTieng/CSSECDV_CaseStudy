# User Login Website

This project is a basic user login website built with Node.js and Express. It provides user authentication functionalities, including login and logout, and serves a dashboard for authenticated users.

## Project Structure

```
user-login-website
├── src
│   ├── app.js                # Entry point of the application
│   ├── controllers           # Contains authentication logic
│   │   └── authController.js
│   ├── routes                # Defines application routes
│   │   └── authRoutes.js
│   ├── models                # User data model
│   │   └── user.js
│   └── views                 # EJS templates for rendering views
│       ├── login.ejs
│       └── dashboard.ejs
├── package.json              # Project dependencies and scripts
└── README.md                 # Project documentation
```

## Installation

1. Clone the repository:
   ```
   git clone <repository-url>
   ```

2. Navigate to the project directory:
   ```
   cd user-login-website
   ```

3. Install the dependencies:
   ```
   npm install
   ```

## Usage

1. Start the server:
   ```
   npm start
   ```

2. Open your browser and go to `http://localhost:3000` to access the login page.

## Features

- User login and logout functionalities
- Dashboard for authenticated users
- EJS templating for dynamic content rendering

## Contributing

Feel free to submit issues or pull requests for improvements or bug fixes.