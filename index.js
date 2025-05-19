// ===================== Module Imports =====================

// Import Express framework
const express = require('express');

// Import session middleware for tracking logged-in users
const session = require('express-session');

// Import SQLite database library
const sqlite3 = require('sqlite3').verbose();

// Import bcrypt for secure password hashing
const bcrypt = require('bcrypt');

// Utilities for file paths and reading HTML files
const path = require('path');
const fs = require('fs');

// ===================== App Setup =====================

// Initialize Express app
const app = express();

// Connect to SQLite database (local file)
const db = new sqlite3.Database('./secureauth.db');

// Number of salt rounds used when hashing (higher = slower = more secure)
const saltRounds = 10;

// Enable Express to parse form submissions
app.use(express.urlencoded({ extended: true }));

// Setup Express sessions for login tracking
app.use(session({
  secret: 'secureauth-secret',
  resave: false,
  saveUninitialized: false
}));

// ===================== Authentication Routes =====================

// Serve registration form
app.get('/demo_register.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'public_html', 'demo_register.html'));
});

// Serve login form
app.get('/demo_login.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'public_html', 'demo_login.html'));
});

// Handles logout and destroy session
app.get('/logout', (req, res) => {
  req.session.destroy(() => {
    res.redirect('/demo_login.html');
  });
});

// ===================== Registration Logic =====================

app.post('/register', (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.send("Missing username or password.");
  }

  // First hash the username
  bcrypt.hash(username, saltRounds, (err, hashedUsername) => {
    if (err) {
      console.error("Error hashing username:", err.message);
      return res.send("Server error while hashing username.");
    }

    // Then hash the password
    bcrypt.hash(password, saltRounds, (err2, hashedPassword) => {
      if (err2) {
        console.error("Error hashing password:", err2.message);
        return res.send("Server error while hashing password.");
      }

      // DEMO PURPOSE ONLY: Also storing the plaintext password for educational visibility
      // --- Remove 'plaintext_password' in production environments ---
      const stmt = `INSERT INTO users (username, hashed_username, plaintext_password, hashed_password) VALUES (?, ?, ?, ?)`;

      db.run(stmt, [username, hashedUsername, password, hashedPassword], (err3) => {
        if (err3) {
          if (err3.message.includes("UNIQUE")) {
            return res.send("Username already exists.");
          }
          console.error("Database error:", err3.message);
          return res.send("Registration failed.");
        }

        console.log(`User '${username}' registered successfully.`);
        res.redirect('/register_success.html');
      });
    });
  });
});

// ===================== Login Logic =====================

app.post('/login', (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.send("Missing login details.");
  }

  // Gets all users to compare against (bcrypt hashes can't be queried directly)
  db.all('SELECT * FROM users', (err, users) => {
    if (err) {
      console.error("DB error during login:", err.message);
      return res.send("Server error.");
    }

    let matchedUser = null;

    // Compares the input credentials with each user's stored hashes
    const compareTasks = users.map(user => {
      return Promise.all([
        bcrypt.compare(username, user.hashed_username),
        bcrypt.compare(password, user.hashed_password)
      ]).then(([usernameMatch, passwordMatch]) => {
        if (usernameMatch && passwordMatch) {
          matchedUser = user;
        }
      });
    });

    // Evaluate all comparison promises
    Promise.all(compareTasks).then(() => {
      if (!matchedUser) {
        return res.send("Invalid username or password.");
      }

      // Save user login state in session
      req.session.loggedIn = true;
      req.session.username = matchedUser.username;
      console.log(`Login successful for '${matchedUser.username}'`);
      res.redirect('/login_success.html');
    });
  });
});

// ===================== User Profile =====================

app.get('/profile', (req, res) => {
  // Only allow access if logged in
  if (!req.session.loggedIn || !req.session.username) {
    return res.redirect('/demo_login.html');
  }

  // Looks up logged-in user's full profile from the Database
  db.get('SELECT * FROM users WHERE username = ?', [req.session.username], (err, user) => {
    if (err || !user) {
      return res.status(500).send("Could not load profile.");
    }

    fs.readFile(path.join(__dirname, 'public_html', 'profile.html'), 'utf8', (err2, html) => {
      if (err2) return res.status(500).send("Missing profile page.");

      const content = `
        <div class="border border-success p-4 rounded">
          <p><strong>Username:</strong> ${user.username}</p>
          <p><strong>Registered:</strong> ${new Date(user.created_at + ' UTC').toLocaleString()}</p>
        </div>
      `;

      res.send(html.replace('<!--PROFILE-CONTENT-->', content));
    });
  });
});

// ===================== User History Display =====================

app.get('/user_history.html', (req, res) => {
  const query = `SELECT id, username, hashed_username, plaintext_password, hashed_password, created_at FROM users ORDER BY id ASC`;

  db.all(query, (err, users) => {
    if (err) return res.status(500).send("Error loading users.");

    fs.readFile(path.join(__dirname, 'public_html', 'user_history.html'), 'utf8', (err2, html) => {
      if (err2) return res.status(500).send("Page not found.");

      // Format users into Bootstrap layout
      const formatted = users.map((user, index) => `
        <div class="border border-success rounded mb-3 p-3">
          <p class="text-secondary mb-1"><small>[${index + 1}] Registered User</small></p>
          <div class="row align-items-center mb-2">
            <div class="col-md-4">
              <p class="text-success mb-1">Username</p>
              <p class="lead mb-0">${user.username}</p>
            </div>
            <div class="col-md-6">
              <p class="text-success mb-1">Hashed Username</p>
              <p class="text-white small mb-0"><code>${user.hashed_username}</code></p>
            </div>
            <div class="col-md-2 text-end">
              <p class="text-success mb-1">Registered</p>
              <p class="text-light small mb-0">${new Date(user.created_at + ' UTC').toLocaleString()}</p>
            </div>
          </div>
          <div class="row align-items-center">
            <div class="col-md-4">
              <p class="text-success mb-1">Password</p>
              <p class="lead mb-0">${user.plaintext_password}</p>
              <!-- --- REMOVE plaintext password for production security --- -->
            </div>
            <div class="col-md-8">
              <p class="text-success mb-1">Hashed Password</p>
              <p class="text-white small mb-0"><code>${user.hashed_password}</code></p>
            </div>
          </div>
        </div>
      `).join('');

      res.send(html.replace('<!--USER-TABLE-->', formatted));
    });
  });
});

// ===================== Hash Demo for Tutorial =====================

app.post('/hash_demo', (req, res) => {
  const { username, password } = req.body;

  // Hash both fields
  bcrypt.hash(username, saltRounds, (err1, hashedUsername) => {
    if (err1) return res.send("Error hashing username");

    bcrypt.hash(password, saltRounds, (err2, hashedPassword) => {
      if (err2) return res.send("Error hashing password");

      res.send(`
        <html>
        <head>
          <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
        </head>
        <body class="bg-dark text-light p-4">
          <div class="container">
            <h2 class="text-success">Bcrypt Hash Demo</h2>
            <p><strong>Username:</strong> ${username}</p>
            <p><strong>Password:</strong> ${password}</p>
            <hr class="border-success" />
            <p><strong>Hashed Username:</strong><br><code>${hashedUsername}</code></p>
            <p><strong>Hashed Password:</strong><br><code>${hashedPassword}</code></p>
            <a href="/hash_demo.html" class="btn btn-outline-success mt-4">Try Again</a>
          </div>
        </body>
        </html>
      `);
    });
  });
});

// ===================== Static File Middleware =====================

// Serves all static files from the public_html folder
app.use(express.static(path.join(__dirname, 'public_html')));

// ===================== Start Server =====================

app.listen(3000, () => {
  console.log("SecureAuthTutorial is running on http://localhost:3000");
});
