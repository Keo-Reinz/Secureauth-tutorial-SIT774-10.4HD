const sqlite3 = require('sqlite3').verbose();
const db = new sqlite3.Database('./secureauth.db');

db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    hashed_username TEXT,
    plaintext_password TEXT UNIQUE,
    hashed_password TEXT,
    created_at TEXT DEFAULT (datetime('now'))
  )`);
});

console.log("Database initialized with 'users' table.");

/*
---------------------------------------------
  Explanation of Columns for Tutorial Use
---------------------------------------------

  username: (remove)
    - Stored in plain text for display in the demo.
    - REMOVE in production for privacy and minimal data retention.

  hashed_username: (keep)
    - This is the secure version of the username used during login.

  plaintext_password: (remove)
    - Stored for educational demonstration purposes only.
    - REMOVE in real-world applications to avoid credential leaks.

  hashed_password: (keep)
    - This is the only version of the password that should be stored.

  created_at: (keep - optional)
    - Records the time of user registration.
*/