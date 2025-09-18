const sqlite3 = require("sqlite3").verbose();

const db = new sqlite3.Database(":memory:");

db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE,
    password TEXT,
    fullName TEXT,
    gender TEXT,
    dob TEXT
  )`);
});

module.exports = db;