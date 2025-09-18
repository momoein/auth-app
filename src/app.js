require("dotenv").config(); 
const express = require("express");
const bodyParser = require("body-parser");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const db = require("./db");
const cookieParser = require("cookie-parser");
const rateLimit = require("express-rate-limit");

const app = express();
app.use(bodyParser.json());
app.use(cookieParser());

const SECRET = process.env.JWT_SECRET || "default_secret";
const EXPIRES_IN = process.env.JWT_EXPIRES_IN || "1h";
const COOKIE_SECURE = process.env.COOKIE_SECURE === "true"; 
const COOKIE_MAX_AGE = parseInt(process.env.COOKIE_MAX_AGE) || 60 * 60 * 1000;

app.post("/signup", async (req, res) => {
  const { fullName, email, password, gender, dob } = req.body;
  if (!fullName || !email || !password || !gender || !dob) {
    return res.status(400).json({ error: "All fields are required" });
  }

  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email)) {
    return res.status(400).json({ error: "Invalid email format" });
  }

  const hash = await bcrypt.hash(password, 10);

  db.run(
    "INSERT INTO users (email, password, fullName, gender, dob) VALUES (?, ?, ?, ?, ?)",
    [email, hash, fullName, gender, dob],
    function (err) {
      if (err) {
        if (err.message.includes("UNIQUE constraint failed")) {
          return res.status(400).json({ error: "User with this email already exists" });
        }
        return res.status(500).json({ error: "Database error" });
      }

      const token = jwt.sign({ id: this.lastID, email }, SECRET, { expiresIn: EXPIRES_IN });

      res.cookie("token", token, {
        httpOnly: true,
        secure: COOKIE_SECURE,
        sameSite: "strict",
        maxAge: COOKIE_MAX_AGE,
      });

      res.json({ message: "Signup successful, logged in!" });
    }
  );
});

const loginLimiter = rateLimit({
  windowMs: 5 * 60 * 1000, 
  max: 5,
  message: "Too many login attempts, try again later"
});

app.post("/login", loginLimiter, (req, res) => {
  const { email, password } = req.body;

  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email)) {
    return res.status(400).json({ error: "Invalid email format" });
  }
  
  db.get("SELECT * FROM users WHERE email = ?", [email], async (err, user) => {
    if (err) return res.status(500).json({ error: "Database error" });
    if (!user) return res.status(400).json({ error: "User not found" });

    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(401).json({ error: "Wrong password" });

    const token = jwt.sign({ id: user.id, email: user.email }, SECRET, { expiresIn: EXPIRES_IN });

    res.cookie("token", token, {
      httpOnly: true,
      secure: COOKIE_SECURE,
      sameSite: "strict",
      maxAge: COOKIE_MAX_AGE,
    });

    res.json({ message: "Logged in successfully" });
  });
});

app.get("/profile", (req, res) => {
  const token = req.cookies.token;
  if (!token) return res.status(401).json({ error: "No token" });

  try {
    const decoded = jwt.verify(token, SECRET);
    db.get("SELECT fullName, email, gender, dob FROM users WHERE id = ?", [decoded.id], (err, user) => {
      if (err) return res.status(500).json({ error: "Database error" });
      if (!user) return res.status(404).json({ error: "User not found" });
      res.json(user);
    });
  } catch (error) {
    res.status(401).json({ error: "Invalid token" });
  }
});

app.post("/logout", (req, res) => {
  res.clearCookie("token");
  res.json({ message: "Logged out" });
});

module.exports = app;