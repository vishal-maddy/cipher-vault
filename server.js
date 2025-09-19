// ====== CIPHER VAULT BACKEND + FRONTEND SERVER ======

const express = require("express");
const bcrypt = require("bcryptjs");
const sqlite3 = require("sqlite3").verbose();
const bodyParser = require("body-parser");
const path = require("path");

const app = express();
app.use(bodyParser.json());

// ==== Serve Frontend (Cipher Vault HTML) ====
app.use(express.static(__dirname));

// ==== Setup SQLite Database ====
const db = new sqlite3.Database("./ciphervault.db", (err) => {
  if (err) console.error("DB Connection Error:", err.message);
  else console.log("Connected to Cipher Vault DB ✅");
});

db.run("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT)");
db.run("CREATE TABLE IF NOT EXISTS notes (id INTEGER PRIMARY KEY, user_id INTEGER, note TEXT)");

// ==== User Signup ====
app.post("/signup", (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: "Missing username/password" });

  const hash = bcrypt.hashSync(password, 10);
  db.run("INSERT INTO users (username, password) VALUES (?, ?)", [username, hash], function(err) {
    if (err) return res.status(400).json({ error: "User already exists" });
    res.json({ message: "User created successfully!" });
  });
});

// ==== User Login ====
app.post("/login", (req, res) => {
  const { username, password } = req.body;
  db.get("SELECT * FROM users WHERE username = ?", [username], (err, user) => {
    if (!user) return res.status(400).json({ error: "User not found" });
    if (!bcrypt.compareSync(password, user.password)) return res.status(400).json({ error: "Wrong password" });
    res.json({ message: "Login successful", userId: user.id });
  });
});

// ==== Save Note ====
app.post("/saveNote", (req, res) => {
  const { userId, note } = req.body;
  if (!userId || !note) return res.status(400).json({ error: "Missing data" });

  db.run("INSERT INTO notes (user_id, note) VALUES (?, ?)", [userId, note], function(err) {
    if (err) return res.status(400).json({ error: "Failed to save note" });
    res.json({ message: "Note saved successfully!" });
  });
});

// ==== Get Notes ====
app.get("/notes/:userId", (req, res) => {
  db.all("SELECT * FROM notes WHERE user_id = ?", [req.params.userId], (err, rows) => {
    if (err) return res.status(400).json({ error: "Failed to fetch notes" });
    res.json(rows);
  });
});

// ==== Start Server ====
const PORT = 5000;
app.listen(PORT, () => {
  console.log(`🚀 Cipher Vault running at http://localhost:${PORT}`);
});
