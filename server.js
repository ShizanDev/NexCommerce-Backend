const express = require("express");
const cors = require("cors");
const mysql = require("mysql2");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
require("dotenv").config();

const app = express();
app.use(cors());
app.use(express.json());

const JWT_SECRET = "nexcommerce_secret_key";

// ✅ MySQL Connection
const connection = mysql.createConnection({
  host: "nozomi.proxy.rlwy.net",
  user: "root",
  password: "KiVzgEQiMcUzQCUmWqyeolQAqhoIEGPa",
  database: "railway",
  port: 27572,
  ssl: { rejectUnauthorized: false }
});

connection.connect((err) => {
  if (err) {
    console.error("❌ Database connection failed:", err);
  } else {
    console.log("✅ Connected to Railway MySQL");
  }
});

// ✅ JWT Middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) return res.status(401).json({ error: "Access token required" });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: "Invalid token" });

    req.user = user;
    next();
  });
};

// ✅ Root
app.get("/", (req, res) => {
  res.json({ message: "🚀 NexCommerce API running successfully" });
});

// ✅ CHECK ROUTE (Dashboard needs this)
app.get("/check", authenticateToken, (req, res) => {
  res.json({
    success: true,
    user: req.user
  });
});

// ✅ Register
app.post("/register", async (req, res) => {
  const { name, email, password } = req.body;

  if (!name || !email || !password)
    return res.status(400).json({ error: "All fields are required" });

  connection.query(
    "SELECT * FROM users WHERE email = ?",
    [email],
    async (err, results) => {
      if (err) return res.status(500).json({ error: err.message });

      if (results.length > 0)
        return res.status(400).json({ error: "Email already exists" });

      const hashedPassword = await bcrypt.hash(password, 10);

      connection.query(
        "INSERT INTO users (name, email, password) VALUES (?, ?, ?)",
        [name, email, hashedPassword],
        (err) => {
          if (err) return res.status(500).json({ error: err.message });

          res.json({ message: "✅ User registered successfully" });
        }
      );
    }
  );
});

// ✅ Login
app.post("/login", (req, res) => {
  const { email, password } = req.body;

  if (!email || !password)
    return res.status(400).json({ error: "Email and password required" });

  connection.query(
    "SELECT * FROM users WHERE email = ?",
    [email],
    async (err, results) => {
      if (err) return res.status(500).json({ error: err.message });

      if (results.length === 0)
        return res.status(400).json({ error: "Invalid credentials" });

      const user = results[0];

      const isMatch = await bcrypt.compare(password, user.password);

      if (!isMatch)
        return res.status(400).json({ error: "Invalid credentials" });

      const token = jwt.sign(
        { id: user.id, email: user.email },
        JWT_SECRET,
        { expiresIn: "7d" }
      );

      res.json({
        success: true,
        token,
        user: {
          id: user.id,
          name: user.name,
          email: user.email,
          plan: user.plan
        }
      });
    }
  );
});

// ✅ INIT ROLE SYSTEM
app.get("/init-role-system", (req, res) => {
  const sql = `
    ALTER TABLE users
    ADD COLUMN role VARCHAR(50) DEFAULT 'admin'
  `;

  connection.query(sql, (err) => {
    if (err) {
      return res.json({ message: "Role column may already exist ✅" });
    }
    res.json({ message: "Role column added ✅" });
  });
});

// ✅ Forgot Password (Simple Reset)
app.post("/forgot-password", (req, res) => {
  const { email, newPassword } = req.body;

  if (!email || !newPassword)
    return res.status(400).json({ error: "Email and new password required" });

  bcrypt.hash(newPassword, 10, (err, hashedPassword) => {
    if (err) return res.status(500).json({ error: "Hash error" });

    connection.query(
      "UPDATE users SET password = ? WHERE email = ?",
      [hashedPassword, email],
      (err, result) => {
        if (err) return res.status(500).json({ error: err.message });

        if (result.affectedRows === 0)
          return res.status(404).json({ error: "User not found" });

        res.json({ success: true, message: "Password updated successfully" });
      }
    );
  });
});

const PORT = process.env.PORT || 5000;

app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});


// ✅ Create Stores Table
app.get("/init-stores-table", (req, res) => {
  const sql = `
    CREATE TABLE IF NOT EXISTS stores (
      id INT AUTO_INCREMENT PRIMARY KEY,
      user_id INT NOT NULL,
      store_name VARCHAR(255),
      store_url VARCHAR(255),
      api_key VARCHAR(255) UNIQUE,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )
  `;

  connection.query(sql, (err) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    res.json({ success: true, message: "Stores table created successfully ✅" });
  });
});

// ✅ Create Store API
app.post("/create-store", authenticateToken, (req, res) => {
  const { store_name, store_url } = req.body;

  if (!store_name || !store_url) {
    return res.status(400).json({ error: "Store name and URL required" });
  }

  const apiKey = "nc_" + Math.random().toString(36).substring(2) + Date.now();

  const sql = `
    INSERT INTO stores (user_id, store_name, store_url, api_key)
    VALUES (?, ?, ?, ?)
  `;

  connection.query(
    sql,
    [req.user.id, store_name, store_url, apiKey],
    (err, result) => {
      if (err) {
        return res.status(500).json({ error: err.message });
      }

      res.json({
        success: true,
        message: "Store created successfully ✅",
        store: {
          id: result.insertId,
          store_name,
          store_url,
          api_key: apiKey,
        },
      });
    }
  );
});

// ✅ Get User Stores
app.get("/stores", authenticateToken, (req, res) => {
  const sql = "SELECT * FROM stores WHERE user_id = ?";

  connection.query(sql, [req.user.id], (err, results) => {
    if (err) return res.status(500).json({ error: err.message });

    res.json({
      success: true,
      stores: results,
    });
  });
});