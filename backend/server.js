
const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { Pool } = require("pg");
const path = require("path");
require("dotenv").config();

const app = express();

app.use(cors());
app.use(express.json({ limit: "5mb" }));

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL
    ? { rejectUnauthorized: false }
    : false
});

const SECRET = process.env.JWT_SECRET;

async function initializeDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      full_name VARCHAR(150) NOT NULL,
      email VARCHAR(255) UNIQUE NOT NULL,
      password TEXT NOT NULL,
      role VARCHAR(20) DEFAULT 'user',
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS complaints (
      id SERIAL PRIMARY KEY,
      complaint_id VARCHAR(40) UNIQUE NOT NULL,
      user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      title VARCHAR(200) NOT NULL,
      category VARCHAR(100),
      description TEXT NOT NULL,
      status VARCHAR(30) DEFAULT 'Pending',
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
  `);

  await pool.query(`
    ALTER TABLE complaints
    ADD COLUMN IF NOT EXISTS type VARCHAR(50) DEFAULT 'Complaint',
    ADD COLUMN IF NOT EXISTS location VARCHAR(255),
    ADD COLUMN IF NOT EXISTS image_data TEXT;
  `);

  if (process.env.ADMIN_EMAIL && process.env.ADMIN_PASSWORD) {
    const email = process.env.ADMIN_EMAIL.toLowerCase().trim();
    const hashedPassword = await bcrypt.hash(
      process.env.ADMIN_PASSWORD,
      10
    );

    await pool.query(
      `INSERT INTO users (full_name, email, password, role)
       VALUES ('Administrator', $1, $2, 'admin')
       ON CONFLICT (email)
       DO UPDATE SET password = $2, role = 'admin'`,
      [email, hashedPassword]
    );
  }

  console.log("PostgreSQL database ready");
}

function authenticate(req, res, next) {
  const token = req.headers.authorization?.split(" ")[1];

  if (!token) {
    return res.status(401).json({ message: "Login required" });
  }

  try {
    req.user = jwt.verify(token, SECRET);
    next();
  } catch {
    return res.status(401).json({
      message: "Invalid or expired token"
    });
  }
}

function adminOnly(req, res, next) {
  if (req.user.role !== "admin") {
    return res.status(403).json({
      message: "Admin access required"
    });
  }
  next();
}

function createToken(user) {
  return jwt.sign(
    {
      id: user.id,
      email: user.email,
      role: user.role
    },
    SECRET,
    { expiresIn: "1d" }
  );
}

function formatComplaint(row) {
  return {
    id: row.complaint_id,
    dbId: row.id,
    owner: row.email,
    ownerName: row.full_name,
    type: row.type,
    category: row.category,
    subject: row.title,
    title: row.title,
    location: row.location,
    description: row.description,
    image: row.image_data,
    status: row.status,
    date: row.created_at
  };
}

app.get("/api/health", (req, res) => {
  res.json({
    message: "CivicConnect backend is running"
  });
});

// Register
app.post("/api/auth/register", async (req, res) => {
  try {
    const { fullName, email, password } = req.body;

    if (!fullName || !email || !password || password.length < 6) {
      return res.status(400).json({
        message: "Enter your name, valid email and password (minimum 6 characters)"
      });
    }

    const cleanEmail = email.toLowerCase().trim();
    const hashedPassword = await bcrypt.hash(password, 10);

    const result = await pool.query(
      `INSERT INTO users (full_name, email, password)
       VALUES ($1, $2, $3)
       RETURNING id, full_name, email, role`,
      [fullName.trim(), cleanEmail, hashedPassword]
    );

    const user = result.rows[0];

    res.status(201).json({
      message: "Registration successful",
      token: createToken(user),
      user: {
        id: user.id,
        fullName: user.full_name,
        email: user.email,
        role: user.role
      }
    });
  } catch (error) {
    if (error.code === "23505") {
      return res.status(409).json({
        message: "Email already registered"
      });
    }

    console.error(error);
    res.status(500).json({
      message: "Registration failed"
    });
  }
});

// Login
app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    const result = await pool.query(
      "SELECT * FROM users WHERE email = $1",
      [email?.toLowerCase().trim()]
    );

    if (!result.rows.length) {
      return res.status(401).json({
        message: "Invalid email or password"
      });
    }

    const user = result.rows[0];
    const valid = await bcrypt.compare(password || "", user.password);

    if (!valid) {
      return res.status(401).json({
        message: "Invalid email or password"
      });
    }

    res.json({
      message: "Login successful",
      token: createToken(user),
      user: {
        id: user.id,
        fullName: user.full_name,
        email: user.email,
        role: user.role
      }
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({
      message: "Login failed"
    });
  }
});

// Submit complaint
app.post("/api/complaints", authenticate, async (req, res) => {
  try {
    const {
      title,
      subject,
      type,
      category,
      location,
      description,
      image,
      image_data
    } = req.body;

    const complaintTitle = title || subject;

    if (!complaintTitle || !description) {
      return res.status(400).json({
        message: "Subject and description are required"
      });
    }

    const complaintId = "CC" + Date.now().toString().slice(-10);

    const result = await pool.query(
      `INSERT INTO complaints
       (complaint_id, user_id, title, category, description,
        type, location, image_data)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
       RETURNING *`,
      [
        complaintId,
        req.user.id,
        complaintTitle,
        category || "General",
        description,
        type || "Complaint",
        location || "",
        image || image_data || null
      ]
    );

    res.status(201).json({
      message: "Complaint submitted successfully",
      complaint: {
        ...result.rows[0],
        id: result.rows[0].complaint_id,
        subject: result.rows[0].title,
        image: result.rows[0].image_data
      }
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({
      message: "Complaint submission failed"
    });
  }
});

// View complaints
app.get("/api/complaints", authenticate, async (req, res) => {
  try {
    let result;

    if (req.user.role === "admin") {
      result = await pool.query(`
        SELECT c.*, u.full_name, u.email
        FROM complaints c
        JOIN users u ON c.user_id = u.id
        ORDER BY c.created_at DESC
      `);
    } else {
      result = await pool.query(
        `SELECT c.*, u.full_name, u.email
         FROM complaints c
         JOIN users u ON c.user_id = u.id
         WHERE c.user_id = $1
         ORDER BY c.created_at DESC`,
        [req.user.id]
      );
    }

    res.json(result.rows.map(formatComplaint));
  } catch (error) {
    console.error(error);
    res.status(500).json({
      message: "Unable to load complaints"
    });
  }
});

// Track a complaint
app.get("/api/complaints/track/:complaintId", authenticate, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT c.*, u.full_name, u.email
       FROM complaints c
       JOIN users u ON c.user_id = u.id
       WHERE c.complaint_id = $1`,
      [req.params.complaintId]
    );

    if (!result.rows.length) {
      return res.status(404).json({
        message: "Complaint not found"
      });
    }

    const complaint = result.rows[0];

    if (
      req.user.role !== "admin" &&
      complaint.user_id !== req.user.id
    ) {
      return res.status(403).json({
        message: "You cannot view this complaint"
      });
    }

    res.json(formatComplaint(complaint));
  } catch (error) {
    console.error(error);
    res.status(500).json({
      message: "Unable to track complaint"
    });
  }
});

// Update complaint status
app.patch(
  "/api/complaints/:id/status",
  authenticate,
  adminOnly,
  async (req, res) => {
    try {
      const { status } = req.body;
      const allowed = ["Pending", "In Progress", "Resolved"];

      if (!allowed.includes(status)) {
        return res.status(400).json({
          message: "Invalid status"
        });
      }

      const result = await pool.query(
        `UPDATE complaints
         SET status = $1, updated_at = CURRENT_TIMESTAMP
         WHERE complaint_id = $2
         RETURNING *`,
        [status, req.params.id]
      );

      if (!result.rows.length) {
        return res.status(404).json({
          message: "Complaint not found"
        });
      }

      res.json({
        message: "Complaint status updated",
        complaint: result.rows[0]
      });
    } catch (error) {
      console.error(error);
      res.status(500).json({
        message: "Status update failed"
      });
    }
  }
);

// Serve frontend files
app.use(express.static(path.join(__dirname, "..")));

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "..", "index.html"));
});

const PORT = process.env.PORT || 3000;

async function startServer() {
  try {
    if (!SECRET) {
      throw new Error("JWT_SECRET environment variable is missing");
    }

    await initializeDatabase();

    app.listen(PORT, () => {
      console.log(`CivicConnect running on port ${PORT}`);
    });
  } catch (error) {
    console.error("Server startup failed:", error);
    process.exit(1);
  }
}

startServer();
