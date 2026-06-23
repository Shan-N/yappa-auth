import express from "express";
import cors from "cors";
import cookieParser from "cookie-parser";
import { Pool } from "pg";
import { createClient } from "redis";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import { z } from "zod";
import { randomUUID } from "crypto";

const app = express();

const JWT_SECRET = process.env.JWT_SECRET || "your-secret-key";
const JWT_ISSUER = process.env.JWT_ISSUER || "yappa-rt";
const JWT_AUDIENCE = process.env.JWT_AUDIENCE || "realtime";
const ACCESS_TOKEN_TTL = process.env.ACCESS_TOKEN_TTL || "5m";
const REFRESH_TOKEN_TTL = process.env.REFRESH_TOKEN_TTL || "7d";
const DATABASE_URL = process.env.DATABASE_URL || "postgres://realtime:realtime@localhost:5432/realtime";
const REDIS_URL = process.env.REDIS_URL || "redis://localhost:6379";
const PORT = process.env.PORT || 3001;
const MAX_USERS_PER_TENANT = parseInt(process.env.MAX_USERS_PER_TENANT || "10", 10);

const pool = new Pool({ connectionString: DATABASE_URL });
const redis = createClient({ url: REDIS_URL });

const createTenantSchema = z.object({
  tenant_id: z.string().min(2).max(64).regex(/^[a-zA-Z0-9_-]+$/, "Only letters, numbers, hyphens, underscores"),
  name: z.string().min(1).max(128),
  user_id: z.string().min(2).max(64).regex(/^[a-zA-Z0-9_-]+$/, "Only letters, numbers, hyphens, underscores"),
  password: z.string().min(6),
  display_name: z.string().min(1).max(64).optional(),
});

const registerSchema = z.object({
  tenant_id: z.string().min(1).max(64),
  user_id: z.string().min(2).max(64).regex(/^[a-zA-Z0-9_-]+$/, "Only letters, numbers, hyphens, underscores"),
  password: z.string().min(6),
  display_name: z.string().min(1).max(64).optional(),
});

const loginSchema = z.object({
  tenant_id: z.string().min(1),
  user_id: z.string().min(1),
  password: z.string().min(1),
});

function generateAccessToken(tenantId, userId) {
  return jwt.sign(
    { tenant_id: tenantId, user_id: userId },
    JWT_SECRET,
    { expiresIn: ACCESS_TOKEN_TTL, issuer: JWT_ISSUER, audience: JWT_AUDIENCE }
  );
}

function generateRefreshToken() {
  return randomUUID();
}

async function hashPassword(password) {
  return bcrypt.hash(password, 12);
}

async function verifyPassword(password, hash) {
  return bcrypt.compare(password, hash);
}

async function storeRefreshToken(token, tenantId, userId) {
  const ttl = 7 * 24 * 60 * 60;
  await redis.setEx(`refresh:${token}`, ttl, JSON.stringify({ tenantId, userId }));
}

async function consumeRefreshToken(token) {
  const data = await redis.get(`refresh:${token}`);
  if (!data) return null;
  await redis.del(`refresh:${token}`);
  return JSON.parse(data);
}

function authMiddleware(req, res, next) {
  const header = req.headers.authorization;
  if (!header?.startsWith("Bearer ")) {
    return res.status(401).json({ error: "Missing token" });
  }
  try {
    req.user = jwt.verify(header.slice(7), JWT_SECRET, { issuer: JWT_ISSUER, audience: JWT_AUDIENCE });
    next();
  } catch {
    return res.status(401).json({ error: "Invalid or expired token" });
  }
}

app.use(cors({
  origin: process.env.CORS_ORIGINS?.split(",").map(s => s.trim()) || [],
  credentials: true,
  methods: ["GET", "POST"],
  allowedHeaders: ["Content-Type", "Authorization"],
}));
app.use(express.json());
app.use(cookieParser());

app.get("/health", (req, res) => res.send("OK"));

// ============================================
// TENANT CREATION — creates tenant + admin user
// ============================================
app.post("/api/tenants", async (req, res) => {
  try {
    const { tenant_id, name, user_id, password, display_name } = createTenantSchema.parse(req.body);

    const existingTenant = await pool.query("SELECT 1 FROM tenants WHERE tenant_id = $1", [tenant_id]);
    if (existingTenant.rowCount > 0) {
      return res.status(409).json({ error: "Tenant already exists" });
    }

    const existingUser = await pool.query(
      "SELECT 1 FROM users WHERE tenant_id = $1 AND user_id = $2",
      [tenant_id, user_id]
    );
    if (existingUser.rowCount > 0) {
      return res.status(409).json({ error: "User already exists in this tenant" });
    }

    const passwordHash = await hashPassword(password);
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      await client.query(
        "INSERT INTO tenants (tenant_id, name) VALUES ($1, $2)",
        [tenant_id, name]
      );
      await client.query(
        "INSERT INTO users (tenant_id, user_id, password_hash, display_name, role) VALUES ($1, $2, $3, $4, 'admin')",
        [tenant_id, user_id, passwordHash, display_name || user_id]
      );
      await client.query("COMMIT");
    } catch (err) {
      await client.query("ROLLBACK");
      throw err;
    } finally {
      client.release();
    }

    const accessToken = generateAccessToken(tenant_id, user_id);
    const refreshToken = generateRefreshToken();
    await storeRefreshToken(refreshToken, tenant_id, user_id);

    res.cookie("refresh_token", refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
      maxAge: 7 * 24 * 60 * 60 * 1000,
      path: "/api/refresh",
    });

    res.status(201).json({
      message: "Tenant created",
      tenant: { tenant_id, name, max_users: MAX_USERS_PER_TENANT },
      user: { tenant_id, user_id, display_name: display_name || user_id, role: "admin" },
      access_token: accessToken,
      token_type: "Bearer",
      expires_in: 300,
    });
  } catch (err) {
    if (err instanceof z.ZodError) {
      return res.status(400).json({ error: "Invalid input", details: err.errors });
    }
    console.error("Create tenant error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// ============================================
// REGISTER ADDITIONAL USER — enforces 10-user cap
// ============================================
app.post("/api/register", async (req, res) => {
  try {
    const { tenant_id, user_id, password, display_name } = registerSchema.parse(req.body);

    const tenant = await pool.query("SELECT 1 FROM tenants WHERE tenant_id = $1", [tenant_id]);
    if (tenant.rowCount === 0) {
      return res.status(404).json({ error: "Tenant does not exist. Ask your admin to create a tenant first." });
    }

    const countResult = await pool.query(
      "SELECT COUNT(*) as cnt FROM users WHERE tenant_id = $1",
      [tenant_id]
    );
    const userCount = parseInt(countResult.rows[0].cnt, 10);
    if (userCount >= MAX_USERS_PER_TENANT) {
      return res.status(429).json({
        error: `Tenant has reached the maximum of ${MAX_USERS_PER_TENANT} users`,
      });
    }

    const existing = await pool.query(
      "SELECT 1 FROM users WHERE tenant_id = $1 AND user_id = $2",
      [tenant_id, user_id]
    );
    if (existing.rowCount > 0) {
      return res.status(409).json({ error: "User already exists" });
    }

    const passwordHash = await hashPassword(password);
    await pool.query(
      "INSERT INTO users (tenant_id, user_id, password_hash, display_name, role) VALUES ($1, $2, $3, $4, 'member')",
      [tenant_id, user_id, passwordHash, display_name || user_id]
    );

    res.status(201).json({ message: "User created" });
  } catch (err) {
    if (err instanceof z.ZodError) {
      return res.status(400).json({ error: "Invalid input", details: err.errors });
    }
    console.error("Register error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// ============================================
// LOGIN
// ============================================
app.post("/api/login", async (req, res) => {
  try {
    const { tenant_id, user_id, password } = loginSchema.parse(req.body);

    const result = await pool.query(
      "SELECT password_hash, display_name FROM users WHERE tenant_id = $1 AND user_id = $2",
      [tenant_id, user_id]
    );
    if (result.rowCount === 0) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    const valid = await verifyPassword(password, result.rows[0].password_hash);
    if (!valid) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    const accessToken = generateAccessToken(tenant_id, user_id);
    const refreshToken = generateRefreshToken();
    await storeRefreshToken(refreshToken, tenant_id, user_id);

    res.cookie("refresh_token", refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
      maxAge: 7 * 24 * 60 * 60 * 1000,
      path: "/api/refresh",
    });

    res.json({
      access_token: accessToken,
      token_type: "Bearer",
      expires_in: 300,
      user: { tenant_id, user_id, display_name: result.rows[0].display_name },
    });
  } catch (err) {
    if (err instanceof z.ZodError) {
      return res.status(400).json({ error: "Invalid input", details: err.errors });
    }
    console.error("Login error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// ============================================
// REFRESH
// ============================================
app.post("/api/refresh", async (req, res) => {
  const refreshToken = req.cookies?.refresh_token;
  if (!refreshToken) {
    return res.status(401).json({ error: "Missing refresh token" });
  }

  try {
    const payload = await consumeRefreshToken(refreshToken);
    if (!payload) {
      return res.status(401).json({ error: "Invalid or expired refresh token" });
    }

    const { tenantId, userId } = payload;
    const accessToken = generateAccessToken(tenantId, userId);
    const newRefreshToken = generateRefreshToken();
    await storeRefreshToken(newRefreshToken, tenantId, userId);

    res.cookie("refresh_token", newRefreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
      maxAge: 7 * 24 * 60 * 60 * 1000,
      path: "/api/refresh",
    });

    res.json({ access_token: accessToken, token_type: "Bearer", expires_in: 300 });
  } catch (err) {
    console.error("Refresh error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// ============================================
// LOGOUT
// ============================================
app.post("/api/logout", async (req, res) => {
  const refreshToken = req.cookies?.refresh_token;
  if (refreshToken) {
    await redis.del(`refresh:${refreshToken}`);
  }
  res.clearCookie("refresh_token", { path: "/api/refresh" });
  res.json({ message: "Logged out" });
});

// ============================================
// TENANT INFO — user count, limit, members
// ============================================
app.get("/api/tenants/:tenant_id", authMiddleware, async (req, res) => {
  try {
    if (req.user.tenant_id !== req.params.tenant_id) {
      return res.status(403).json({ error: "You can only view your own tenant" });
    }

    const tenant = await pool.query(
      "SELECT tenant_id, name, created_at FROM tenants WHERE tenant_id = $1",
      [req.params.tenant_id]
    );
    if (tenant.rowCount === 0) {
      return res.status(404).json({ error: "Tenant not found" });
    }

    const countResult = await pool.query(
      "SELECT COUNT(*) as cnt FROM users WHERE tenant_id = $1",
      [req.params.tenant_id]
    );
    const userCount = parseInt(countResult.rows[0].cnt, 10);

    const users = await pool.query(
      "SELECT user_id, display_name, role, created_at FROM users WHERE tenant_id = $1 ORDER BY created_at",
      [req.params.tenant_id]
    );

    res.json({
      ...tenant.rows[0],
      user_count: userCount,
      max_users: MAX_USERS_PER_TENANT,
      users: users.rows,
    });
  } catch (err) {
    console.error("Tenant info error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// ============================================
// ME — current user info
// ============================================
app.get("/api/me", authMiddleware, async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT user_id, display_name, role FROM users WHERE tenant_id = $1 AND user_id = $2",
      [req.user.tenant_id, req.user.user_id]
    );
    if (result.rowCount === 0) {
      return res.status(404).json({ error: "User not found" });
    }
    res.json({
      tenant_id: req.user.tenant_id,
      ...result.rows[0],
    });
  } catch (err) {
    console.error("Me error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS tenants (
      tenant_id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS users (
      tenant_id TEXT NOT NULL REFERENCES tenants(tenant_id),
      user_id TEXT NOT NULL,
      password_hash TEXT NOT NULL,
      display_name TEXT,
      role TEXT NOT NULL DEFAULT 'member',
      created_at TIMESTAMPTZ DEFAULT NOW(),
      PRIMARY KEY (tenant_id, user_id)
    );
    CREATE INDEX IF NOT EXISTS idx_users_tenant ON users (tenant_id);
  `);
  console.log("Database initialized");
}

async function start() {
  try {
    await redis.connect();
    console.log("Connected to Redis");
    await initDb();
    app.listen(PORT, () => console.log(`Auth service listening on :${PORT}`));
  } catch (err) {
    console.error("Failed to start:", err);
    process.exit(1);
  }
}

process.on("SIGTERM", async () => {
  console.log("Shutting down...");
  await redis.quit();
  await pool.end();
  process.exit(0);
});

start();
