import express, { Request, Response, NextFunction } from "express";
import crypto from "node:crypto";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { createServer as createViteServer } from "vite";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT ? parseInt(process.env.PORT, 10) : 3000;
const ADMIN_TOKEN = process.env.VAULTLINE_ADMIN_TOKEN || "vaultline-admin-demo-token";

// Middleware: JSON parser with size limit (max 200KB for ciphertext + metadata)
app.use(express.json({ limit: "200kb" }));

/* -------------------------------------------------------------------------- */
/*                         Strict Security Headers Middleware                 */
/* -------------------------------------------------------------------------- */

app.use((req: Request, res: Response, next: NextFunction) => {
  // Prevent MIME-sniffing
  res.setHeader("X-Content-Type-Options", "nosniff");
  // Deny iframe embedding entirely (anti-clickjacking)
  res.setHeader("X-Frame-Options", "DENY");
  // Never leak the URL fragment or referrer in HTTP headers
  res.setHeader("Referrer-Policy", "no-referrer");
  // Cache-Control: strict no-store for all sensitive endpoints
  if (req.path.startsWith("/api/")) {
    res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, private");
    res.setHeader("Pragma", "no-cache");
    res.setHeader("Expires", "0");
  }
  // Content Security Policy
  res.setHeader(
    "Content-Security-Policy",
    "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self' ws: http:;"
  );
  next();
});

/* -------------------------------------------------------------------------- */
/*                           IP-Based Rate Limiting                           */
/* -------------------------------------------------------------------------- */

interface RateLimitBucket {
  count: number;
  resetAt: number;
}

const rateLimitMap = new Map<string, RateLimitBucket>();

function rateLimiter(limit: number, windowMs: number, keyPrefix: string) {
  return (req: Request, res: Response, next: NextFunction): void => {
    const ip = (req.headers["x-forwarded-for"] as string) || req.socket.remoteAddress || "127.0.0.1";
    const bucketKey = `${keyPrefix}:${ip.split(",")[0].trim()}`;
    const now = Date.now();
    const bucket = rateLimitMap.get(bucketKey);

    if (!bucket || now > bucket.resetAt) {
      rateLimitMap.set(bucketKey, { count: 1, resetAt: now + windowMs });
      next();
      return;
    }

    if (bucket.count >= limit) {
      res.status(429).json({
        error: "Too many requests. Please slow down.",
        retryAfterMs: bucket.resetAt - now,
      });
      return;
    }

    bucket.count++;
    next();
  };
}

/* -------------------------------------------------------------------------- */
/*                           In-Memory Database & Mutex                       */
/* -------------------------------------------------------------------------- */

export interface StoredSecret {
  id: string;
  ciphertext: string;
  iv: string;
  wrapped_key?: string | null;
  salt?: string | null;
  max_views: number;
  views: number;
  expires_at: number; // timestamp ms
  created_at: string; // ISO string
  has_passphrase: boolean;
}

export interface StoredAuditLog {
  id: number;
  event: "created" | "viewed" | "expired" | "deleted" | "failed_attempt";
  secret_id: string;
  ip_hash: string;
  prev_hash: string;
  hash: string;
  created_at: string;
}

const secretsStore = new Map<string, StoredSecret>();
const auditLogsStore: StoredAuditLog[] = [];
let auditIdCounter = 1;
const GENESIS_HASH = "0000000000000000000000000000000000000000000000000000000000000000";

// Truncated IP hash for privacy
function hashIp(ip: string): string {
  return crypto.createHash("sha256").update(ip + "vaultline-salt").digest("hex").slice(0, 16);
}

// Append an entry to the tamper-evident cryptographic hash chain
function recordAuditEvent(
  event: StoredAuditLog["event"],
  secretId: string,
  clientIp: string
): StoredAuditLog {
  const ipHash = hashIp(clientIp);
  const createdAt = new Date().toISOString();
  const prevHash =
    auditLogsStore.length === 0
      ? GENESIS_HASH
      : auditLogsStore[auditLogsStore.length - 1].hash;

  const content = `${prevHash}:${event}:${secretId}:${ipHash}:${createdAt}`;
  const entryHash = crypto.createHash("sha256").update(content).digest("hex");

  const entry: StoredAuditLog = {
    id: auditIdCounter++,
    event,
    secret_id: secretId,
    ip_hash: ipHash,
    prev_hash: prevHash,
    hash: entryHash,
    created_at: createdAt,
  };

  auditLogsStore.push(entry);
  return entry;
}

// Verification function for the audit chain
function checkAuditChainIntegrity(): { isValid: boolean; brokenAt?: number; total: number } {
  for (let i = 0; i < auditLogsStore.length; i++) {
    const entry = auditLogsStore[i];
    const expectedPrev = i === 0 ? GENESIS_HASH : auditLogsStore[i - 1].hash;

    if (entry.prev_hash !== expectedPrev) {
      return { isValid: false, brokenAt: entry.id, total: auditLogsStore.length };
    }

    const content = `${entry.prev_hash}:${entry.event}:${entry.secret_id}:${entry.ip_hash}:${entry.created_at}`;
    const calculatedHash = crypto.createHash("sha256").update(content).digest("hex");

    if (calculatedHash !== entry.hash) {
      return { isValid: false, brokenAt: entry.id, total: auditLogsStore.length };
    }
  }
  return { isValid: true, total: auditLogsStore.length };
}

// Background Task: Periodic purge of expired secrets (runs every 30s)
setInterval(() => {
  const now = Date.now();
  for (const [id, secret] of secretsStore.entries()) {
    if (secret.expires_at <= now) {
      secretsStore.delete(id);
      recordAuditEvent("expired", id, "127.0.0.1 (system)");
    }
  }
}, 30000);

/* -------------------------------------------------------------------------- */
/*                                 API Routes                                 */
/* -------------------------------------------------------------------------- */

// 1. POST /api/secrets — Create encrypted secret
app.post(
  "/api/secrets",
  rateLimiter(30, 60000, "create"),
  (req: Request, res: Response): void => {
    try {
      const {
        ciphertext,
        iv,
        expires_in = "24h",
        max_views = 1,
        has_passphrase = false,
        wrapped_key = null,
        salt = null,
      } = req.body;

      if (!ciphertext || typeof ciphertext !== "string") {
        res.status(422).json({ error: "Missing or invalid ciphertext." });
        return;
      }

      if (!iv || typeof iv !== "string") {
        res.status(422).json({ error: "Missing or invalid IV." });
        return;
      }

      // Max ciphertext size limit (~150KB, corresponding to ~10k chars plaintext)
      if (ciphertext.length > 200000) {
        res.status(422).json({ error: "Ciphertext exceeds payload limit." });
        return;
      }

      const validExpiries: Record<string, number> = {
        "5m": 5 * 60 * 1000,
        "1h": 60 * 60 * 1000,
        "24h": 24 * 60 * 60 * 1000,
        "7d": 7 * 24 * 60 * 60 * 1000,
      };

      const durationMs = validExpiries[expires_in];
      if (!durationMs) {
        res.status(422).json({ error: "Invalid expires_in value." });
        return;
      }

      const viewsLimit = Math.max(1, Math.min(5, parseInt(max_views, 10) || 1));

      // 128-bit random non-guessable ID (16 cryptographically random bytes -> base64url)
      const randomBytes = crypto.randomBytes(16);
      const secretId = randomBytes
        .toString("base64")
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=+$/, "");

      const now = Date.now();
      const expiresAt = now + durationMs;

      const newSecret: StoredSecret = {
        id: secretId,
        ciphertext,
        iv,
        wrapped_key: has_passphrase ? wrapped_key : null,
        salt: has_passphrase ? salt : null,
        max_views: viewsLimit,
        views: 0,
        expires_at: expiresAt,
        created_at: new Date(now).toISOString(),
        has_passphrase: Boolean(has_passphrase),
      };

      secretsStore.set(secretId, newSecret);

      const clientIp = (req.headers["x-forwarded-for"] as string) || req.socket.remoteAddress || "127.0.0.1";
      recordAuditEvent("created", secretId, clientIp);

      res.status(201).json({
        id: secretId,
        expires_at: new Date(expiresAt).toISOString(),
        max_views: viewsLimit,
      });
    } catch {
      res.status(500).json({ error: "Internal server error creating secret." });
    }
  }
);

// 2. GET /api/secrets/:id/meta — Metadata inspection without consuming a view
// Prevents social media/messenger link previews from accidentally burning the secret!
app.get("/api/secrets/:id/meta", (req: Request, res: Response): void => {
  const { id } = req.params;
  const secret = secretsStore.get(id);
  const now = Date.now();

  if (!secret) {
    res.json({
      exists: false,
      status: "not_found",
    });
    return;
  }

  if (secret.expires_at <= now) {
    secretsStore.delete(id);
    recordAuditEvent("expired", id, "system");
    res.json({
      exists: false,
      status: "expired",
    });
    return;
  }

  if (secret.views >= secret.max_views) {
    secretsStore.delete(id);
    res.json({
      exists: false,
      status: "destroyed",
    });
    return;
  }

  res.json({
    exists: true,
    has_passphrase: secret.has_passphrase,
    salt: secret.salt,
    expires_at: new Date(secret.expires_at).toISOString(),
    max_views: secret.max_views,
    views_remaining: secret.max_views - secret.views,
  });
});

// 3. POST /api/secrets/:id/reveal — Atomically consumes a view and returns ciphertext
app.post(
  "/api/secrets/:id/reveal",
  rateLimiter(60, 60000, "reveal"),
  (req: Request, res: Response): void => {
    const { id } = req.params;
    const clientIp = (req.headers["x-forwarded-for"] as string) || req.socket.remoteAddress || "127.0.0.1";

    const secret = secretsStore.get(id);
    const now = Date.now();

    if (!secret) {
      recordAuditEvent("failed_attempt", id, clientIp);
      res.status(404).json({
        error: "Secret not found or already destroyed.",
        status: "not_found",
      });
      return;
    }

    if (secret.expires_at <= now) {
      secretsStore.delete(id);
      recordAuditEvent("expired", id, clientIp);
      res.status(410).json({
        error: "This secret has expired.",
        status: "expired",
      });
      return;
    }

    // Atomic burn logic: increment view count
    secret.views += 1;
    const isDestroyed = secret.views >= secret.max_views;

    const payload = {
      ciphertext: secret.ciphertext,
      iv: secret.iv,
      wrapped_key: secret.wrapped_key,
      salt: secret.salt,
      views: secret.views,
      max_views: secret.max_views,
      burned: isDestroyed,
    };

    if (isDestroyed) {
      // Burn immediately and permanently from storage!
      secretsStore.delete(id);
      recordAuditEvent("viewed", id, clientIp);
      recordAuditEvent("deleted", id, clientIp);
    } else {
      recordAuditEvent("viewed", id, clientIp);
    }

    res.json(payload);
  }
);

// 4. GET /api/admin/audit — Read tamper-evident audit log with token
app.get("/api/admin/audit", (req: Request, res: Response): void => {
  const authHeader = req.headers.authorization;
  const queryToken = req.query.token as string;
  const token = authHeader?.replace(/^Bearer\s+/i, "") || queryToken;

  if (!token || token !== ADMIN_TOKEN) {
    res.status(401).json({
      error: "Unauthorized: Invalid or missing admin token.",
      hint: `Default demo admin token is '${ADMIN_TOKEN}'`,
    });
    return;
  }

  const integrity = checkAuditChainIntegrity();

  res.json({
    chain_valid: integrity.isValid,
    broken_at: integrity.brokenAt,
    total_entries: auditLogsStore.length,
    entries: auditLogsStore.slice().reverse(), // newest first
  });
});

// 5. POST /api/admin/simulate-tamper — Educational tool to prove tamper detection
app.post("/api/admin/simulate-tamper", (req: Request, res: Response): void => {
  const authHeader = req.headers.authorization;
  const token = authHeader?.replace(/^Bearer\s+/i, "") || (req.body.token as string);

  if (token !== ADMIN_TOKEN) {
    res.status(401).json({ error: "Unauthorized" });
    return;
  }

  if (auditLogsStore.length === 0) {
    res.status(400).json({ error: "No audit logs exist yet to simulate tampering." });
    return;
  }

  // Alter the earliest record's event type to simulate tampering
  const target = auditLogsStore[0];
  target.event = target.event === "created" ? "deleted" : "created";

  const integrity = checkAuditChainIntegrity();
  res.json({
    message: "Tampering simulated on entry #" + target.id,
    chain_valid: integrity.isValid,
    broken_at: integrity.brokenAt,
  });
});

// Seed an initial demo audit log event so the audit log view is never empty on launch
recordAuditEvent("created", "genesis_init_vault", "127.0.0.1 (system)");

/* -------------------------------------------------------------------------- */
/*                            Vite Integration & Start                        */
/* -------------------------------------------------------------------------- */

async function startServer() {
  if (process.env.NODE_ENV !== "production") {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa",
    });
    app.use(vite.middlewares);
  } else {
    // Serve static files in production build
    app.use(express.static(path.resolve(__dirname, "dist")));
    app.get("*", (_req, res) => {
      res.sendFile(path.resolve(__dirname, "dist", "index.html"));
    });
  }

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`[VaultLine] Server listening on http://0.0.0.0:${PORT}`);
  });
}

startServer();
