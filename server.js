const express = require("express");
const Database = require("better-sqlite3");
const multer = require("multer");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");

const app = express();

const PORT = process.env.PORT || 3000;
const ROOT = __dirname;
const DATA_DIR = path.join(ROOT, "data");
const UPLOAD_DIR = path.join(ROOT, "uploads");

fs.mkdirSync(DATA_DIR, { recursive: true });
fs.mkdirSync(UPLOAD_DIR, { recursive: true });

const db = new Database(path.join(DATA_DIR, "gamevault.db"));
db.pragma("journal_mode = WAL");

/* =========================
   PASSWORD HELPERS
========================= */

function hashPassword(password, salt = crypto.randomBytes(16).toString("hex")) {
  const hash = crypto
    .scryptSync(String(password), salt, 64)
    .toString("hex");

  return { hash, salt };
}

function safeEqual(a, b) {
  const aa = Buffer.from(String(a));
  const bb = Buffer.from(String(b));

  return aa.length === bb.length && crypto.timingSafeEqual(aa, bb);
}

/* =========================
   DATABASE
========================= */

db.exec(`
CREATE TABLE IF NOT EXISTS products (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  title TEXT NOT NULL,
  game TEXT NOT NULL,
  level TEXT NOT NULL,
  rank TEXT NOT NULL,
  price INTEGER NOT NULL,
  stock TEXT NOT NULL,
  description TEXT NOT NULL,
  image TEXT,
  video TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS admin_settings (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  username TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  password_salt TEXT NOT NULL,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS orders (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  product_id INTEGER NOT NULL,
  buyer_name TEXT NOT NULL,
  phone TEXT NOT NULL,
  note TEXT DEFAULT '',
  amount INTEGER NOT NULL,
  status TEXT NOT NULL DEFAULT 'Pending',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(product_id) REFERENCES products(id)
);
`);

/* =========================
   DEFAULT ADMIN
========================= */

const existingAdmin = db
  .prepare("SELECT id FROM admin_settings WHERE id = 1")
  .get();

if (!existingAdmin) {
  const initialUsername = process.env.ADMIN_USERNAME || "admin";
  const initialPassword = process.env.ADMIN_PASSWORD || "admin123";

  const { hash, salt } = hashPassword(initialPassword);

  db.prepare(`
    INSERT INTO admin_settings
    (id, username, password_hash, password_salt)
    VALUES (1, ?, ?, ?)
  `).run(initialUsername, hash, salt);
}

function getAdminSettings() {
  return db
    .prepare(`
      SELECT username, password_hash, password_salt
      FROM admin_settings
      WHERE id = 1
    `)
    .get();
}

/* =========================
   MIDDLEWARE
========================= */

app.use(express.json({ limit: "2mb" }));
app.use(express.urlencoded({ extended: true }));

/*
  Simple signed admin cookie.
  This avoids express-session memory problems
  when running on Netlify Functions.
*/

const COOKIE_NAME = "gamevault_admin";

function createAdminToken() {
  const payload = `${Date.now()}`;
  const secret =
    process.env.SESSION_SECRET || "gamevault-change-this-secret";

  const signature = crypto
    .createHmac("sha256", secret)
    .update(payload)
    .digest("hex");

  return `${payload}.${signature}`;
}

function verifyAdminToken(token) {
  if (!token) return false;

  const parts = String(token).split(".");
  if (parts.length !== 2) return false;

  const [payload, signature] = parts;

  const secret =
    process.env.SESSION_SECRET || "gamevault-change-this-secret";

  const expected = crypto
    .createHmac("sha256", secret)
    .update(payload)
    .digest("hex");

  if (!safeEqual(signature, expected)) return false;

  const timestamp = Number(payload);

  if (!Number.isFinite(timestamp)) return false;

  // 8 hours
  if (Date.now() - timestamp > 8 * 60 * 60 * 1000) {
    return false;
  }

  return true;
}

function getCookie(req, name) {
  const header = req.headers.cookie || "";

  const cookies = header.split(";");

  for (const item of cookies) {
    const index = item.indexOf("=");

    if (index === -1) continue;

    const key = item.slice(0, index).trim();
    const value = item.slice(index + 1).trim();

    if (key === name) {
      return decodeURIComponent(value);
    }
  }

  return null;
}

function setAdminCookie(res, token) {
  const secure =
    process.env.NODE_ENV === "production" ? " Secure;" : "";

  res.setHeader(
    "Set-Cookie",
    `${COOKIE_NAME}=${encodeURIComponent(token)}; Path=/; HttpOnly; SameSite=Lax; Max-Age=28800;${secure}`
  );
}

function clearAdminCookie(res) {
  res.setHeader(
    "Set-Cookie",
    `${COOKIE_NAME}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0`
  );
}

function adminOnly(req, res, next) {
  const token = getCookie(req, COOKIE_NAME);

  if (!verifyAdminToken(token)) {
    return res.status(401).json({
      error: "Admin login required"
    });
  }

  next();
}

/* =========================
   STATIC FILES
========================= */

app.use("/uploads", express.static(UPLOAD_DIR));
app.use(express.static(path.join(ROOT, "public")));

/* =========================
   MULTER UPLOAD
========================= */

const storage = multer.diskStorage({
  destination: (_, __, cb) => {
    cb(null, UPLOAD_DIR);
  },

  filename: (_, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();

    const safe = path
      .basename(file.originalname, ext)
      .replace(/[^a-z0-9_-]/gi, "-")
      .slice(0, 40);

    cb(null, `${Date.now()}-${safe}${ext}`);
  }
});

const upload = multer({
  storage,

  limits: {
    fileSize: 80 * 1024 * 1024
  },

  fileFilter: (_, file, cb) => {
    const ok =
      file.mimetype.startsWith("image/") ||
      file.mimetype.startsWith("video/");

    cb(
      ok ? null : new Error("Only image/video files are allowed"),
      ok
    );
  }
});

/* =========================
   PUBLIC PRODUCTS
========================= */

function publicProduct(row) {
  return row;
}

app.get("/api/products", (req, res) => {
  const rows = db
    .prepare(`
      SELECT *
      FROM products
      ORDER BY id DESC
    `)
    .all();

  res.json(rows.map(publicProduct));
});

app.get("/api/products/:id", (req, res) => {
  const product = db
    .prepare(`
      SELECT *
      FROM products
      WHERE id = ?
    `)
    .get(req.params.id);

  if (!product) {
    return res.status(404).json({
      error: "Listing not found"
    });
  }

  res.json(publicProduct(product));
});

/* =========================
   PUBLIC ORDER
========================= */

app.post("/api/orders", (req, res) => {
  const {
    productId,
    buyerName,
    phone,
    note = ""
  } = req.body || {};

  if (
    !productId ||
    !buyerName?.trim() ||
    !phone?.trim()
  ) {
    return res.status(400).json({
      error: "Product, name and phone are required"
    });
  }

  const product = db
    .prepare(`
      SELECT *
      FROM products
      WHERE id = ?
    `)
    .get(productId);

  if (!product) {
    return res.status(404).json({
      error: "Listing not found"
    });
  }

  if (String(product.stock).toLowerCase() !== "available") {
    return res.status(400).json({
      error: "This listing is not available"
    });
  }

  const info = db
    .prepare(`
      INSERT INTO orders
      (product_id, buyer_name, phone, note, amount)
      VALUES (?, ?, ?, ?, ?)
    `)
    .run(
      product.id,
      buyerName.trim(),
      phone.trim(),
      String(note).slice(0, 1000),
      product.price
    );

  res.status(201).json({
    ok: true,
    orderId: info.lastInsertRowid
  });
});

/* =========================
   ADMIN LOGIN
========================= */

app.post("/api/admin/login", (req, res) => {
  const settings = getAdminSettings();

  const {
    user,
    pass
  } = req.body || {};

  if (
    user === settings.username
  ) {
    const { hash } = hashPassword(
      pass || "",
      settings.password_salt
    );

    if (
      safeEqual(
        hash,
        settings.password_hash
      )
    ) {
      const token = createAdminToken();

      setAdminCookie(res, token);

      return res.json({
        ok: true
      });
    }
  }

  return res.status(401).json({
    error: "Invalid username or password"
  });
});

/* =========================
   ADMIN SETTINGS
========================= */

app.get(
  "/api/admin/settings",
  adminOnly,
  (req, res) => {
    const settings = getAdminSettings();

    res.json({
      username: settings.username
    });
  }
);

app.patch(
  "/api/admin/settings",
  adminOnly,
  (req, res) => {
    const {
      username,
      currentPassword,
      newPassword
    } = req.body || {};

    const current = getAdminSettings();

    const nextUsername = String(
      username || current.username
    ).trim();

    const oldPassword = String(
      currentPassword || ""
    );

    const nextPassword = String(
      newPassword || ""
    );

    if (
      !nextUsername ||
      nextUsername.length < 3 ||
      nextUsername.length > 48
    ) {
      return res.status(400).json({
        error: "Username must be 3-48 characters"
      });
    }

    if (
      !/^[A-Za-z0-9_.-]+$/.test(nextUsername)
    ) {
      return res.status(400).json({
        error:
          "Username can use letters, numbers, dot, dash and underscore only"
      });
    }

    if (
      nextPassword &&
      (
        nextPassword.length < 8 ||
        nextPassword.length > 100
      )
    ) {
      return res.status(400).json({
        error: "New password must be 8-100 characters"
      });
    }

    const { hash: oldHash } =
      hashPassword(
        oldPassword,
        current.password_salt
      );

    if (
      !safeEqual(
        oldHash,
        current.password_hash
      )
    ) {
      return res.status(401).json({
        error: "Current password is incorrect"
      });
    }

    try {
      if (nextPassword) {
        const {
          hash,
          salt
        } = hashPassword(nextPassword);

        db.prepare(`
          UPDATE admin_settings
          SET
            username = ?,
            password_hash = ?,
            password_salt = ?,
            updated_at = CURRENT_TIMESTAMP
          WHERE id = 1
        `).run(
          nextUsername,
          hash,
          salt
        );
      } else {
        db.prepare(`
          UPDATE admin_settings
          SET
            username = ?,
            updated_at = CURRENT_TIMESTAMP
          WHERE id = 1
        `).run(nextUsername);
      }
    } catch (err) {
      if (
        String(err.message).includes("UNIQUE")
      ) {
        return res.status(409).json({
          error:
            "That username is already in use"
        });
      }

      throw err;
    }

    clearAdminCookie(res);

    return res.json({
      ok: true,
      message:
        "Admin credentials updated. Please log in again."
    });
  }
);

/* =========================
   ADMIN LOGOUT / ME
========================= */

app.post(
  "/api/admin/logout",
  (req, res) => {
    clearAdminCookie(res);

    res.json({
      ok: true
    });
  }
);

app.get(
  "/api/admin/me",
  (req, res) => {
    const token = getCookie(
      req,
      COOKIE_NAME
    );

    res.json({
      admin: verifyAdminToken(token)
    });
  }
);

/* =========================
   ADMIN STATS
========================= */

app.get(
  "/api/admin/stats",
  adminOnly,
  (req, res) => {
    const listings = db
      .prepare(
        "SELECT COUNT(*) AS c FROM products"
      )
      .get().c;

    const orders = db
      .prepare(
        "SELECT COUNT(*) AS c FROM orders"
      )
      .get().c;

    const available = db
      .prepare(`
        SELECT COUNT(*) AS c
        FROM products
        WHERE lower(stock) = 'available'
      `)
      .get().c;

    const revenue = db
      .prepare(`
        SELECT COALESCE(SUM(amount), 0) AS n
        FROM orders
        WHERE status = 'Completed'
      `)
      .get().n;

    res.json({
      listings,
      orders,
      available,
      revenue
    });
  }
);

/* =========================
   ADMIN ORDERS
========================= */

app.get(
  "/api/admin/orders",
  adminOnly,
  (req, res) => {
    const rows = db
      .prepare(`
        SELECT
          o.*,
          p.title AS product_title
        FROM orders o
        JOIN products p
          ON p.id = o.product_id
        ORDER BY o.id DESC
      `)
      .all();

    res.json(rows);
  }
);

/* =========================
   ADMIN ADD PRODUCT
========================= */

app.post(
  "/api/admin/products",
  adminOnly,
  upload.fields([
    {
      name: "image",
      maxCount: 1
    },
    {
      name: "video",
      maxCount: 1
    }
  ]),
  (req, res) => {
    const {
      title,
      game,
      level,
      rank,
      price,
      stock = "Available",
      description
    } = req.body;

    if (
      !title?.trim() ||
      !game?.trim() ||
      !level?.trim() ||
      !rank?.trim() ||
      !price ||
      !description?.trim()
    ) {
      return res.status(400).json({
        error:
          "Title, game, level, rank, price and description are required"
      });
    }

    const image = req.files?.image?.[0]
      ? `/uploads/${req.files.image[0].filename}`
      : null;

    const video = req.files?.video?.[0]
      ? `/uploads/${req.files.video[0].filename}`
      : null;

    const info = db
      .prepare(`
        INSERT INTO products
        (
          title,
          game,
          level,
          rank,
          price,
          stock,
          description,
          image,
          video
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
      `)
      .run(
        title.trim(),
        game.trim(),
        level.trim(),
        rank.trim(),
        Number(price),
        stock.trim(),
        description.trim(),
        image,
        video
      );

    res.status(201).json({
      id: info.lastInsertRowid
    });
  }
);

/* =========================
   ADMIN DELETE PRODUCT
========================= */

app.delete(
  "/api/admin/products/:id",
  adminOnly,
  (req, res) => {
    const product = db
      .prepare(`
        SELECT image, video
        FROM products
        WHERE id = ?
      `)
      .get(req.params.id);

    if (!product) {
      return res.status(404).json({
        error: "Not found"
      });
    }

    db.prepare(`
      DELETE FROM products
      WHERE id = ?
    `).run(req.params.id);

    for (const url of [
      product.image,
      product.video
    ]) {
      if (
        url &&
        url.startsWith("/uploads/")
      ) {
        const filePath = path.join(
          ROOT,
          url.slice(1)
        );

        if (fs.existsSync(filePath)) {
          fs.unlinkSync(filePath);
        }
      }
    }

    res.json({
      ok: true
    });
  }
);

/* =========================
   ADMIN UPDATE ORDER
========================= */

app.patch(
  "/api/admin/orders/:id",
  adminOnly,
  (req, res) => {
    const allowed = [
      "Pending",
      "Completed",
      "Cancelled"
    ];

    if (
      !allowed.includes(
        req.body?.status
      )
    ) {
      return res.status(400).json({
        error: "Invalid status"
      });
    }

    const result = db
      .prepare(`
        UPDATE orders
        SET status = ?
        WHERE id = ?
      `)
      .run(
        req.body.status,
        req.params.id
      );

    if (!result.changes) {
      return res.status(404).json({
        error: "Order not found"
      });
    }

    res.json({
      ok: true
    });
  }
);

/* =========================
   FRONTEND
========================= */

app.get(/.*/, (req, res) => {
  res.sendFile(
    path.join(
      ROOT,
      "public",
      "index.html"
    )
  );
});

/* =========================
   ERROR HANDLER
========================= */

app.use(
  (err, req, res, next) => {
    console.error(err);

    res.status(400).json({
      error:
        err.message ||
        "Request failed"
    });
  }
);

/* =========================
   LOCAL + NETLIFY
========================= */

if (require.main === module) {
  app.listen(
    PORT,
    () => {
      console.log(
        `GameVault running on http://localhost:${PORT}`
      );
    }
  );
}

module.exports = app;