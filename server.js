require("dotenv").config();

const express = require("express");
const session = require("express-session");
const bcrypt = require("bcryptjs");
const Database = require("better-sqlite3");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;

if (!process.env.SESSION_SECRET) {
  console.error("SESSION_SECRET is required");
  process.exit(1);
}

app.disable("x-powered-by");
app.use(helmet());
app.use(express.json({ limit: "10kb" }));
app.use(express.urlencoded({ extended: false, limit: "10kb" }));

const db = new Database(process.env.DB_PATH || "deposit.db");
db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    demo_balance INTEGER NOT NULL DEFAULT 10000,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS transactions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    amount INTEGER NOT NULL,
    type TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id)
  );
`);

app.use(session({
  name: "deposit.sid",
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    maxAge: 1000 * 60 * 60 * 8
  }
}));

app.use(express.static(path.join(__dirname, "public")));

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: true,
  legacyHeaders: false
});

function requireLogin(req, res, next) {
  if (!req.session.userId) {
    return res.status(401).json({ error: "Сначала войдите в аккаунт" });
  }
  next();
}

app.get("/api/health", (req, res) => {
  res.json({ ok: true, mode: "DEMO" });
});

app.post("/api/register", authLimiter, async (req, res) => {
  try {
    const username = String(req.body.username || "").trim().toLowerCase();
    const password = String(req.body.password || "");

    if (!/^[a-z0-9_]{3,24}$/.test(username)) {
      return res.status(400).json({
        error: "Логин: 3–24 символа, латинские буквы, цифры и _"
      });
    }

    if (password.length < 10 || password.length > 72) {
      return res.status(400).json({
        error: "Пароль должен содержать от 10 до 72 символов"
      });
    }

    const passwordHash = await bcrypt.hash(password, 12);

    const result = db.prepare(`
      INSERT INTO users (username, password_hash)
      VALUES (?, ?)
    `).run(username, passwordHash);

    req.session.regenerate((err) => {
      if (err) return res.status(500).json({ error: "Ошибка сессии" });

      req.session.userId = Number(result.lastInsertRowid);
      req.session.save((saveErr) => {
        if (saveErr) return res.status(500).json({ error: "Ошибка сессии" });

        res.status(201).json({
          ok: true,
          username,
          balance: 10000,
          mode: "DEMO",
          note: "Баланс демонстрационный, не является деньгами"
        });
      });
    });
  } catch (err) {
    if (String(err.code) === "SQLITE_CONSTRAINT_UNIQUE") {
      return res.status(409).json({ error: "Такой логин уже существует" });
    }

    console.error(err);
    res.status(500).json({ error: "Не удалось создать аккаунт" });
  }
});

app.post("/api/login", authLimiter, async (req, res) => {
  try {
    const username = String(req.body.username || "").trim().toLowerCase();
    const password = String(req.body.password || "");

    const user = db.prepare(
      "SELECT * FROM users WHERE username = ?"
    ).get(username);

    if (!user || !(await bcrypt.compare(password, user.password_hash))) {
      return res.status(401).json({ error: "Неверный логин или пароль" });
    }

    req.session.regenerate((err) => {
      if (err) return res.status(500).json({ error: "Ошибка сессии" });

      req.session.userId = user.id;
      req.session.save((saveErr) => {
        if (saveErr) return res.status(500).json({ error: "Ошибка сессии" });

        res.json({
          ok: true,
          username: user.username,
          balance: user.demo_balance,
          mode: "DEMO"
        });
      });
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Ошибка входа" });
  }
});

app.post("/api/logout", (req, res) => {
  req.session.destroy(() => {
    res.clearCookie("deposit.sid");
    res.json({ ok: true });
  });
});

app.get("/api/me", requireLogin, (req, res) => {
  const user = db.prepare(
    "SELECT id, username, demo_balance FROM users WHERE id = ?"
  ).get(req.session.userId);

  if (!user) return res.status(401).json({ error: "Аккаунт не найден" });

  res.json({
    id: user.id,
    username: user.username,
    balance: user.demo_balance,
    mode: "DEMO"
  });
});

app.get("/api/history", requireLogin, (req, res) => {
  const rows = db.prepare(`
    SELECT amount, type, created_at
    FROM transactions
    WHERE user_id = ?
    ORDER BY id DESC
    LIMIT 50
  `).all(req.session.userId);

  res.json({ history: rows });
});

app.post("/api/demo-play", requireLogin, (req, res) => {
  const bet = Number(req.body.bet);

  if (!Number.isSafeInteger(bet) || bet < 1 || bet > 1000) {
    return res.status(400).json({ error: "Ставка: от 1 до 1000 демо-кредитов" });
  }

  const play = db.transaction(() => {
    const user = db.prepare(
      "SELECT demo_balance FROM users WHERE id = ?"
    ).get(req.session.userId);

    if (!user || user.demo_balance < bet) {
      throw new Error("INSUFFICIENT_BALANCE");
    }

    const won = Math.random() < 0.45;
    const change = won ? bet : -bet;
    const newBalance = user.demo_balance + change;

    db.prepare(
      "UPDATE users SET demo_balance = ? WHERE id = ?"
    ).run(newBalance, req.session.userId);

    db.prepare(`
      INSERT INTO transactions (user_id, amount, type)
      VALUES (?, ?, ?)
    `).run(req.session.userId, change, won ? "DEMO_WIN" : "DEMO_LOSS");

    return { won, change, balance: newBalance };
  });

  try {
    res.json({ ...play(), mode: "DEMO" });
  } catch (err) {
    if (err.message === "INSUFFICIENT_BALANCE") {
      return res.status(400).json({ error: "Недостаточно демо-кредитов" });
    }
    console.error(err);
    res.status(500).json({ error: "Ошибка игры" });
  }
});

app.use((req, res) => {
  res.status(404).json({ error: "Маршрут не найден" });
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`DEPOSIT 2.0 demo server running on port ${PORT}`);
});
