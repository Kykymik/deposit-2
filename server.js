"use strict";

require("dotenv").config();

const express = require("express");
const session = require("express-session");
const bcrypt = require("bcryptjs");
const Database = require("better-sqlite3");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");

const app = express();
const PORT = Number(process.env.PORT) || 3000;
const IS_PRODUCTION = process.env.NODE_ENV === "production";
const SESSION_SECRET = process.env.SESSION_SECRET;

if (IS_PRODUCTION && (!SESSION_SECRET || SESSION_SECRET.length < 32)) {
  throw new Error("Set SESSION_SECRET to a random secret of at least 32 characters.");
}

const sessionSecret =
  SESSION_SECRET || crypto.randomBytes(32).toString("hex");

const dataDir = path.join(__dirname, "data");
fs.mkdirSync(dataDir, { recursive: true });

const db = new Database(path.join(dataDir, "deposit.sqlite"));

db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL COLLATE NOCASE UNIQUE,
    password_hash TEXT NOT NULL,
    balance INTEGER NOT NULL DEFAULT 100000,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS transactions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    type TEXT NOT NULL,
    amount INTEGER NOT NULL,
    balance_after INTEGER NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
  );
`);

const findUser = db.prepare(
  "SELECT id, username, password_hash, balance FROM users WHERE username = ?"
);

const getUser = db.prepare(
  "SELECT id, username, balance FROM users WHERE id = ?"
);

const addTransaction = db.prepare(`
  INSERT INTO transactions (user_id, type, amount, balance_after)
  VALUES (?, ?, ?, ?)
`);

const getHistory = db.prepare(`
  SELECT id, type, amount, balance_after, created_at
  FROM transactions
  WHERE user_id = ?
  ORDER BY id DESC
  LIMIT 50
`);

app.disable("x-powered-by");

app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'"],
        imgSrc: ["'self'", "data:"],
        connectSrc: ["'self'"],
        objectSrc: ["'none'"],
        baseUri: ["'self'"],
        frameAncestors: ["'none'"]
      }
    }
  })
);

app.use(express.json({ limit: "10kb" }));

app.use(
  session({
    name: "deposit.sid",
    secret: sessionSecret,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: "lax",
      secure: IS_PRODUCTION,
      maxAge: 1000 * 60 * 60 * 24
    }
  })
);

app.use(
  "/api",
  rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 150,
    standardHeaders: "draft-7",
    legacyHeaders: false
  })
);

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: "draft-7",
  legacyHeaders: false
});

function requireLogin(req, res, next) {
  if (!req.session.userId) {
    return res.status(401).json({ error: "Сначала войдите в аккаунт." });
  }

  const user = getUser.get(req.session.userId);

  if (!user) {
    req.session.destroy(() => {});
    return res.status(401).json({ error: "Аккаунт не найден." });
  }

  req.user = user;
  next();
}

function publicUser(user) {
  return {
    id: user.id,
    username: user.username,
    balance: user.balance
  };
}

function saveLogin(req, res, user) {
  req.session.regenerate((err) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ error: "Ошибка создания сессии." });
    }

    req.session.userId = user.id;

    req.session.save((saveError) => {
      if (saveError) {
        console.error(saveError);
        return res.status(500).json({ error: "Не удалось сохранить сессию." });
      }

      res.json({ user: publicUser(user) });
    });
  });
}

app.get("/api/health", (req, res) => {
  res.json({ ok: true, mode: "DEMO" });
});

app.get("/api/me", (req, res) => {
  if (!req.session.userId) {
    return res.json({ user: null });
  }

  const user = getUser.get(req.session.userId);

  if (!user) {
    return res.json({ user: null });
  }

  res.json({ user: publicUser(user) });
});

app.post("/api/register", authLimiter, async (req, res) => {
  const username = String(req.body.username || "").trim();
  const password = String(req.body.password || "");

  if (!/^[a-zA-Z0-9_]{3,20}$/.test(username)) {
    return res.status(400).json({
      error: "Имя: 3–20 символов, только латинские буквы, цифры и _."
    });
  }

  if (password.length < 8 || password.length > 72) {
    return res.status(400).json({
      error: "Пароль должен содержать от 8 до 72 символов."
    });
  }

  try {
    const passwordHash = await bcrypt.hash(password, 12);

    const createUser = db.transaction(() => {
      const result = db.prepare(`
        INSERT INTO users (username, password_hash, balance)
        VALUES (?, ?, 100000)
      `).run(username, passwordHash);

      const id = Number(result.lastInsertRowid);

      addTransaction.run(id, "DEMO_START", 100000, 100000);

      return getUser.get(id);
    });

    const user = createUser();

    saveLogin(req, res, user);
  } catch (error) {
    if (String(error.code || "").includes("SQLITE_CONSTRAINT")) {
      return res.status(409).json({
        error: "Это имя пользователя уже занято."
      });
    }

    console.error(error);
    res.status(500).json({ error: "Не удалось создать аккаунт." });
  }
});

app.post("/api/login", authLimiter, async (req, res) => {
  const username = String(req.body.username || "").trim();
  const password = String(req.body.password || "");

  if (username.length > 20 || password.length > 72) {
    return res.status(400).json({ error: "Проверьте данные входа." });
  }

  try {
    const user = findUser.get(username);

    if (!user || !(await bcrypt.compare(password, user.password_hash))) {
      return res.status(401).json({
        error: "Неверное имя пользователя или пароль."
      });
    }

    saveLogin(req, res, user);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Ошибка входа." });
  }
});

app.post("/api/logout", (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return res.status(500).json({ error: "Не удалось выйти." });
    }

    res.clearCookie("deposit.sid", {
      httpOnly: true,
      sameSite: "lax",
      secure: IS_PRODUCTION
    });

    res.json({ ok: true });
  });
});

app.get("/api/history", requireLogin, (req, res) => {
  res.json({ items: getHistory.all(req.user.id) });
});

app.post("/api/demo-topup", requireLogin, (req, res) => {
  const amount = Number(req.body.amount);

  if (!Number.isSafeInteger(amount) || amount < 100 || amount > 100000) {
    return res.status(400).json({
      error: "Можно добавить от 100 до 100000 демо-кредитов."
    });
  }

  try {
    const result = db.transaction(() => {
      const user = getUser.get(req.user.id);
      const balance = user.balance + amount;

      if (!Number.isSafeInteger(balance)) {
        throw new Error("Недопустимый баланс.");
      }

      db.prepare("UPDATE users SET balance = ? WHERE id = ?")
        .run(balance, user.id);

      addTransaction.run(
        user.id,
        "DEMO_TOPUP",
        amount,
        balance
      );

      return { balance };
    })();

    res.json({
      ...result,
      message: "Добавлены виртуальные демо-кредиты."
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Не удалось пополнить демо-баланс." });
  }
});

app.post("/api/demo-play", requireLogin, (req, res) => {
  const bet = Number(req.body.bet);

  if (!Number.isSafeInteger(bet) || bet < 1 || bet > 1000) {
    return res.status(400).json({
      error: "Ставка должна быть от 1 до 1000 демо-кредитов."
    });
  }

  try {
    const result = db.transaction(() => {
      const user = getUser.get(req.user.id);

      if (!user || user.balance < bet) {
        throw new Error("Недостаточно демо-кредитов.");
      }

      const won = crypto.randomInt(0, 100) < 45;
      const change = won ? bet : -bet;
      const balance = user.balance + change;

      db.prepare("UPDATE users SET balance = ? WHERE id = ?")
        .run(balance, user.id);

      addTransaction.run(
        user.id,
        won ? "DEMO_WIN" : "DEMO_LOSS",
        change,
        balance
      );

      return { won, change, balance };
    })();

    res.json({ ...result, mode: "DEMO" });
  } catch (error) {
    if (error.message === "Недостаточно демо-кредитов.") {
      return res.status(400).json({ error: error.message });
    }

    console.error(error);
    res.status(500).json({ error: "Не удалось выполнить демо-игру." });
  }
});

app.use(express.static(path.join(__dirname, "public")));

app.use((req, res) => {
  res.status(404).json({ error: "Страница или маршрут не найдены." });
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`DEPOSIT 2.0 demo server running on port ${PORT}`);
});
