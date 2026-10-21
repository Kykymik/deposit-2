"use strict";

const express = require("express");
const session = require("express-session");
const bcrypt = require("bcryptjs");
const Database = require("better-sqlite3");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const path = require("path");
const fs = require("fs");

const app = express();
const PORT = process.env.PORT || 3000;
const IS_PRODUCTION = process.env.NODE_ENV === "production";

app.set("trust proxy", 1);

const ADMIN_USERNAME = (
  process.env.ADMIN_USERNAME || "black"
).trim().toLowerCase();

const SESSION_SECRET = process.env.SESSION_SECRET;

if (IS_PRODUCTION && (!SESSION_SECRET || SESSION_SECRET.length < 32)) {
  console.error(
    "ERROR: Set SESSION_SECRET in Render Environment. Use at least 32 characters."
  );
  process.exit(1);
}

app.disable("x-powered-by");

app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        scriptSrc: ["'self'", "'unsafe-inline'"]
      }
    }
  })
);

app.use(express.json({ limit: "20kb" }));
app.use(express.urlencoded({ extended: false, limit: "20kb" }));

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 100,
  standardHeaders: "draft-8",
  legacyHeaders: false
});

app.use("/api/", limiter);

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: "draft-8",
  legacyHeaders: false,
  message: {
    error: "Слишком много попыток. Попробуй позже."
  }
});

const dbPath = process.env.DB_PATH ||
  path.join(__dirname, "data", "deposit.sqlite");

fs.mkdirSync(path.dirname(dbPath), { recursive: true });

const db = new Database(dbPath);

db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE COLLATE NOCASE,
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

app.use(
  session({
    name: "deposit.sid",
    secret: SESSION_SECRET || "development-only-secret-change-this",
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      secure: IS_PRODUCTION,
      sameSite: "lax",
      maxAge: 24 * 60 * 60 * 1000
    }
  })
);

const findUserById = db.prepare(`
  SELECT id, username, balance, created_at
  FROM users
  WHERE id = ?
`);

const findUserByUsername = db.prepare(`
  SELECT *
  FROM users
  WHERE username = ? COLLATE NOCASE
`);

const insertTransaction = db.prepare(`
  INSERT INTO transactions
    (user_id, type, amount, balance_after)
  VALUES (?, ?, ?, ?)
`);

function publicUser(user) {
  return {
    id: user.id,
    username: user.username,
    balance: user.balance,
    created_at: user.created_at
  };
}

function requireLogin(req, res, next) {
  if (!req.session.userId) {
    return res.status(401).json({
      error: "Сначала войди в аккаунт."
    });
  }

  const user = findUserById.get(req.session.userId);

  if (!user) {
    req.session.destroy(() => {});
    return res.status(401).json({
      error: "Аккаунт не найден. Войди снова."
    });
  }

  req.user = user;
  next();
}

function requireAdmin(req, res, next) {
  if (!req.session.userId) {
    return res.status(401).json({
      error: "Сначала войди в аккаунт."
    });
  }

  const user = findUserById.get(req.session.userId);

  if (!user) {
    return res.status(401).json({
      error: "Аккаунт не найден."
    });
  }

  if (user.username.toLowerCase() !== ADMIN_USERNAME) {
    return res.status(403).json({
      error: "Доступ только для администратора."
    });
  }

  req.user = user;
  next();
}

app.get("/api/health", (req, res) => {
  res.json({
    ok: true,
    service: "DEPOSIT 2.0"
  });
});

app.get("/api/me", (req, res) => {
  if (!req.session.userId) {
    return res.json({ user: null });
  }

  const user = findUserById.get(req.session.userId);

  if (!user) {
    return res.json({ user: null });
  }

  res.json({ user });
});

app.post("/api/register", loginLimiter, async (req, res) => {
  try {
    const username = String(req.body.username || "").trim();
    const password = String(req.body.password || "");

    if (!/^[a-zA-Z0-9_]{3,32}$/.test(username)) {
      return res.status(400).json({
        error: "Логин должен содержать 3–32 английских буквы, цифры или _."
      });
    }

    if (password.length < 8 || password.length > 128) {
      return res.status(400).json({
        error: "Пароль должен содержать от 8 до 128 символов."
      });
    }

    if (username.toLowerCase() === ADMIN_USERNAME) {
      return res.status(403).json({
        error: "Этот логин зарезервирован для администратора."
      });
    }

    const passwordHash = await bcrypt.hash(password, 12);

    let userId;

    try {
      const result = db.prepare(`
        INSERT INTO users (username, password_hash, balance)
        VALUES (?, ?, 100000)
      `).run(username, passwordHash);

      userId = Number(result.lastInsertRowid);

      insertTransaction.run(
        userId,
        "demo_bonus",
        100000,
        100000
      );
    } catch (error) {
      if (String(error.code).includes("SQLITE_CONSTRAINT")) {
        return res.status(409).json({
          error: "Такой логин уже существует."
        });
      }

      throw error;
    }

    req.session.userId = userId;

    req.session.save((error) => {
      if (error) {
        console.error("Session save error:", error.message);
        return res.status(500).json({
          error: "Не удалось создать сессию. Попробуй снова."
        });
      }

      res.status(201).json({
        user: publicUser(findUserById.get(userId))
      });
    });
  } catch (error) {
    console.error("Registration error:", error.message);
    res.status(500).json({
      error: "Ошибка регистрации."
    });
  }
});

app.post("/api/login", loginLimiter, async (req, res) => {
  try {
    const username = String(req.body.username || "").trim();
    const password = String(req.body.password || "");

    if (!username || !password) {
      return res.status(400).json({
        error: "Введи логин и пароль."
      });
    }

    const user = findUserByUsername.get(username);

    if (!user) {
      return res.status(401).json({
        error: "Неверный логин или пароль."
      });
    }

    const valid = await bcrypt.compare(password, user.password_hash);

    if (!valid) {
      return res.status(401).json({
        error: "Неверный логин или пароль."
      });
    }

    req.session.regenerate((error) => {
      if (error) {
        console.error("Session regenerate error:", error.message);
        return res.status(500).json({
          error: "Не удалось начать сессию."
        });
      }

      req.session.userId = user.id;

      req.session.save((saveError) => {
        if (saveError) {
          console.error("Session save error:", saveError.message);
          return res.status(500).json({
            error: "Не удалось сохранить сессию."
          });
        }

        res.json({
          user: publicUser(findUserById.get(user.id))
        });
      });
    });
  } catch (error) {
    console.error("Login error:", error.message);
    res.status(500).json({
      error: "Ошибка входа."
    });
  }
});

app.post("/api/logout", (req, res) => {
  req.session.destroy((error) => {
    if (error) {
      return res.status(500).json({
        error: "Не удалось выйти."
      });
    }

    res.clearCookie("deposit.sid", {
      httpOnly: true,
      secure: IS_PRODUCTION,
      sameSite: "lax"
    });

    res.json({ ok: true });
  });
});

app.get("/api/history", requireLogin, (req, res) => {
  const items = db.prepare(`
    SELECT id, type, amount, balance_after, created_at
    FROM transactions
    WHERE user_id = ?
    ORDER BY id DESC
    LIMIT 100
  `).all(req.user.id);

  res.json({ items });
});

app.post("/api/demo-topup", requireLogin, (req, res) => {
  const amount = Number(req.body.amount);

  if (
    !Number.isSafeInteger(amount) ||
    amount < 1 ||
    amount > 100000
  ) {
    return res.status(400).json({
      error: "Некорректное количество демо-кредитов."
    });
  }

  const result = db.transaction(() => {
    const user = db.prepare(`
      SELECT balance FROM users WHERE id = ?
    `).get(req.user.id);

    const newBalance = user.balance + amount;

    db.prepare(`
      UPDATE users SET balance = ? WHERE id = ?
    `).run(newBalance, req.user.id);

    insertTransaction.run(
      req.user.id,
      "demo_topup",
      amount,
      newBalance
    );

    return newBalance;
  })();

  res.json({
    ok: true,
    balance: result,
    message: "Демо-кредиты добавлены."
  });
});

app.post("/api/demo-play", requireLogin, (req, res) => {
  const bet = Number(req.body.bet);
  const game = String(req.body.game || "");

  if (!["luck", "coin", "challenge"].includes(game)) {
    return res.status(400).json({
      error: "Неизвестная демо-игра."
    });
  }

  if (!Number.isSafeInteger(bet) || bet !== 100) {
    return res.status(400).json({
      error: "Ставка в демо-режиме должна составлять 100 кредитов."
    });
  }

  const result = db.transaction(() => {
    const user = db.prepare(`
      SELECT balance FROM users WHERE id = ?
    `).get(req.user.id);

    if (!user || user.balance < bet) {
      throw new Error("Недостаточно демо-кредитов.");
    }

    const won = Math.random() < 0.45;
    const delta = won ? bet : -bet;
    const newBalance = user.balance + delta;

    db.prepare(`
      UPDATE users SET balance = ? WHERE id = ?
    `).run(newBalance, req.user.id);

    insertTransaction.run(
      req.user.id,
      "demo_game_" + game,
      delta,
      newBalance
    );

    return { won, newBalance, delta };
  });

  try {
    const outcome = result();

    res.json({
      ok: true,
      balance: outcome.newBalance,
      amount: outcome.delta,
      message: outcome.won
        ? "Ты выиграл 100 виртуальных демо-кредитов!"
        : "Ты потерял 100 виртуальных демо-кредитов."
    });
  } catch (error) {
    res.status(400).json({
      error: error.message
    });
  }
});

app.get("/api/admin/me", requireAdmin, (req, res) => {
  res.json({
    ok: true,
    user: publicUser(req.user)
  });
});

app.get("/api/admin/users", requireAdmin, (req, res) => {
  const users = db.prepare(`
    SELECT id, username, balance, created_at
    FROM users
    ORDER BY id DESC
    LIMIT 500
  `).all();

  res.json({ users });
});

app.get("/api/admin/users/:id/history", requireAdmin, (req, res) => {
  const userId = Number(req.params.id);

  if (!Number.isSafeInteger(userId) || userId < 1) {
    return res.status(400).json({
      error: "Некорректный ID пользователя."
    });
  }

  const user = findUserById.get(userId);

  if (!user) {
    return res.status(404).json({
      error: "Пользователь не найден."
    });
  }

  const items = db.prepare(`
    SELECT id, type, amount, balance_after, created_at
    FROM transactions
    WHERE user_id = ?
    ORDER BY id DESC
    LIMIT 100
  `).all(userId);

  res.json({
    user: publicUser(user),
    items
  });
});

app.post("/api/admin/demo-adjust", requireAdmin, (req, res) => {
  const userId = Number(req.body.userId);
  const amount = Number(req.body.amount);

  if (
    !Number.isSafeInteger(userId) ||
    userId < 1 ||
    !Number.isSafeInteger(amount) ||
    amount === 0 ||
    Math.abs(amount) > 1000000
  ) {
    return res.status(400).json({
      error: "Некорректный ID или сумма."
    });
  }

  try {
    const result = db.transaction(() => {
      const user = db.prepare(`
        SELECT id, balance FROM users WHERE id = ?
      `).get(userId);

      if (!user) {
        throw new Error("Пользователь не найден.");
      }

      const newBalance = user.balance + amount;

      if (newBalance < 0 || !Number.isSafeInteger(newBalance)) {
        throw new Error("Баланс не может быть отрицательным.");
      }

      db.prepare(`
        UPDATE users SET balance = ? WHERE id = ?
      `).run(newBalance, userId);

      insertTransaction.run(
        userId,
        "admin_demo_adjustment",
        amount,
        newBalance
      );

      return newBalance;
    })();

    res.json({
      ok: true,
      balance: result,
      message: "Демо-баланс успешно изменён."
    });
  } catch (error) {
    res.status(400).json({
      error: error.message
    });
  }
});

app.use(express.static(path.join(__dirname, "public")));

app.use((req, res) => {
  if (req.path.startsWith("/api/")) {
    return res.status(404).json({
      error: "API-маршрут не найден."
    });
  }

  res.status(404).send("Страница не найдена.");
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`DEPOSIT 2.0 running on port ${PORT}`);
  console.log(`Database path: ${dbPath}`);
});
