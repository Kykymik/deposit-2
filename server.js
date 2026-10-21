"use strict";

const express = require("express");
const session = require("express-session");
const bcrypt = require("bcryptjs");
const Database = require("better-sqlite3");
const helmet = require("helmet");
const path = require("path");
const fs = require("fs");

const rateLimitModule = require("express-rate-limit");
const rateLimit =
  rateLimitModule.rateLimit || rateLimitModule;

const app = express();

const PORT = Number(process.env.PORT) || 3000;
const IS_PRODUCTION = process.env.NODE_ENV === "production";

const ADMIN_USERNAME = (
  process.env.ADMIN_USERNAME || "black"
).toLowerCase();

const SESSION_SECRET = process.env.SESSION_SECRET;

if (
  IS_PRODUCTION &&
  (!SESSION_SECRET || SESSION_SECRET.length < 32)
) {
  throw new Error(
    "В Render задай SESSION_SECRET длиной не менее 32 символов."
  );
}

app.disable("x-powered-by");
app.set("trust proxy", 1);

app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'", "'unsafe-inline'"],
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
  rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 300,
    standardHeaders: "draft-8",
    legacyHeaders: false
  })
);

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 20,
  standardHeaders: "draft-8",
  legacyHeaders: false,
  message: {
    error: "Слишком много попыток. Попробуй позже."
  }
});

// --------------------------------------------------
// БАЗА ДАННЫХ
// --------------------------------------------------

const DB_PATH =
  process.env.DB_PATH ||
  path.join(__dirname, "data", "deposit.sqlite");

fs.mkdirSync(path.dirname(DB_PATH), {
  recursive: true
});

const db = new Database(DB_PATH);

db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
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

// Добавляем игровое ID, не удаляя существующих пользователей.
const userColumns = db
  .prepare("PRAGMA table_info(users)")
  .all();

if (!userColumns.some((column) => column.name === "gamer_id")) {
  db.exec("ALTER TABLE users ADD COLUMN gamer_id TEXT");
}

// Присваиваем ID существующим игрокам.
const usersWithoutGamerId = db.prepare(`
  SELECT id
  FROM users
  WHERE gamer_id IS NULL OR gamer_id = ''
`).all();

const setGamerId = db.prepare(`
  UPDATE users
  SET gamer_id = ?
  WHERE id = ?
`);

for (const user of usersWithoutGamerId) {
  setGamerId.run(
    "D2" + String(user.id).padStart(8, "0"),
    user.id
  );
}

db.exec(`
  CREATE UNIQUE INDEX IF NOT EXISTS idx_users_gamer_id
  ON users(gamer_id);

  CREATE TABLE IF NOT EXISTS topup_requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    gamer_id TEXT NOT NULL,
    amount INTEGER NOT NULL CHECK(amount > 0),
    status TEXT NOT NULL DEFAULT 'pending'
      CHECK(status IN ('pending', 'approved', 'rejected')),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    reviewed_at TEXT,
    admin_note TEXT,
    FOREIGN KEY (user_id) REFERENCES users(id)
  );
`);

const findUserById = db.prepare(`
  SELECT id, username, password_hash, balance,
         gamer_id, created_at
  FROM users
  WHERE id = ?
`);

const findUserByUsername = db.prepare(`
  SELECT id, username, password_hash, balance,
         gamer_id, created_at
  FROM users
  WHERE lower(username) = lower(?)
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
    gamer_id: user.gamer_id,
    balance: user.balance,
    created_at: user.created_at
  };
}

// --------------------------------------------------
// СЕССИИ
// --------------------------------------------------

app.use(
  session({
    name: "deposit.sid",
    secret: SESSION_SECRET || "development-only-change-this-secret",
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: "lax",
      secure: IS_PRODUCTION,
      maxAge: 7 * 24 * 60 * 60 * 1000
    }
  })
);

// --------------------------------------------------
// ПРОВЕРКИ ДОСТУПА
// --------------------------------------------------

function requireLogin(req, res, next) {
  const userId = req.session.userId;

  if (!userId) {
    return res.status(401).json({
      error: "Сначала войди в аккаунт."
    });
  }

  const user = findUserById.get(userId);

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

  if (!user || user.username.toLowerCase() !== ADMIN_USERNAME) {
    return res.status(403).json({
      error: "Доступ только для администратора."
    });
  }

  req.user = user;
  next();
}

// --------------------------------------------------
// РЕГИСТРАЦИЯ
// --------------------------------------------------

app.post(
  "/api/register",
  loginLimiter,
  async (req, res) => {
    try {
      const username =
        typeof req.body.username === "string"
          ? req.body.username.trim()
          : "";

      const password =
        typeof req.body.password === "string"
          ? req.body.password
          : "";

      if (!/^[a-zA-Z0-9_-]{3,32}$/.test(username)) {
        return res.status(400).json({
          error:
            "Логин: от 3 до 32 символов, только латинские буквы, цифры, _ и -."
        });
      }

      if (password.length < 6 || password.length > 128) {
        return res.status(400).json({
          error: "Пароль должен содержать от 6 до 128 символов."
        });
      }

      // Нельзя создать новый аккаунт с именем администратора.
      if (username.toLowerCase() === ADMIN_USERNAME) {
        return res.status(400).json({
          error: "Этот логин зарезервирован."
        });
      }

      if (findUserByUsername.get(username)) {
        return res.status(409).json({
          error: "Такой логин уже занят."
        });
      }

      const passwordHash = await bcrypt.hash(password, 12);

      const createUser = db.transaction(() => {
        const result = db.prepare(`
          INSERT INTO users
            (username, password_hash, balance)
          VALUES (?, ?, 0)
        `).run(username, passwordHash);

        const userId = Number(result.lastInsertRowid);

        const gamerId =
          "D2" + String(userId).padStart(8, "0");

        db.prepare(`
          UPDATE users
          SET gamer_id = ?
          WHERE id = ?
        `).run(gamerId, userId);

        return userId;
      });

      const userId = createUser();

      req.session.userId = userId;

      req.session.save((error) => {
        if (error) {
          console.error("Session save error:", error);

          return res.status(500).json({
            error: "Аккаунт создан, но не удалось войти. Попробуй войти вручную."
          });
        }

        const user = findUserById.get(userId);

        return res.status(201).json({
          ok: true,
          user: publicUser(user),
          message: "Аккаунт создан. Баланс: 0 UZS."
        });
      });
    } catch (error) {
      console.error("Registration error:", error.message);

      if (String(error.code || "").startsWith("SQLITE_CONSTRAINT")) {
        return res.status(409).json({
          error: "Не удалось создать аккаунт: данные уже используются."
        });
      }

      return res.status(500).json({
        error: "Ошибка регистрации."
      });
    }
  }
);

// --------------------------------------------------
// ВХОД
// --------------------------------------------------

app.post(
  "/api/login",
  loginLimiter,
  async (req, res) => {
    try {
      const username =
        typeof req.body.username === "string"
          ? req.body.username.trim()
          : "";

      const password =
        typeof req.body.password === "string"
          ? req.body.password
          : "";

      if (!username || !password) {
        return res.status(400).json({
          error: "Введи логин и пароль."
        });
      }

      const user = findUserByUsername.get(username);

      if (
        !user ||
        !(await bcrypt.compare(password, user.password_hash))
      ) {
        return res.status(401).json({
          error: "Неверный логин или пароль."
        });
      }

      req.session.regenerate((error) => {
        if (error) {
          return res.status(500).json({
            error: "Не удалось начать сессию."
          });
        }

        req.session.userId = user.id;

        req.session.save((saveError) => {
          if (saveError) {
            return res.status(500).json({
              error: "Не удалось сохранить сессию."
            });
          }

          const updatedUser = findUserById.get(user.id);

          return res.json({
            ok: true,
            user: publicUser(updatedUser),
            message: "Вход выполнен."
          });
        });
      });
    } catch (error) {
      console.error("Login error:", error.message);

      return res.status(500).json({
        error: "Ошибка входа."
      });
    }
  }
);

// --------------------------------------------------
// ВЫХОД
// --------------------------------------------------

app.post("/api/logout", (req, res) => {
  req.session.destroy((error) => {
    if (error) {
      return res.status(500).json({
        error: "Не удалось выйти."
      });
    }

    res.clearCookie("deposit.sid");

    return res.json({
      ok: true,
      message: "Выход выполнен."
    });
  });
});

// --------------------------------------------------
// ДАННЫЕ ТЕКУЩЕГО ИГРОКА
// --------------------------------------------------

app.get("/api/me", (req, res) => {
  if (!req.session.userId) {
    return res.json({ user: null });
  }

  const user = findUserById.get(req.session.userId);

  if (!user) {
    return res.json({ user: null });
  }

  return res.json({
    user: publicUser(user)
  });
});

// --------------------------------------------------
// ИСТОРИЯ ОПЕРАЦИЙ ИГРОКА
// --------------------------------------------------

app.get("/api/history", requireLogin, (req, res) => {
  const items = db.prepare(`
    SELECT id, type, amount, balance_after, created_at
    FROM transactions
    WHERE user_id = ?
    ORDER BY id DESC
    LIMIT 100
  `).all(req.user.id);

  return res.json({ items });
});

// --------------------------------------------------
// ТЕСТОВЫЕ ИГРЫ
// --------------------------------------------------

app.post("/api/demo-play", requireLogin, (req, res) => {
  const bet = Number(req.body.bet);
  const game = req.body.game;

  if (
    bet !== 100 ||
    !["luck", "coin", "challenge"].includes(game)
  ) {
    return res.status(400).json({
      error: "Некорректная демо-игра или ставка."
    });
  }

  try {
    const play = db.transaction(() => {
      const user = findUserById.get(req.user.id);

      if (user.balance < bet) {
        throw new Error("Недостаточно средств для игры.");
      }

      const won = Math.random() < 0.5;

      let balance = user.balance - bet;

      insertTransaction.run(
        user.id,
        "demo_bet",
        -bet,
        balance
      );

      let message;

      if (won) {
        // Возврат ставки плюс виртуальный выигрыш.
        balance += bet * 2;

        insertTransaction.run(
          user.id,
          "demo_win",
          bet * 2,
          balance
        );

        message = "Удача! Тестовый выигрыш зачислен.";
      } else {
        message = "В этот раз не повезло. Это демо-игра.";
      }

      db.prepare(`
        UPDATE users
        SET balance = ?
        WHERE id = ?
      `).run(balance, user.id);

      return { balance, won, message };
    });

    const result = play();

    return res.json({
      ok: true,
      balance: result.balance,
      won: result.won,
      message: result.message
    });
  } catch (error) {
    return res.status(400).json({
      error: error.message || "Не удалось сыграть."
    });
  }
});

// --------------------------------------------------
// ТЕСТОВОЕ ИЗМЕНЕНИЕ БАЛАНСА АДМИНИСТРАТОРОМ
// --------------------------------------------------

app.post(
  "/api/admin/demo-adjust",
  requireAdmin,
  (req, res) => {
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
        error: "Проверь ID пользователя и сумму."
      });
    }

    try {
      const adjust = db.transaction(() => {
        const user = findUserById.get(userId);

        if (!user) {
          throw new Error("Пользователь не найден.");
        }

        const balance = user.balance + amount;

        if (
          !Number.isSafeInteger(balance) ||
          balance < 0
        ) {
          throw new Error(
            "Баланс не может быть отрицательным."
          );
        }

        db.prepare(`
          UPDATE users
          SET balance = ?
          WHERE id = ?
        `).run(balance, userId);

        insertTransaction.run(
          userId,
          "admin_demo_adjust",
          amount,
          balance
        );

        return balance;
      });

      const balance = adjust();

      return res.json({
        ok: true,
        balance,
        message: "Тестовый баланс изменён."
      });
    } catch (error) {
      return res.status(400).json({
        error: error.message || "Ошибка изменения баланса."
      });
    }
  }
);

// --------------------------------------------------
// ПРОВЕРКА АДМИНИСТРАТОРА
// --------------------------------------------------

app.get("/api/admin/me", requireAdmin, (req, res) => {
  return res.json({
    ok: true,
    user: publicUser(req.user)
  });
});

// --------------------------------------------------
// СПИСОК ПОЛЬЗОВАТЕЛЕЙ
// --------------------------------------------------

app.get("/api/admin/users", requireAdmin, (req, res) => {
  const users = db.prepare(`
    SELECT id, username, balance, gamer_id, created_at
    FROM users
    ORDER BY id DESC
    LIMIT 500
  `).all();

  return res.json({ users });
});

// --------------------------------------------------
// ИСТОРИЯ КОНКРЕТНОГО ПОЛЬЗОВАТЕЛЯ
// --------------------------------------------------

app.get(
  "/api/admin/users/:id/history",
  requireAdmin,
  (req, res) => {
    const userId = Number(req.params.id);

    if (!Number.isSafeInteger(userId) || userId < 1) {
      return res.status(400).json({
        error: "Некорректный ID пользователя."
      });
    }

    const items = db.prepare(`
      SELECT id, type, amount, balance_after, created_at
      FROM transactions
      WHERE user_id = ?
      ORDER BY id DESC
      LIMIT 100
    `).all(userId);

    return res.json({ items });
  }
);

// --------------------------------------------------
// СОЗДАНИЕ ТЕСТОВОЙ ЗАЯВКИ НА ПОПОЛНЕНИЕ
// --------------------------------------------------

app.post(
  "/api/topup-requests",
  requireLogin,
  (req, res) => {
    const amount = Number(req.body.amount);

    if (
      !Number.isSafeInteger(amount) ||
      amount < 1000 ||
      amount > 10000000
    ) {
      return res.status(400).json({
        error:
          "Сумма должна быть от 1 000 до 10 000 000 UZS."
      });
    }

    try {
      const result = db.prepare(`
        INSERT INTO topup_requests
          (user_id, gamer_id, amount, status)
        VALUES (?, ?, ?, 'pending')
      `).run(
        req.user.id,
        req.user.gamer_id,
        amount
      );

      return res.status(201).json({
        ok: true,
        requestId: Number(result.lastInsertRowid),
        gamerId: req.user.gamer_id,
        amount,
        status: "pending",
        message: "Тестовая заявка создана."
      });
    } catch (error) {
      console.error("Top-up request error:", error.message);

      return res.status(500).json({
        error: "Не удалось создать заявку."
      });
    }
  }
);

// --------------------------------------------------
// СПИСОК ЗАЯВОК ТЕКУЩЕГО ИГРОКА
// --------------------------------------------------

app.get(
  "/api/my-topup-requests",
  requireLogin,
  (req, res) => {
    const requests = db.prepare(`
      SELECT id, gamer_id, amount, status,
             created_at, reviewed_at, admin_note
      FROM topup_requests
      WHERE user_id = ?
      ORDER BY id DESC
      LIMIT 100
    `).all(req.user.id);

    return res.json({ requests });
  }
);

// --------------------------------------------------
// ВСЕ ЗАЯВКИ ДЛЯ АДМИНИСТРАТОРА
// --------------------------------------------------

app.get(
  "/api/admin/topup-requests",
  requireAdmin,
  (req, res) => {
    const requests = db.prepare(`
      SELECT
        r.id,
        r.user_id,
        u.username,
        r.gamer_id,
        r.amount,
        r.status,
        r.created_at,
        r.reviewed_at,
        r.admin_note
      FROM topup_requests r
      JOIN users u ON u.id = r.user_id
      ORDER BY
        CASE
          WHEN r.status = 'pending' THEN 0
          ELSE 1
        END,
        r.id DESC
      LIMIT 500
    `).all();

    return res.json({ requests });
  }
);

// --------------------------------------------------
// ПОДТВЕРЖДЕНИЕ ТЕСТОВОЙ ЗАЯВКИ
// --------------------------------------------------

app.post(
  "/api/admin/topup-requests/:id/approve",
  requireAdmin,
  (req, res) => {
    const requestId = Number(req.params.id);

    if (
      !Number.isSafeInteger(requestId) ||
      requestId < 1
    ) {
      return res.status(400).json({
        error: "Некорректный номер заявки."
      });
    }

    try {
      const approve = db.transaction(() => {
        const request = db.prepare(`
          SELECT *
          FROM topup_requests
          WHERE id = ?
        `).get(requestId);

        if (!request) {
          throw new Error("Заявка не найдена.");
        }

        if (request.status !== "pending") {
          throw new Error(
            "Заявка уже обработана. Повторное зачисление запрещено."
          );
        }

        const user = findUserById.get(request.user_id);

        if (!user) {
          throw new Error("Игрок не найден.");
        }

        const newBalance = user.balance + request.amount;

        if (!Number.isSafeInteger(newBalance)) {
          throw new Error("Недопустимая сумма баланса.");
        }

        const update = db.prepare(`
          UPDATE topup_requests
          SET status = 'approved',
              reviewed_at = CURRENT_TIMESTAMP
          WHERE id = ?
            AND status = 'pending'
        `).run(requestId);

        if (update.changes !== 1) {
          throw new Error("Заявка уже обработана.");
        }

        db.prepare(`
          UPDATE users
          SET balance = ?
          WHERE id = ?
        `).run(newBalance, user.id);

        insertTransaction.run(
          user.id,
          "test_topup_approved",
          request.amount,
          newBalance
        );

        return {
          balance: newBalance,
          amount: request.amount
        };
      });

      const result = approve();

      return res.json({
        ok: true,
        balance: result.balance,
        amount: result.amount,
        message: "Тестовая заявка подтверждена."
      });
    } catch (error) {
      return res.status(400).json({
        error: error.message || "Не удалось подтвердить заявку."
      });
    }
  }
);

// --------------------------------------------------
// ОТКЛОНЕНИЕ ЗАЯВКИ
// --------------------------------------------------

app.post(
  "/api/admin/topup-requests/:id/reject",
  requireAdmin,
  (req, res) => {
    const requestId = Number(req.params.id);

    if (
      !Number.isSafeInteger(requestId) ||
      requestId < 1
    ) {
      return res.status(400).json({
        error: "Некорректный номер заявки."
      });
    }

    const result = db.prepare(`
      UPDATE topup_requests
      SET status = 'rejected',
          reviewed_at = CURRENT_TIMESTAMP
      WHERE id = ?
        AND status = 'pending'
    `).run(requestId);

    if (result.changes !== 1) {
      return res.status(400).json({
        error: "Заявка не найдена или уже обработана."
      });
    }

    return res.json({
      ok: true,
      message: "Заявка отклонена. Баланс не изменён."
    });
  }
);

// --------------------------------------------------
// СТАТИЧЕСКИЕ ФАЙЛЫ САЙТА
// --------------------------------------------------

app.use(express.static(path.join(__dirname, "public")));

// --------------------------------------------------
// ОБРАБОТКА ОШИБОК
// --------------------------------------------------

app.use((error, req, res, next) => {
  console.error("Server error:", error.message);

  if (res.headersSent) {
    return next(error);
  }

  return res.status(500).json({
    error: "Внутренняя ошибка сервера."
  });
});

// --------------------------------------------------
// ЗАПУСК
// --------------------------------------------------

app.listen(PORT, "0.0.0.0", () => {
  console.log(`DEPOSIT 2.0 запущен на порту ${PORT}`);
});
