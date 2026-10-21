"use strict";

const http = require("http");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const PORT = Number(process.env.PORT) || 3000;
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || "black";
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "ChangeMe123!";

const DATA_DIR = process.env.DATA_DIR || __dirname;
const PUBLIC_DIR = path.join(__dirname, "public");
const DATA_FILE = path.join(DATA_DIR, "data.json");
const RECEIPTS_DIR = path.join(DATA_DIR, "receipts");

fs.mkdirSync(DATA_DIR, { recursive: true });
fs.mkdirSync(RECEIPTS_DIR, { recursive: true });

if (
  process.env.NODE_ENV === "production" &&
  (!process.env.SESSION_SECRET ||
    process.env.SESSION_SECRET.length < 32)
) {
  console.error("Установите SESSION_SECRET длиной не менее 32 символов.");
  process.exit(1);
}

if (
  process.env.NODE_ENV === "production" &&
  ADMIN_PASSWORD === "ChangeMe123!"
) {
  console.error("Установите собственный ADMIN_PASSWORD.");
  process.exit(1);
}

const sessions = new Map();
const games = new Map();

function createDatabase() {
  return {
    users: [],
    transactions: [],
    topupRequests: [],
    withdrawalRequests: [],
    nextUserId: 1,
    nextTransactionId: 1,
    nextRequestId: 1,
    nextWithdrawalId: 1
  };
}

function loadDatabase() {
  if (!fs.existsSync(DATA_FILE)) {
    const data = createDatabase();
    fs.writeFileSync(DATA_FILE, JSON.stringify(data, null, 2));
    return data;
  }

  const data = JSON.parse(fs.readFileSync(DATA_FILE, "utf8"));

  data.users ||= [];
  data.transactions ||= [];
  data.topupRequests ||= [];
  data.withdrawalRequests ||= [];
  data.nextUserId ||= 1;
  data.nextTransactionId ||= 1;
  data.nextRequestId ||= 1;
  data.nextWithdrawalId ||= 1;

  return data;
}

const db = loadDatabase();

function saveDatabase() {
  const temp = DATA_FILE + ".tmp";
  fs.writeFileSync(temp, JSON.stringify(db, null, 2));
  fs.renameSync(temp, DATA_FILE);
}

function randomId() {
  return crypto.randomBytes(32).toString("hex");
}

function hashPassword(password, salt = crypto.randomBytes(16).toString("hex")) {
  return {
    salt,
    hash: crypto.scryptSync(password, salt, 64).toString("hex")
  };
}

function verifyPassword(password, user) {
  try {
    const hash = crypto.scryptSync(password, user.salt, 64);
    const saved = Buffer.from(user.password_hash, "hex");

    return (
      hash.length === saved.length &&
      crypto.timingSafeEqual(hash, saved)
    );
  } catch {
    return false;
  }
}

function publicUser(user) {
  return {
    id: user.id,
    username: user.username,
    gamer_id: user.gamer_id,
    balance: user.balance
  };
}

function isAdmin(user) {
  return Boolean(user) &&
    user.username.toLowerCase() === ADMIN_USERNAME.toLowerCase();
}

function sessionUser(req) {
  const cookies = req.headers.cookie || "";
  const match = cookies.match(/(?:^|;\s*)sid=([a-f0-9]{64})(?:;|$)/);

  if (!match) return null;

  const session = sessions.get(match[1]);
  if (!session) return null;

  const user = db.users.find(u => u.id === session.userId);

  return user ? { token: match[1], user } : null;
}

function setSession(res, user) {
  const token = randomId();
  sessions.set(token, { userId: user.id });

  const secure =
    process.env.NODE_ENV === "production" ? "; Secure" : "";

  res.setHeader(
    "Set-Cookie",
    `sid=${token}; HttpOnly; SameSite=Lax; Path=/; Max-Age=86400${secure}`
  );
}

function clearSession(req, res) {
  const session = sessionUser(req);

  if (session) sessions.delete(session.token);

  const secure =
    process.env.NODE_ENV === "production" ? "; Secure" : "";

  res.setHeader(
    "Set-Cookie",
    `sid=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0${secure}`
  );
}

function json(res, status, data) {
  res.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff"
  });

  res.end(JSON.stringify(data));
}

function error(res, status, message) {
  json(res, status, { error: message });
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    let stopped = false;

    req.on("data", chunk => {
      if (stopped) return;

      size += chunk.length;

      if (size > 6 * 1024 * 1024) {
        stopped = true;
        reject(new Error("Запрос слишком большой. Максимум 6 МБ."));
        req.resume();
        return;
      }

      chunks.push(chunk);
    });

    req.on("end", () => {
      if (stopped) return;

      const raw = Buffer.concat(chunks).toString("utf8");

      if (!raw) {
        resolve({});
        return;
      }

      try {
        const data = JSON.parse(raw);

        if (!data || typeof data !== "object" || Array.isArray(data)) {
          reject(new Error("Неверный формат данных."));
          return;
        }

        resolve(data);
      } catch {
        reject(new Error("Некорректный JSON."));
      }
    });

    req.on("error", reject);
  });
}

function requireUser(session, res) {
  if (!session) {
    error(res, 401, "Сначала войдите в аккаунт.");
    return null;
  }

  return session.user;
}

function requireAdmin(user, res) {
  if (!isAdmin(user)) {
    error(res, 403, "Нет доступа администратора.");
    return false;
  }

  return true;
}

function addTransaction(user, type, amount) {
  db.transactions.push({
    id: db.nextTransactionId++,
    user_id: user.id,
    type,
    amount,
    balance_after: user.balance,
    created_at: new Date().toISOString()
  });

  saveDatabase();
}

function gamerId() {
  let id;

  do {
    id = String(10000000 + crypto.randomInt(90000000));
  } while (db.users.some(u => u.gamer_id === id));

  return id;
}

function getBet(body, res) {
  if (
    !Number.isSafeInteger(body.bet) ||
    body.bet < 100 ||
    body.bet > 1000000
  ) {
    error(res, 400, "Ставка должна быть от 100 до 1 000 000 UZS.");
    return null;
  }

  return body.bet;
}

function gameKey(user, name) {
  return `${user.id}:${name}`;
}

function receiptPath(dataUrl) {
  if (
    typeof dataUrl !== "string" ||
    dataUrl.length > 5 * 1024 * 1024
  ) {
    throw new Error("Прикрепите чек размером до 4 МБ.");
  }

  const match = dataUrl.match(
    /^data:image\/(png|jpeg|jpg|webp);base64,([A-Za-z0-9+/=]+)$/
  );

  if (!match) {
    throw new Error("Чек должен быть изображением PNG, JPG или WEBP.");
  }

  const extension = match[1] === "jpeg" ? "jpg" : match[1];
  const bytes = Buffer.from(match[2], "base64");

  if (!bytes.length || bytes.length > 4 * 1024 * 1024) {
    throw new Error("Размер изображения превышает 4 МБ.");
  }

  const name = crypto.randomBytes(16).toString("hex") + "." + extension;

  fs.writeFileSync(path.join(RECEIPTS_DIR, name), bytes, {
    flag: "wx"
  });

  return name;
}

function safeTopup(request) {
  const result = { ...request };

  delete result.receipt_file;

  if (request.receipt_file) {
    result.receipt_url =
      `/api/admin/receipts/${encodeURIComponent(request.receipt_file)}`;
  }

  return result;
}

function cardInfo() {
  return {
    bank: "NBU HUMO",
    cardNumber: "9860 1266 3574 3415",
    cardholder: "Xakimova Sh."
  };
}

function transaction(user, type, amount) {
  user.balance += amount;

  db.transactions.push({
    id: db.nextTransactionId++,
    user_id: user.id,
    type,
    amount,
    balance_after: user.balance,
    created_at: new Date().toISOString()
  });

  saveDatabase();
}

async function api(req, res, url) {
  const route = url.pathname;
  const method = req.method;
  const session = sessionUser(req);
  const user = session?.user || null;

  let body = {};

  if (method === "POST") {
    try {
      body = await readBody(req);
    } catch (e) {
      return error(res, 400, e.message);
    }
  }

  // Регистрация
  if (route === "/api/register" && method === "POST") {
    const username = String(body.username || "").trim();
    const password = String(body.password || "");

    if (!/^[a-zA-Z0-9_]{3,24}$/.test(username)) {
      return error(res, 400, "Логин: от 3 до 24 символов.");
    }

    if (password.length < 8 || password.length > 128) {
      return error(res, 400, "Пароль должен содержать 8–128 символов.");
    }

    if (username.toLowerCase() === ADMIN_USERNAME.toLowerCase()) {
      return error(res, 400, "Этот логин зарезервирован.");
    }

    if (db.users.some(u => u.username.toLowerCase() === username.toLowerCase())) {
      return error(res, 409, "Такой логин уже существует.");
    }

    const credentials = hashPassword(password);

    const newUser = {
      id: db.nextUserId++,
      username,
      gamer_id: gamerId(),
      balance: 0,
      salt: credentials.salt,
      password_hash: credentials.hash,
      created_at: new Date().toISOString()
    };

    db.users.push(newUser);
    saveDatabase();
    setSession(res, newUser);

    return json(res, 201, { user: publicUser(newUser) });
  }

  // Вход
  if (route === "/api/login" && method === "POST") {
    const username = String(body.username || "").trim();
    const password = String(body.password || "");

    let found = db.users.find(
      u => u.username.toLowerCase() === username.toLowerCase()
    );

    if (
      !found &&
      username.toLowerCase() === ADMIN_USERNAME.toLowerCase() &&
      password === ADMIN_PASSWORD
    ) {
      const credentials = hashPassword(password);

      found = {
        id: db.nextUserId++,
        username: ADMIN_USERNAME,
        gamer_id: gamerId(),
        balance: 0,
        salt: credentials.salt,
        password_hash: credentials.hash,
        created_at: new Date().toISOString()
      };

      db.users.push(found);
      saveDatabase();
    }

    if (!found || !verifyPassword(password, found)) {
      return error(res, 401, "Неверный логин или пароль.");
    }

    setSession(res, found);

    return json(res, 200, { user: publicUser(found) });
  }

  if (route === "/api/logout" && method === "POST") {
    clearSession(req, res);
    return json(res, 200, { ok: true });
  }

  if (route === "/api/me" && method === "GET") {
    if (!user) return error(res, 401, "Войдите в аккаунт.");
    return json(res, 200, { user: publicUser(user) });
  }

  if (route === "/api/history" && method === "GET") {
    if (!user) return error(res, 401, "Войдите в аккаунт.");

    return json(res, 200, {
      history: db.transactions
        .filter(t => t.user_id === user.id)
        .slice(-100)
        .reverse()
    });
  }

  // Создать заявку на пополнение с чеком
  if (route === "/api/topup-requests" && method === "POST") {
    if (!user) return error(res, 401, "Войдите в аккаунт.");

    if (
      !Number.isSafeInteger(body.amount) ||
      body.amount < 1000 ||
      body.amount > 10000000 ||
      body.amount % 1000 !== 0
    ) {
      return error(res, 400, "Сумма должна быть от 1 000 до 10 000 000 UZS.");
    }

    let file;

    try {
      file = receiptPath(body.receiptData);
    } catch (e) {
      return error(res, 400, e.message);
    }

    const request = {
      id: db.nextRequestId++,
      user_id: user.id,
      amount: body.amount,
      status: "pending",
      receipt_file: file,
      created_at: new Date().toISOString()
    };

    db.topupRequests.push(request);
    saveDatabase();

    return json(res, 201, {
      request: safeTopup(request),
      card: cardInfo()
    });
  }

  if (route === "/api/my-topup-requests" && method === "GET") {
    if (!user) return error(res, 401, "Войдите в аккаунт.");

    return json(res, 200, {
      requests: db.topupRequests
        .filter(r => r.user_id === user.id)
        .slice()
        .reverse()
        .map(safeTopup)
    });
  }

  // Создать заявку на вывод. Средства резервируются до решения администратора.
  if (route === "/api/withdrawal-requests" && method === "POST") {
    if (!user) return error(res, 401, "Войдите в аккаунт.");

    const amount = body.amount;
    const methodName = String(body.method || "").trim().slice(0, 40);
    const recipient = String(body.recipient || "").trim().slice(0, 120);

    if (
      !Number.isSafeInteger(amount) ||
      amount < 1000 ||
      amount > 10000000 ||
      amount % 1000 !== 0
    ) {
      return error(res, 400, "Сумма должна быть от 1 000 до 10 000 000 UZS.");
    }

    if (methodName.length < 2 || recipient.length < 4) {
      return error(res, 400, "Заполните способ вывода и реквизиты.");
    }

    if (user.balance < amount) {
      return error(res, 400, "Недостаточно виртуальных средств.");
    }

    user.balance -= amount;

    const request = {
      id: db.nextWithdrawalId++,
      user_id: user.id,
      amount,
      method: methodName,
      recipient,
      status: "pending",
      created_at: new Date().toISOString()
    };

    db.withdrawalRequests.push(request);

    db.transactions.push({
      id: db.nextTransactionId++,
      user_id: user.id,
      type: "withdrawal_pending",
      amount: -amount,
      balance_after: user.balance,
      created_at: new Date().toISOString()
    });

    saveDatabase();

    return json(res, 201, {
      request,
      user: publicUser(user)
    });
  }

  if (route === "/api/my-withdrawal-requests" && method === "GET") {
    if (!user) return error(res, 401, "Войдите в аккаунт.");

    return json(res, 200, {
      requests: db.withdrawalRequests
        .filter(r => r.user_id === user.id)
        .slice()
        .reverse()
    });
  }

  // Администратор
  if (route.startsWith("/api/admin/")) {
    if (!user) return error(res, 401, "Войдите в аккаунт.");
    if (!requireAdmin(user, res)) return;

    if (route === "/api/admin/me" && method === "GET") {
      return json(res, 200, { admin: true });
    }

    if (route === "/api/admin/users" && method === "GET") {
      return json(res, 200, { users: db.users.map(publicUser) });
    }

    if (route === "/api/admin/topup-requests" && method === "GET") {
      return json(res, 200, {
        requests: db.topupRequests.slice().reverse().map(r => {
          const owner = db.users.find(u => u.id === r.user_id);

          return {
            ...safeTopup(r),
            username: owner?.username || "Неизвестный",
            gamer_id: owner?.gamer_id || "—"
          };
        })
      });
    }

    if (route.startsWith("/api/admin/receipts/") && method === "GET") {
      const name = path.basename(route.slice("/api/admin/receipts/".length));

      if (!/^[a-f0-9]{32}\.(png|jpg|webp)$/.test(name)) {
        return error(res, 400, "Неверный файл.");
      }

      if (!db.topupRequests.some(r => r.receipt_file === name)) {
        return error(res, 404, "Чек не найден.");
      }

      const file = path.join(RECEIPTS_DIR, name);

      return fs.readFile(file, (e, bytes) => {
        if (e) return error(res, 404, "Файл чека не найден.");

        const ext = path.extname(name);
        const type = ext === ".png"
          ? "image/png"
          : ext === ".webp"
            ? "image/webp"
            : "image/jpeg";

        res.writeHead(200, {
          "Content-Type": type,
          "Cache-Control": "no-store",
          "X-Content-Type-Options": "nosniff"
        });

        res.end(bytes);
      });
    }

    const topupMatch = route.match(
      /^\/api\/admin\/topup-requests\/(\d+)\/(approve|reject)$/
    );

    if (topupMatch && method === "POST") {
      const request = db.topupRequests.find(
        r => r.id === Number(topupMatch[1])
      );

      if (!request) return error(res, 404, "Заявка не найдена.");
      if (request.status !== "pending") {
        return error(res, 409, "Заявка уже обработана.");
      }

      const owner = db.users.find(u => u.id === request.user_id);

      if (!owner) return error(res, 404, "Игрок не найден.");

      request.status = topupMatch[2] === "approve"
        ? "approved"
        : "rejected";

      request.reviewed_at = new Date().toISOString();

      if (request.status === "approved") {
        transaction(owner, "topup", request.amount);
      } else {
        saveDatabase();
      }

      return json(res, 200, {
        ok: true,
        request: safeTopup(request)
      });
    }

    if (route === "/api/admin/withdrawal-requests" && method === "GET") {
      return json(res, 200, {
        requests: db.withdrawalRequests.slice().reverse().map(r => {
          const owner = db.users.find(u => u.id === r.user_id);

          return {
            ...r,
            username: owner?.username || "Неизвестный",
            gamer_id: owner?.gamer_id || "—"
          };
        })
      });
    }

    const withdrawalMatch = route.match(
      /^\/api\/admin\/withdrawal-requests\/(\d+)\/(approve|reject)$/
    );

    if (withdrawalMatch && method === "POST") {
      const request = db.withdrawalRequests.find(
        r => r.id === Number(withdrawalMatch[1])
      );

      if (!request) return error(res, 404, "Заявка не найдена.");
      if (request.status !== "pending") {
        return error(res, 409, "Заявка уже обработана.");
      }

      const owner = db.users.find(u => u.id === request.user_id);

      if (!owner) return error(res, 404, "Игрок не найден.");

      request.status = withdrawalMatch[2] === "approve"
        ? "approved"
        : "rejected";

      request.reviewed_at = new Date().toISOString();

      if (request.status === "rejected") {
        transaction(owner, "withdrawal_refund", request.amount);
      } else {
        saveDatabase();
      }

      return json(res, 200, {
        ok: true,
        request,
        user: publicUser(owner)
      });
    }
  }

  // Простые демо-игры
  if (route === "/api/demo-play" && method === "POST") {
    if (!user) return error(res, 401, "Войдите в аккаунт.");

    const game = String(body.game || "");

    if (!["luck", "coin", "challenge"].includes(game)) {
      return error(res, 400, "Неизвестная игра.");
    }

    const bet = getBet(body, res);
    if (bet === null) return;

    if (user.balance < bet) {
      return error(res, 400, "Недостаточно виртуальных средств.");
    }

    user.balance -= bet;

    const win = crypto.randomInt(100) < (
      game === "luck" ? 45 : game === "coin" ? 50 : 33
    );

    const multiplier = game === "challenge" ? 3 : 2;
    const payout = win ? bet * multiplier : 0;

    transaction(user, game + (win ? "_win" : "_loss"), payout);

    return json(res, 200, {
      result: win ? "Вы выиграли!" : "В этот раз не повезло.",
      payout,
      balance: user.balance
    });
  }

  return error(res, 404, "Маршрут не найден.");
}

const MIME = {
  ".html": "text/html; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".js": "application/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".png": "image/png",
  ".jpg": "image/jpeg",
  ".jpeg": "image/jpeg",
  ".webp": "image/webp",
  ".svg": "image/svg+xml",
  ".ico": "image/x-icon"
};

function staticFile(req, res, url) {
  let pathname;

  try {
    pathname = decodeURIComponent(url.pathname);
  } catch {
    return error(res, 400, "Неверный адрес.");
  }

  if (pathname === "/") pathname = "/index.html";

  const file = path.resolve(PUBLIC_DIR, "." + pathname);

  if (!file.startsWith(PUBLIC_DIR + path.sep)) {
    return error(res, 403, "Доступ запрещён.");
  }

  fs.readFile(file, (e, data) => {
    if (e) return error(res, 404, "Файл не найден.");

    res.writeHead(200, {
      "Content-Type": MIME[path.extname(file).toLowerCase()] ||
        "application/octet-stream",
      "X-Content-Type-Options": "nosniff",
      "X-Frame-Options": "DENY",
      "Referrer-Policy": "same-origin"
    });

    res.end(data);
  });
}

const server = http.createServer(async (req, res) => {
  let url;

  try {
    url = new URL(req.url, "http://" + (req.headers.host || "localhost"));
  } catch {
    return error(res, 400, "Неверный адрес.");
  }

  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "same-origin");

  try {
    if (url.pathname.startsWith("/api/")) {
      if (!["GET", "POST"].includes(req.method)) {
        res.setHeader("Allow", "GET, POST");
        return error(res, 405, "Метод не поддерживается.");
      }

      await api(req, res, url);
      return;
    }

    if (!["GET", "HEAD"].includes(req.method)) {
      res.setHeader("Allow", "GET, HEAD");
      return error(res, 405, "Метод не поддерживается.");
    }

    staticFile(req, res, url);
  } catch (e) {
    console.error("Ошибка сервера:", e);

    if (!res.headersSent) {
      error(res, 500, "Внутренняя ошибка сервера.");
    } else {
      res.end();
    }
  }
});

server.listen(PORT, "0.0.0.0", () => {
  console.log("DEPOSIT 2.0 запущен на порту " + PORT);
});
