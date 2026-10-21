"use strict";

const http = require("node:http");
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");

const PORT = Number(process.env.PORT) || 3000;
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || "black";
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "ChangeMe123!";
const SESSION_SECRET = process.env.SESSION_SECRET || "";

if (
  process.env.NODE_ENV === "production" &&
  SESSION_SECRET.length < 32
) {
  console.error(
    "ERROR: Set SESSION_SECRET to a random secret of at least 32 characters."
  );
  process.exit(1);
}

if (process.env.NODE_ENV === "production" &&
    ADMIN_PASSWORD === "ChangeMe123!") {
  console.error(
    "ERROR: Set a unique ADMIN_PASSWORD in Render environment variables."
  );
  process.exit(1);
}

const PUBLIC_DIR = path.join(__dirname, "public");
const DATA_DIR = process.env.DATA_DIR || __dirname;
const DATA_FILE = path.join(DATA_DIR, "data.json");

fs.mkdirSync(DATA_DIR, { recursive: true });

const sessions = new Map();
const activeGames = new Map();

function initialDatabase() {
  return {
    users: [],
    transactions: [],
    topupRequests: [],
    nextUserId: 1,
    nextTransactionId: 1,
    nextRequestId: 1
  };
}

function loadDatabase() {
  try {
    const db = JSON.parse(fs.readFileSync(DATA_FILE, "utf8"));

    if (!Array.isArray(db.users) ||
        !Array.isArray(db.transactions) ||
        !Array.isArray(db.topupRequests)) {
      throw new Error("Invalid database format");
    }

    db.nextUserId ||= 1;
    db.nextTransactionId ||= 1;
    db.nextRequestId ||= 1;

    return db;
  } catch (error) {
    if (error.code !== "ENOENT") {
      console.error("Could not read database:", error.message);
      process.exit(1);
    }

    const db = initialDatabase();
    fs.writeFileSync(DATA_FILE, JSON.stringify(db, null, 2));
    return db;
  }
}

const db = loadDatabase();

function saveDatabase() {
  const temporaryFile = DATA_FILE + ".tmp";
  fs.writeFileSync(temporaryFile, JSON.stringify(db, null, 2));
  fs.renameSync(temporaryFile, DATA_FILE);
}

function makeId() {
  return crypto.randomBytes(32).toString("hex");
}

function makeGamerId() {
  let id;

  do {
    id = String(10000000 + crypto.randomInt(90000000));
  } while (db.users.some(user => user.gamer_id === id));

  return id;
}

function hashPassword(password, salt = crypto.randomBytes(16).toString("hex")) {
  const hash = crypto.scryptSync(password, salt, 64).toString("hex");
  return { salt, hash };
}

function checkPassword(password, user) {
  const actual = crypto.scryptSync(password, user.salt, 64);
  const expected = Buffer.from(user.password_hash, "hex");

  return expected.length === actual.length &&
    crypto.timingSafeEqual(actual, expected);
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

function getSession(req) {
  const cookie = req.headers.cookie || "";
  const match = cookie.match(/(?:^|;\s*)sid=([a-f0-9]{64})(?:;|$)/);

  if (!match) return null;

  const session = sessions.get(match[1]);

  if (!session) return null;

  const user = db.users.find(item => item.id === session.userId);

  if (!user) return null;

  return { token: match[1], user };
}

function setSession(res, user) {
  const token = makeId();

  sessions.set(token, { userId: user.id });

  const secure = process.env.NODE_ENV === "production"
    ? "; Secure"
    : "";

  res.setHeader(
    "Set-Cookie",
    `sid=${token}; HttpOnly; SameSite=Lax; Path=/; Max-Age=86400${secure}`
  );
}

function clearSession(req, res) {
  const session = getSession(req);

  if (session) {
    sessions.delete(session.token);
  }

  const secure = process.env.NODE_ENV === "production"
    ? "; Secure"
    : "";

  res.setHeader(
    "Set-Cookie",
    `sid=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0${secure}`
  );
}

function sendJson(res, status, data) {
  res.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff"
  });

  res.end(JSON.stringify(data));
}

function fail(res, status, message) {
  sendJson(res, status, { error: message });
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let body = "";
    let size = 0;

    req.on("data", chunk => {
      size += chunk.length;

      if (size > 20000) {
        reject(new Error("Слишком большой запрос"));
        req.destroy();
        return;
      }

      body += chunk;
    });

    req.on("end", () => {
      if (!body) {
        resolve({});
        return;
      }

      try {
        const parsed = JSON.parse(body);

        if (!parsed || typeof parsed !== "object" ||
            Array.isArray(parsed)) {
          reject(new Error("Неверный формат данных"));
          return;
        }

        resolve(parsed);
      } catch {
        reject(new Error("Некорректный JSON"));
      }
    });

    req.on("error", reject);
  });
}

function requireUser(session, res) {
  if (!session) {
    fail(res, 401, "Сначала войдите в аккаунт");
    return null;
  }

  return session.user;
}

function requireAdmin(user, res) {
  if (!user || !isAdmin(user)) {
    fail(res, 403, "Доступ разрешён только администратору");
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

function validBet(value) {
  return Number.isSafeInteger(value) &&
    value >= 100 &&
    value <= 1000000;
}

function getBet(body, res) {
  const bet = body.bet;

  if (!validBet(bet)) {
    fail(res, 400, "Ставка должна быть от 100 до 1 000 000 UZS");
    return null;
  }

  return bet;
}

function debit(user, bet, res) {
  if (user.balance < bet) {
    fail(res, 400, "Недостаточно виртуальных средств");
    return false;
  }

  user.balance -= bet;
  return true;
}

function finishGame(user, type, payout) {
  payout = Math.max(0, Math.floor(payout));

  user.balance += payout;

  addTransaction(user, type, payout);

  return payout;
}

function gameKey(user, game) {
  return `${user.id}:${game}`;
}

function activeGame(user, game) {
  return activeGames.get(gameKey(user, game));
}

function randomCard() {
  const ranks = [
    "2", "3", "4", "5", "6", "7", "8", "9", "10",
    "J", "Q", "K", "A"
  ];

  const suits = ["♠", "♥", "♦", "♣"];

  return {
    rank: ranks[crypto.randomInt(ranks.length)],
    suit: suits[crypto.randomInt(suits.length)]
  };
}

function cardValue(card) {
  if (["J", "Q", "K"].includes(card.rank)) return 10;
  if (card.rank === "A") return 11;
  return Number(card.rank);
}

function handValue(cards) {
  let total = cards.reduce((sum, card) => sum + cardValue(card), 0);
  let aces = cards.filter(card => card.rank === "A").length;

  while (total > 21 && aces > 0) {
    total -= 10;
    aces--;
  }

  return total;
}

function publicBlackjack(game, finished = false, result = null, payout = 0) {
  return {
    player: game.player,
    playerValue: handValue(game.player),
    dealer: finished ? game.dealer : [game.dealer[0]],
    dealerValue: finished ? handValue(game.dealer) : null,
    finished,
    result,
    payout
  };
}

function finishBlackjack(user, game, result, payout) {
  activeGames.delete(gameKey(user, "blackjack"));

  payout = finishGame(user, "blackjack", payout);

  return {
    ...publicBlackjack(game, true, result, payout),
    result,
    payout
  };
}

async function handleApi(req, res, url) {
  const route = url.pathname;
  const method = req.method;
  const session = getSession(req);

  let body = {};

  if (["POST", "PUT", "PATCH"].includes(method)) {
    try {
      body = await readBody(req);
    } catch (error) {
      return fail(res, 400, error.message);
    }
  }

  // Регистрация
  if (route === "/api/register" && method === "POST") {
    const username = String(body.username || "").trim();
    const password = String(body.password || "");

    if (!/^[a-zA-Z0-9_]{3,24}$/.test(username)) {
      return fail(res, 400,
        "Логин: от 3 до 24 символов, латинские буквы, цифры и _");
    }

    if (password.length < 8 || password.length > 128) {
      return fail(res, 400, "Пароль должен содержать от 8 до 128 символов");
    }

    if (username.toLowerCase() === ADMIN_USERNAME.toLowerCase()) {
      return fail(res, 400, "Этот логин зарезервирован");
    }

    if (db.users.some(u =>
      u.username.toLowerCase() === username.toLowerCase())) {
      return fail(res, 409, "Такой логин уже существует");
    }

    const credentials = hashPassword(password);

    const user = {
      id: db.nextUserId++,
      username,
      gamer_id: makeGamerId(),
      balance: 0,
      salt: credentials.salt,
      password_hash: credentials.hash,
      created_at: new Date().toISOString()
    };

    db.users.push(user);
    saveDatabase();
    setSession(res, user);

    return sendJson(res, 201, { user: publicUser(user) });
  }

  // Вход
  if (route === "/api/login" && method === "POST") {
    const username = String(body.username || "").trim();
    const password = String(body.password || "");

    if (username.length > 24 || password.length > 128) {
      return fail(res, 400, "Неверный логин или пароль");
    }

    let user = db.users.find(u =>
      u.username.toLowerCase() === username.toLowerCase());

    // Учётная запись администратора создаётся при первом входе.
    if (!user &&
        username.toLowerCase() === ADMIN_USERNAME.toLowerCase() &&
        password === ADMIN_PASSWORD) {
      const credentials = hashPassword(password);

      user = {
        id: db.nextUserId++,
        username: ADMIN_USERNAME,
        gamer_id: makeGamerId(),
        balance: 0,
        salt: credentials.salt,
        password_hash: credentials.hash,
        created_at: new Date().toISOString()
      };

      db.users.push(user);
      saveDatabase();
    }

    if (!user || !checkPassword(password, user)) {
      return fail(res, 401, "Неверный логин или пароль");
    }

    setSession(res, user);

    return sendJson(res, 200, { user: publicUser(user) });
  }

  // Выход
  if (route === "/api/logout" && method === "POST") {
    clearSession(req, res);
    return sendJson(res, 200, { ok: true });
  }

  // Текущий пользователь
  if (route === "/api/me" && method === "GET") {
    const user = requireUser(session, res);
    if (!user) return;

    return sendJson(res, 200, { user: publicUser(user) });
  }

  // История операций
  if (route === "/api/history" && method === "GET") {
    const user = requireUser(session, res);
    if (!user) return;

    const history = db.transactions
      .filter(t => t.user_id === user.id)
      .slice(-100)
      .reverse();

    return sendJson(res, 200, { history });
  }

  // Создание тестовой заявки
  if (route === "/api/topup-requests" && method === "POST") {
    const user = requireUser(session, res);
    if (!user) return;

    if (!Number.isSafeInteger(body.amount) ||
        body.amount < 1000 ||
        body.amount > 10000000 ||
        body.amount % 1000 !== 0) {
      return fail(res, 400, "Укажите сумму от 1 000 до 10 000 000 UZS");
    }

    const request = {
      id: db.nextRequestId++,
      user_id: user.id,
      amount: body.amount,
      status: "pending",
      created_at: new Date().toISOString()
    };

    db.topupRequests.push(request);
    saveDatabase();

    return sendJson(res, 201, { request });
  }

  // Список заявок игрока
  if (route === "/api/my-topup-requests" && method === "GET") {
    const user = requireUser(session, res);
    if (!user) return;

    const requests = db.topupRequests
      .filter(r => r.user_id === user.id)
      .slice()
      .reverse();

    return sendJson(res, 200, { requests });
  }

  // Администратор
  if (route === "/api/admin/me" && method === "GET") {
    const user = requireUser(session, res);
    if (!user) return;

    if (!requireAdmin(user, res)) return;

    return sendJson(res, 200, { admin: true });
  }

  if (route === "/api/admin/users" && method === "GET") {
    const user = requireUser(session, res);
    if (!user) return;

    if (!requireAdmin(user, res)) return;

    return sendJson(res, 200, {
      users: db.users.map(publicUser)
    });
  }

  if (route === "/api/admin/topup-requests" && method === "GET") {
    const user = requireUser(session, res);
    if (!user) return;

    if (!requireAdmin(user, res)) return;

    const requests = db.topupRequests
      .slice()
      .reverse()
      .map(request => {
        const owner = db.users.find(u => u.id === request.user_id);

        return {
          ...request,
          username: owner ? owner.username : "Неизвестный",
          gamer_id: owner ? owner.gamer_id : "—"
        };
      });

    return sendJson(res, 200, { requests });
  }

  const reviewMatch = route.match(
    /^\/api\/admin\/topup-requests\/(\d+)\/(approve|reject)$/
  );

  if (reviewMatch && method === "POST") {
    const user = requireUser(session, res);
    if (!user) return;

    if (!requireAdmin(user, res)) return;

    const request = db.topupRequests.find(
      r => r.id === Number(reviewMatch[1])
    );

    if (!request) {
      return fail(res, 404, "Заявка не найдена");
    }

    if (request.status !== "pending") {
      return fail(res, 409, "Заявка уже обработана");
    }

    const owner = db.users.find(u => u.id === request.user_id);

    if (!owner) {
      return fail(res, 404, "Игрок не найден");
    }

    if (reviewMatch[2] === "approve") {
      request.status = "approved";
      owner.balance += request.amount;
      addTransaction(owner, "test_topup", request.amount);
    } else {
      request.status = "rejected";
      saveDatabase();
    }

    return sendJson(res, 200, {
      ok: true,
      request
    });
  }

  // Три простые демо-игры
  if (route === "/api/demo-play" && method === "POST") {
    const user = requireUser(session, res);
    if (!user) return;

    const game = String(body.game || "");
    const allowed = ["luck", "coin", "challenge"];

    if (!allowed.includes(game)) {
      return fail(res, 400, "Неизвестная игра");
    }

    const bet = getBet(body, res);
    if (bet === null) return;

    if (!debit(user, bet, res)) return;

    let win = false;
    let multiplier = 2;

    if (game === "luck") {
      win = crypto.randomInt(100) < 45;
    } else if (game === "coin") {
      win = crypto.randomInt(2) === 0;
    } else {
      win = crypto.randomInt(3) === 0;
      multiplier = 3;
    }

    const payout = finishGame(user, game, win ? bet * multiplier : 0);

    return sendJson(res, 200, {
      result: win ? "Вы выиграли!" : "В этот раз не повезло.",
      payout,
      balance: user.balance
    });
  }

  // Apple of Fortune: виртуальная игра
  if (route === "/api/games/apple/start" && method === "POST") {
    const user = requireUser(session, res);
    if (!user) return;

    if (activeGame(user, "apple")) {
      return fail(res, 409, "Завершите текущую игру");
    }

    const bet = getBet(body, res);
    if (bet === null) return;

    if (!debit(user, bet, res)) return;

    const trap = crypto.randomInt(3);

    activeGames.set(gameKey(user, "apple"), {
      bet,
      trap,
      step: 0,
      multiplier: 1.5
    });

    saveDatabase();

    return sendJson(res, 200, { ok: true });
  }

  if (route === "/api/games/apple/pick" && method === "POST") {
    const user = requireUser(session, res);
    if (!user) return;

    const game = activeGame(user, "apple");
    if (!game) return fail(res, 400, "Сначала начните игру");

    if (![0, 1, 2].includes(body.choice)) {
      return fail(res, 400, "Выберите одно из трёх яблок");
    }

    if (body.choice === game.trap) {
      activeGames.delete(gameKey(user, "apple"));

      finishGame(user, "apple_loss", 0);

      return sendJson(res, 200, {
        lost: true,
        message: "Ловушка! Виртуальная ставка потеряна."
      });
    }

    game.step++;
    game.multiplier = Math.pow(1.5, game.step + 1);

    return sendJson(res, 200, {
      lost: false,
      game: {
        step: game.step,
        multiplier: Number(game.multiplier.toFixed(2))
      }
    });
  }

  if (route === "/api/games/apple/cashout" && method === "POST") {
    const user = requireUser(session, res);
    if (!user) return;

    const game = activeGame(user, "apple");
    if (!game || game.step < 1) {
      return fail(res, 400, "Сначала успешно выберите яблоко");
    }

    activeGames.delete(gameKey(user, "apple"));

    const payout = finishGame(
      user,
      "apple_win",
      Math.floor(game.bet * game.multiplier)
    );

    return sendJson(res, 200, {
      payout,
      multiplier: Number(game.multiplier.toFixed(2))
    });
  }

  // Aviator: виртуальный раунд
  if (route === "/api/games/aviator/start" && method === "POST") {
    const user = requireUser(session, res);
    if (!user) return;

    if (activeGame(user, "aviator")) {
      return fail(res, 409, "Завершите текущий раунд");
    }

    const bet = getBet(body, res);
    if (bet === null) return;

    if (!debit(user, bet, res)) return;

    activeGames.set(gameKey(user, "aviator"), {
      bet,
      started: Date.now(),
      crashAt: 1.2 + crypto.randomInt(280) / 100
    });

    saveDatabase();

    return sendJson(res, 200, { ok: true });
  }

  if (route === "/api/games/aviator/state" && method === "GET") {
    const user = requireUser(session, res);
    if (!user) return;

    const game = activeGame(user, "aviator");
    if (!game) return fail(res, 400, "Активный полёт не найден");

    const elapsed = (Date.now() - game.started) / 1000;
    const multiplier = Math.exp(elapsed * 0.12);
    const crashed = multiplier >= game.crashAt;

    if (crashed) {
      activeGames.delete(gameKey(user, "aviator"));
      finishGame(user, "aviator_loss", 0);
    }

    return sendJson(res, 200, {
      crashed,
      multiplier: Number(
        Math.min(multiplier, game.crashAt).toFixed(2)
      )
    });
  }

  if (route === "/api/games/aviator/cashout" && method === "POST") {
    const user = requireUser(session, res);
    if (!user) return;

    const game = activeGame(user, "aviator");
    if (!game) return fail(res, 400, "Активный полёт не найден");

    const multiplier = Math.exp((Date.now() - game.started) / 1000 * 0.12);

    activeGames.delete(gameKey(user, "aviator"));

    if (multiplier >= game.crashAt) {
      finishGame(user, "aviator_loss", 0);

      return sendJson(res, 200, {
        crashed: true,
        multiplier: Number(game.crashAt.toFixed(2)),
        payout: 0
      });
    }

    const payout = finishGame(
      user,
      "aviator_win",
      Math.floor(game.bet * multiplier)
    );

    return sendJson(res, 200, {
      crashed: false,
      multiplier: Number(multiplier.toFixed(2)),
      payout
    });
  }

  // Blackjack
  if (route === "/api/games/blackjack/start" && method === "POST") {
    const user = requireUser(session, res);
    if (!user) return;

    if (activeGame(user, "blackjack")) {
      return fail(res, 409, "Завершите текущий раунд");
    }

    const bet = getBet(body, res);
    if (bet === null) return;

    if (!debit(user, bet, res)) return;

    const game = {
      bet,
      player: [randomCard(), randomCard()],
      dealer: [randomCard(), randomCard()]
    };

    activeGames.set(gameKey(user, "blackjack"), game);

    const playerScore = handValue(game.player);
    const dealerScore = handValue(game.dealer);

    if (playerScore === 21 || dealerScore === 21) {
      if (playerScore === dealerScore) {
        return sendJson(
          res,
          200,
          finishBlackjack(user, game, "Ничья!", bet)
        );
      }

      if (playerScore === 21) {
        return sendJson(
          res,
          200,
          finishBlackjack(user, game, "Blackjack! Вы выиграли!", bet * 2)
        );
      }

      return sendJson(
        res,
        200,
        finishBlackjack(user, game, "У дилера 21. Вы проиграли.", 0)
      );
    }

    return sendJson(res, 200, publicBlackjack(game));
  }

  const blackjackAction = route.match(
    /^\/api\/games\/blackjack\/(hit|stand)$/
  );

  if (blackjackAction && method === "POST") {
    const user = requireUser(session, res);
    if (!user) return;

    const game = activeGame(user, "blackjack");
    if (!game) return fail(res, 400, "Активный раунд не найден");

    if (blackjackAction[1] === "hit") {
      game.player.push(randomCard());

      if (handValue(game.player) > 21) {
        return sendJson(
          res,
          200,
          finishBlackjack(user, game, "Перебор! Вы проиграли.", 0)
        );
      }

      if (handValue(game.player) === 21) {
        while (handValue(game.dealer) < 17) {
          game.dealer.push(randomCard());
        }

        const p = handValue(game.player);
        const d = handValue(game.dealer);

        if (d > 21 || p > d) {
          return sendJson(
            res, 200, finishBlackjack(user, game, "Вы выиграли!", game.bet * 2)
          );
        }

        if (p === d) {
          return sendJson(
            res, 200, finishBlackjack(user, game, "Ничья!", game.bet)
          );
        }

        return sendJson(
          res, 200, finishBlackjack(user, game, "Дилер выиграл.", 0)
        );
      }

      return sendJson(res, 200, publicBlackjack(game));
    }

    while (handValue(game.dealer) < 17) {
      game.dealer.push(randomCard());
    }

    const playerScore = handValue(game.player);
    const dealerScore = handValue(game.dealer);

    if (dealerScore > 21 || playerScore > dealerScore) {
      return sendJson(
        res, 200, finishBlackjack(user, game, "Вы выиграли!", game.bet * 2)
      );
    }

    if (playerScore === dealerScore) {
      return sendJson(
        res, 200, finishBlackjack(user, game, "Ничья!", game.bet)
      );
    }

    return sendJson(
      res, 200, finishBlackjack(user, game, "Дилер выиграл.", 0)
    );
  }

  return fail(res, 404, "Маршрут не найден");
}

const MIME_TYPES = {
  ".html": "text/html; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".js": "application/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".png": "image/png",
  ".jpg": "image/jpeg",
  ".svg": "image/svg+xml",
  ".ico": "image/x-icon"
};

function serveStatic(req, res, url) {
  let pathname;

  try {
    pathname = decodeURIComponent(url.pathname);
  } catch {
    return fail(res, 400, "Неверный адрес");
  }

  if (pathname === "/") {
    pathname = "/index.html";
  }

  const filename = path.resolve(PUBLIC_DIR, "." + pathname);

  if (!filename.startsWith(PUBLIC_DIR + path.sep)) {
    return fail(res, 403, "Доступ запрещён");
  }

  fs.readFile(filename, (error, content) => {
    if (error) {
      return fail(res, 404, "Файл не найден");
    }

    res.writeHead(200, {
      "Content-Type":
        MIME_TYPES[path.extname(filename).toLowerCase()] ||
        "application/octet-stream",
      "X-Content-Type-Options": "nosniff",
      "X-Frame-Options": "DENY",
      "Referrer-Policy": "same-origin"
    });

    res.end(content);
  });
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host || "localhost"}`);

  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "same-origin");

  try {
    if (url.pathname.startsWith("/api/")) {
      if (!["GET", "POST"].includes(req.method)) {
        res.setHeader("Allow", "GET, POST");
        return fail(res, 405, "Метод не поддерживается");
      }

      await handleApi(req, res, url);
      return;
    }

    if (req.method !== "GET" && req.method !== "HEAD") {
      res.setHeader("Allow", "GET, HEAD");
      return fail(res, 405, "Метод не поддерживается");
    }

    serveStatic(req, res, url);
  } catch (error) {
    console.error("Request error:", error);

    if (!res.headersSent) {
      fail(res, 500, "Внутренняя ошибка сервера");
    } else {
      res.end();
    }
  }
});

server.listen(PORT, "0.0.0.0", () => {
  console.log(`DEPOSIT 2.0 server started on port ${PORT}`);
  console.log(`Admin username: ${ADMIN_USERNAME}`);
});
