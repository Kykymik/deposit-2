'use strict';

const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = Number(process.env.PORT || 3000);
const HOST = '0.0.0.0';
const DATA_DIR = process.env.DATA_DIR || __dirname;
const PUBLIC_DIR = path.join(__dirname, 'public');
const RECEIPTS_DIR = path.join(DATA_DIR, 'receipts');
const DATA_FILE = path.join(DATA_DIR, 'data.json');

const ADMIN_USERNAME = process.env.ADMIN_USERNAME || 'black';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || '';
const SESSION_SECRET = process.env.SESSION_SECRET || '';

if (process.env.NODE_ENV === 'production') {
  if (ADMIN_PASSWORD.length < 12) {
    throw new Error('Set ADMIN_PASSWORD to a strong password of at least 12 characters.');
  }

  if (SESSION_SECRET.length < 32) {
    throw new Error('Set SESSION_SECRET to a random secret of at least 32 characters.');
  }
}

fs.mkdirSync(DATA_DIR, { recursive: true });
fs.mkdirSync(RECEIPTS_DIR, { recursive: true });

function emptyDatabase() {
  return {
    users: [],
    topups: [],
    withdrawals: [],
    history: [],
    nextUserId: 1,
    nextTopupId: 1,
    nextWithdrawalId: 1,
    nextHistoryId: 1
  };
}

function loadDatabase() {
  try {
    if (fs.existsSync(DATA_FILE)) {
      const parsed = JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
      const defaults = emptyDatabase();

      return {
        ...defaults,
        ...parsed,
        users: Array.isArray(parsed.users) ? parsed.users : [],
        topups: Array.isArray(parsed.topups) ? parsed.topups : [],
        withdrawals: Array.isArray(parsed.withdrawals) ? parsed.withdrawals : [],
        history: Array.isArray(parsed.history) ? parsed.history : []
      };
    }
  } catch (error) {
    console.error('Database loading failed:', error.message);
    throw error;
  }

  return emptyDatabase();
}

let db = loadDatabase();

function saveDatabase() {
  const temporaryFile = DATA_FILE + '.tmp';
  fs.writeFileSync(temporaryFile, JSON.stringify(db, null, 2), 'utf8');
  fs.renameSync(temporaryFile, DATA_FILE);
}

const sessions = new Map();
const games = new Map();

const MIME_TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.webp': 'image/webp',
  '.ico': 'image/x-icon'
};

function now() {
  return new Date().toISOString();
}

function randomId(bytes = 24) {
  return crypto.randomBytes(bytes).toString('hex');
}

function hashPassword(password, salt = crypto.randomBytes(16).toString('hex')) {
  const hash = crypto.scryptSync(String(password), salt, 64).toString('hex');
  return { salt, hash };
}

function verifyPassword(password, salt, expectedHash) {
  try {
    const actual = crypto.scryptSync(String(password), salt, 64);
    const expected = Buffer.from(expectedHash, 'hex');

    return actual.length === expected.length &&
      crypto.timingSafeEqual(actual, expected);
  } catch {
    return false;
  }
}

function publicUser(user) {
  return {
    id: user.id,
    username: user.username,
    balance: user.balance,
    createdAt: user.createdAt
  };
}

function findUserById(id) {
  return db.users.find(user => user.id === Number(id));
}

function getCookie(req, name) {
  const header = req.headers.cookie || '';

  for (const item of header.split(';')) {
    const index = item.indexOf('=');
    if (index < 0) continue;

    const key = item.slice(0, index).trim();
    const value = item.slice(index + 1).trim();

    if (key === name) {
      try {
        return decodeURIComponent(value);
      } catch {
        return '';
      }
    }
  }

  return '';
}

function setSessionCookie(res, token) {
  const secure = process.env.NODE_ENV === 'production' ? '; Secure' : '';

  res.setHeader(
    'Set-Cookie',
    `sid=${encodeURIComponent(token)}; HttpOnly; SameSite=Lax; Path=/; Max-Age=604800${secure}`
  );
}

function clearSessionCookie(res) {
  const secure = process.env.NODE_ENV === 'production' ? '; Secure' : '';

  res.setHeader(
    'Set-Cookie',
    `sid=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0${secure}`
  );
}

function currentSession(req) {
  const token = getCookie(req, 'sid');
  if (!token) return null;

  const session = sessions.get(token);
  if (!session) return null;

  if (session.expiresAt < Date.now()) {
    sessions.delete(token);
    return null;
  }

  session.expiresAt = Date.now() + 7 * 24 * 60 * 60 * 1000;
  return session;
}

function requireUser(req, res) {
  const session = currentSession(req);

  if (!session || session.role !== 'user') {
    sendJson(res, 401, { ok: false, error: 'Требуется авторизация.' });
    return null;
  }

  const user = findUserById(session.userId);

  if (!user) {
    sendJson(res, 401, { ok: false, error: 'Пользователь не найден.' });
    return null;
  }

  return user;
}

function requireAdmin(req, res) {
  const session = currentSession(req);

  if (!session || session.role !== 'admin') {
    sendJson(res, 403, { ok: false, error: 'Доступ только для администратора.' });
    return null;
  }

  return session;
}

function sendJson(res, status, data) {
  if (res.writableEnded) return;

  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff'
  });

  res.end(JSON.stringify(data));
}

function addHistory(userId, type, amount, description, extra = {}) {
  const record = {
    id: db.nextHistoryId++,
    userId,
    type,
    amount: Math.round(Number(amount) || 0),
    description,
    createdAt: now(),
    ...extra
  };

  db.history.unshift(record);

  if (db.history.length > 20000) {
    db.history.length = 20000;
  }

  saveDatabase();
  return record;
}

function safeAmount(value, min = 1000, max = 10000000) {
  const amount = Number(value);

  if (!Number.isSafeInteger(amount)) return null;
  if (amount < min || amount > max) return null;
  if (amount % 1000 !== 0) return null;

  return amount;
}

function parseCookiesAndBody(req, res) {
  return new Promise(resolve => {
    let body = '';
    let tooLarge = false;

    req.on('data', chunk => {
      body += chunk.toString('utf8');

      if (body.length > 9 * 1024 * 1024) {
        tooLarge = true;
        req.destroy();
      }
    });

    req.on('end', () => {
      if (tooLarge) {
        if (!res.writableEnded) {
          sendJson(res, 413, { ok: false, error: 'Запрос слишком большой.' });
        }
        resolve(null);
        return;
      }

      if (!body) {
        resolve({});
        return;
      }

      try {
        resolve(JSON.parse(body));
      } catch {
        sendJson(res, 400, { ok: false, error: 'Некорректный JSON.' });
        resolve(null);
      }
    });

    req.on('error', () => resolve(null));
  });
}

function removeReceipt(filename) {
  if (!filename || path.basename(filename) !== filename) return;

  const file = path.join(RECEIPTS_DIR, filename);

  try {
    if (fs.existsSync(file)) fs.unlinkSync(file);
  } catch (error) {
    console.error('Receipt removal failed:', error.message);
  }
}

function saveReceipt(dataUrl) {
  if (typeof dataUrl !== 'string') {
    throw new Error('Прикрепите фотографию чека.');
  }

  const match = dataUrl.match(
    /^data:image\/(jpeg|jpg|png|webp);base64,([A-Za-z0-9+/=]+)$/
  );

  if (!match) {
    throw new Error('Поддерживаются только JPG, PNG и WEBP.');
  }

  const extension = match[1] === 'jpeg' ? 'jpg' : match[1];
  const buffer = Buffer.from(match[2], 'base64');

  if (!buffer.length || buffer.length > 5 * 1024 * 1024) {
    throw new Error('Размер чека не должен превышать 5 МБ.');
  }

  const filename = `${randomId(16)}.${extension}`;
  fs.writeFileSync(path.join(RECEIPTS_DIR, filename), buffer, { flag: 'wx' });

  return filename;
}

function topupForUser(item) {
  return {
    id: item.id,
    amount: item.amount,
    status: item.status,
    createdAt: item.createdAt,
    updatedAt: item.updatedAt
  };
}

function topupForAdmin(item) {
  const user = findUserById(item.userId);

  return {
    ...topupForUser(item),
    userId: item.userId,
    username: user ? user.username : 'Удалённый пользователь',
    receiptUrl: item.receiptFile
      ? `/api/admin/receipts/${encodeURIComponent(item.receiptFile)}`
      : null,
    adminComment: item.adminComment || ''
  };
}

function withdrawalForUser(item) {
  return {
    id: item.id,
    amount: item.amount,
    recipient: item.recipient,
    paymentDetails: item.paymentDetails,
    status: item.status,
    createdAt: item.createdAt,
    updatedAt: item.updatedAt,
    adminComment: item.adminComment || ''
  };
}

function withdrawalForAdmin(item) {
  const user = findUserById(item.userId);

  return {
    ...withdrawalForUser(item),
    userId: item.userId,
    username: user ? user.username : 'Удалённый пользователь'
  };
}

function getUserGame(userId, gameName) {
  return games.get(`${userId}:${gameName}`);
}

function setUserGame(userId, gameName, state) {
  games.set(`${userId}:${gameName}`, state);
}

function clearUserGame(userId, gameName) {
  games.delete(`${userId}:${gameName}`);
}

function secureRandomInt(min, max) {
  return crypto.randomInt(min, max + 1);
}

function appleMultiplier(row, column) {
  const risk = [
    [1.15, 1.35, 1.65, 2.1],
    [1.3, 1.7, 2.25, 3.2],
    [1.55, 2.2, 3.25, 5.5],
    [1.9, 3.0, 5.0, 9.0],
    [2.4, 4.0, 7.5, 15.0]
  ];

  return risk[row][column];
}

function startApple(user, body, res) {
  const bet = safeAmount(body.bet, 1000, 1000000);

  if (!bet || user.balance < bet) {
    return sendJson(res, 400, {
      ok: false,
      error: 'Некорректная ставка или недостаточно средств.'
    });
  }

  if (getUserGame(user.id, 'apple')) {
    return sendJson(res, 409, {
      ok: false,
      error: 'Сначала завершите текущую игру.'
    });
  }

  user.balance -= bet;

  const state = {
    bet,
    row: 0,
    picks: [],
    safeColumns: Array.from({ length: 5 }, () => secureRandomInt(0, 3)),
    status: 'playing',
    startedAt: now()
  };

  setUserGame(user.id, 'apple', state);
  addHistory(user.id, 'game_bet', -bet, 'Apple of Fortune: ставка');

  return sendJson(res, 200, {
    ok: true,
    bet,
    balance: user.balance,
    row: state.row,
    picks: state.picks
  });
}

function pickApple(user, body, res) {
  const state = getUserGame(user.id, 'apple');

  if (!state || state.status !== 'playing') {
    return sendJson(res, 400, { ok: false, error: 'Нет активной игры.' });
  }

  const column = Number(body.column);

  if (!Number.isInteger(column) || column < 0 || column > 3) {
    return sendJson(res, 400, { ok: false, error: 'Неверная ячейка.' });
  }

  if (state.row >= 5) {
    return sendJson(res, 400, { ok: false, error: 'Все ряды открыты.' });
  }

  const correct = state.safeColumns[state.row] === column;
  state.picks.push({ row: state.row, column, correct });

  if (!correct) {
    state.status = 'lost';
    clearUserGame(user.id, 'apple');

    addHistory(user.id, 'game_loss', 0, 'Apple of Fortune: проигрыш');

    return sendJson(res, 200, {
      ok: true,
      correct: false,
      finished: true,
      payout: 0,
      balance: user.balance
    });
  }

  state.row++;

  const multiplier = state.row === 0
    ? 1
    : appleMultiplier(Math.min(state.row - 1, 4), Math.min(column, 3));

  const nextMultiplier = state.row >= 5
    ? null
    : appleMultiplier(state.row, 0);

  setUserGame(user.id, 'apple', state);

  return sendJson(res, 200, {
    ok: true,
    correct: true,
    finished: false,
    row: state.row,
    picks: state.picks,
    multiplier,
    nextMultiplier,
    potentialPayout: Math.floor(state.bet * multiplier),
    balance: user.balance
  });
}

function cashoutApple(user, res) {
  const state = getUserGame(user.id, 'apple');

  if (!state || state.status !== 'playing' || state.row < 1) {
    return sendJson(res, 400, {
      ok: false,
      error: 'Нужно сначала открыть безопасную ячейку.'
    });
  }

  const multiplier = state.row >= 5
    ? 15
    : appleMultiplier(Math.min(state.row - 1, 4), 0);

  const payout = Math.floor(state.bet * multiplier);

  user.balance += payout;
  clearUserGame(user.id, 'apple');

  addHistory(
    user.id,
    'game_win',
    payout,
    `Apple of Fortune: выплата x${multiplier}`
  );

  return sendJson(res, 200, {
    ok: true,
    payout,
    multiplier,
    balance: user.balance
  });
}

function startAviator(user, body, res) {
  const bet = safeAmount(body.bet, 1000, 1000000);

  if (!bet || user.balance < bet) {
    return sendJson(res, 400, {
      ok: false,
      error: 'Некорректная ставка или недостаточно средств.'
    });
  }

  if (getUserGame(user.id, 'aviator')) {
    return sendJson(res, 409, {
      ok: false,
      error: 'Сначала завершите текущую игру.'
    });
  }

  user.balance -= bet;

  const crashMultiplier = Math.max(
    1,
    Math.floor((1 / Math.max(0.0001, Math.random())) * 100) / 100
  );

  const state = {
    bet,
    multiplier: 1,
    crashMultiplier: Math.min(crashMultiplier, 100),
    status: 'flying',
    startedAt: Date.now()
  };

  setUserGame(user.id, 'aviator', state);
  addHistory(user.id, 'game_bet', -bet, 'Aviator: ставка');

  return sendJson(res, 200, {
    ok: true,
    bet,
    balance: user.balance,
    multiplier: 1,
    status: 'flying'
  });
}

function updateAviator(state) {
  if (state.status !== 'flying') return;

  const elapsed = Math.max(0, (Date.now() - state.startedAt) / 1000);

  state.multiplier = Math.max(
    1,
    Math.floor(Math.exp(elapsed * 0.12) * 100) / 100
  );

  if (state.multiplier >= state.crashMultiplier) {
    state.multiplier = state.crashMultiplier;
    state.status = 'crashed';
  }
}

function aviatorState(user, res) {
  const state = getUserGame(user.id, 'aviator');

  if (!state) {
    return sendJson(res, 200, {
      ok: true,
      active: false,
      balance: user.balance
    });
  }

  updateAviator(state);

  if (state.status === 'crashed') {
    clearUserGame(user.id, 'aviator');
    addHistory(user.id, 'game_loss', 0, 'Aviator: самолёт улетел');

    return sendJson(res, 200, {
      ok: true,
      active: false,
      status: 'crashed',
      crashMultiplier: state.crashMultiplier,
      balance: user.balance
    });
  }

  setUserGame(user.id, 'aviator', state);

  return sendJson(res, 200, {
    ok: true,
    active: true,
    status: state.status,
    multiplier: state.multiplier,
    balance: user.balance
  });
}

function cashoutAviator(user, res) {
  const state = getUserGame(user.id, 'aviator');

  if (!state || state.status !== 'flying') {
    return sendJson(res, 400, {
      ok: false,
      error: 'Нет активного полёта.'
    });
  }

  updateAviator(state);

  if (state.status !== 'flying' || state.multiplier >= state.crashMultiplier) {
    clearUserGame(user.id, 'aviator');
    addHistory(user.id, 'game_loss', 0, 'Aviator: самолёт улетел');

    return sendJson(res, 400, {
      ok: false,
      error: 'Самолёт уже улетел.',
      balance: user.balance
    });
  }

  const multiplier = state.multiplier;
  const payout = Math.floor(state.bet * multiplier);

  user.balance += payout;
  clearUserGame(user.id, 'aviator');

  addHistory(
    user.id,
    'game_win',
    payout,
    `Aviator: выплата x${multiplier.toFixed(2)}`
  );

  return sendJson(res, 200, {
    ok: true,
    payout,
    multiplier,
    balance: user.balance
  });
}

function startBlackjack(user, body, res) {
  const bet = safeAmount(body.bet, 1000, 1000000);

  if (!bet || user.balance < bet) {
    return sendJson(res, 400, {
      ok: false,
      error: 'Некорректная ставка или недостаточно средств.'
    });
  }

  if (getUserGame(user.id, 'blackjack')) {
    return sendJson(res, 409, {
      ok: false,
      error: 'Сначала завершите текущую игру.'
    });
  }

  const deck = [];

  for (let suit = 0; suit < 4; suit++) {
    for (let value = 1; value <= 13; value++) {
      deck.push({ value, suit });
    }
  }

  for (let i = deck.length - 1; i > 0; i--) {
    const j = secureRandomInt(0, i);
    [deck[i], deck[j]] = [deck[j], deck[i]];
  }

  const state = {
    bet,
    deck,
    player: [deck.pop(), deck.pop()],
    dealer: [deck.pop(), deck.pop()],
    status: 'playing'
  };

  user.balance -= bet;
  setUserGame(user.id, 'blackjack', state);

  addHistory(user.id, 'game_bet', -bet, 'Blackjack: ставка');

  return sendJson(res, 200, {
    ok: true,
    bet,
    balance: user.balance,
    player: state.player,
    dealer: [state.dealer[0], { hidden: true }],
    playerScore: blackjackScore(state.player)
  });
}

function blackjackCardValue(card) {
  if (card.value === 1) return 11;
  if (card.value >= 10) return 10;
  return card.value;
}

function blackjackScore(cards) {
  let total = 0;
  let aces = 0;

  for (const card of cards) {
    total += blackjackCardValue(card);

    if (card.value === 1) aces++;
  }

  while (total > 21 && aces > 0) {
    total -= 10;
    aces--;
  }

  return total;
}

function finishBlackjack(user, state, res, action) {
  const playerScore = blackjackScore(state.player);

  while (blackjackScore(state.dealer) < 17) {
    if (!state.deck.length) break;
    state.dealer.push(state.deck.pop());
  }

  const dealerScore = blackjackScore(state.dealer);
  let payout = 0;
  let result = 'loss';

  if (playerScore <= 21 && (
    dealerScore > 21 || playerScore > dealerScore
  )) {
    result = 'win';
    payout = state.bet * 2;
  } else if (playerScore === dealerScore) {
    result = 'draw';
    payout = state.bet;
  }

  user.balance += payout;
  clearUserGame(user.id, 'blackjack');

  if (result === 'win') {
    addHistory(user.id, 'game_win', payout, 'Blackjack: победа');
  } else if (result === 'draw') {
    addHistory(user.id, 'game_refund', payout, 'Blackjack: ничья');
  } else {
    addHistory(user.id, 'game_loss', 0, 'Blackjack: проигрыш');
  }

  return sendJson(res, 200, {
    ok: true,
    finished: true,
    result,
    payout,
    balance: user.balance,
    player: state.player,
    dealer: state.dealer,
    playerScore,
    dealerScore
  });
}

function blackjackHit(user, res) {
  const state = getUserGame(user.id, 'blackjack');

  if (!state || state.status !== 'playing') {
    return sendJson(res, 400, { ok: false, error: 'Нет активной игры.' });
  }

  if (!state.deck.length) {
    return finishBlackjack(user, state, res, 'stand');
  }

  state.player.push(state.deck.pop());

  const score = blackjackScore(state.player);

  if (score > 21) {
    return finishBlackjack(user, state, res, 'bust');
  }

  setUserGame(user.id, 'blackjack', state);

  return sendJson(res, 200, {
    ok: true,
    finished: false,
    player: state.player,
    dealer: [state.dealer[0], { hidden: true }],
    playerScore: score,
    balance: user.balance
  });
}

function blackjackStand(user, res) {
  const state = getUserGame(user.id, 'blackjack');

  if (!state || state.status !== 'playing') {
    return sendJson(res, 400, { ok: false, error: 'Нет активной игры.' });
  }

  return finishBlackjack(user, state, res, 'stand');
}

function serveStatic(req, res, pathname) {
  let requestedPath;

  try {
    requestedPath = decodeURIComponent(pathname);
  } catch {
    res.writeHead(400);
    res.end('Bad Request');
    return;
  }

  if (requestedPath === '/') requestedPath = '/index.html';

  const normalized = path.normalize(requestedPath).replace(/^(\.\.[/\\])+/, '');
  const file = path.resolve(PUBLIC_DIR, '.' + normalized);

  if (!file.startsWith(path.resolve(PUBLIC_DIR) + path.sep) &&
      file !== path.join(path.resolve(PUBLIC_DIR), 'index.html')) {
    res.writeHead(403);
    res.end('Forbidden');
    return;
  }

  fs.readFile(file, (error, content) => {
    if (error) {
      res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
      res.end('Not found');
      return;
    }

    res.writeHead(200, {
      'Content-Type': MIME_TYPES[path.extname(file).toLowerCase()] || 'application/octet-stream',
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'SAMEORIGIN',
      'Referrer-Policy': 'strict-origin-when-cross-origin'
    });

    res.end(content);
  });
}

async function handleRequest(req, res) {
  const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  const pathname = url.pathname;
  const method = req.method || 'GET';

  if (method === 'GET' && !pathname.startsWith('/api/')) {
    return serveStatic(req, res, pathname);
  }

  if (!pathname.startsWith('/api/')) {
    return sendJson(res, 404, { ok: false, error: 'Маршрут не найден.' });
  }

  const body = ['POST', 'PUT', 'PATCH', 'DELETE'].includes(method)
    ? await parseCookiesAndBody(req, res)
    : {};

  if (body === null) return;

  // Регистрация
  if (method === 'POST' && pathname === '/api/register') {
    const username = String(body.username || '').trim();
    const password = String(body.password || '');

    if (!/^[a-zA-Z0-9_]{3,24}$/.test(username)) {
      return sendJson(res, 400, {
        ok: false,
        error: 'Логин должен содержать 3–24 латинских букв, цифр или _.'
      });
    }

    if (password.length < 8 || password.length > 128) {
      return sendJson(res, 400, {
        ok: false,
        error: 'Пароль должен содержать от 8 до 128 символов.'
      });
    }

    if (db.users.some(user =>
      user.username.toLowerCase() === username.toLowerCase()
    )) {
      return sendJson(res, 409, {
        ok: false,
        error: 'Такой логин уже существует.'
      });
    }

    const passwordData = hashPassword(password);

    const user = {
      id: db.nextUserId++,
      username,
      passwordSalt: passwordData.salt,
      passwordHash: passwordData.hash,
      balance: 0,
      createdAt: now()
    };

    db.users.push(user);

    const token = randomId(32);

    sessions.set(token, {
      role: 'user',
      userId: user.id,
      expiresAt: Date.now() + 7 * 24 * 60 * 60 * 1000
    });

    saveDatabase();
    setSessionCookie(res, token);

    return sendJson(res, 201, {
      ok: true,
      user: publicUser(user)
    });
  }

  // Вход
  if (method === 'POST' && pathname === '/api/login') {
    const username = String(body.username || '').trim();
    const password = String(body.password || '');

    const user = db.users.find(item =>
      item.username.toLowerCase() === username.toLowerCase()
    );

    if (!user || !verifyPassword(password, user.passwordSalt, user.passwordHash)) {
      return sendJson(res, 401, {
        ok: false,
        error: 'Неверный логин или пароль.'
      });
    }

    const token = randomId(32);

    sessions.set(token, {
      role: 'user',
      userId: user.id,
      expiresAt: Date.now() + 7 * 24 * 60 * 60 * 1000
    });

    setSessionCookie(res, token);

    return sendJson(res, 200, {
      ok: true,
      user: publicUser(user)
    });
  }

  // Выход
  if (method === 'POST' && pathname === '/api/logout') {
    const token = getCookie(req, 'sid');

    if (token) sessions.delete(token);

    clearSessionCookie(res);
    return sendJson(res, 200, { ok: true });
  }

  // Текущий пользователь
  if (method === 'GET' && pathname === '/api/me') {
    const session = currentSession(req);

    if (!session || session.role !== 'user') {
      return sendJson(res, 200, { ok: true, user: null });
    }

    const user = findUserById(session.userId);

    return sendJson(res, 200, {
      ok: true,
      user: user ? publicUser(user) : null
    });
  }

  // История пользователя
  if (method === 'GET' && pathname === '/api/history') {
    const user = requireUser(req, res);
    if (!user) return;

    const history = db.history
      .filter(item => item.userId === user.id)
      .slice(0, 200);

    return sendJson(res, 200, { ok: true, history });
  }

  // Создание заявки на пополнение
  if (method === 'POST' && pathname === '/api/topup-requests') {
    const user = requireUser(req, res);
    if (!user) return;

    const amount = safeAmount(body.amount);

    if (!amount) {
      return sendJson(res, 400, {
        ok: false,
        error: 'Сумма должна быть от 1 000 до 10 000 000 и кратна 1 000.'
      });
    }

    let receiptFile;

    try {
      receiptFile = saveReceipt(body.receiptData || body.receipt);
    } catch (error) {
      return sendJson(res, 400, { ok: false, error: error.message });
    }

    const request = {
      id: db.nextTopupId++,
      userId: user.id,
      amount,
      receiptFile,
      status: 'pending',
      adminComment: '',
      createdAt: now(),
      updatedAt: now()
    };

    db.topups.unshift(request);
    saveDatabase();

    return sendJson(res, 201, {
      ok: true,
      request: topupForUser(request),
      message: 'Заявка отправлена на проверку.'
    });
  }

  // Заявки на пополнение пользователя
  if (method === 'GET' && pathname === '/api/my-topup-requests') {
    const user = requireUser(req, res);
    if (!user) return;

    return sendJson(res, 200, {
      ok: true,
      requests: db.topups
        .filter(item => item.userId === user.id)
        .map(topupForUser)
    });
  }

  // Создание заявки на вывод
  if (method === 'POST' && pathname === '/api/withdrawal-requests') {
    const user = requireUser(req, res);
    if (!user) return;

    const amount = safeAmount(body.amount);

    const recipient = String(body.recipient || '').trim();
    const paymentDetails = String(body.paymentDetails || '').trim();

    if (!amount) {
      return sendJson(res, 400, {
        ok: false,
        error: 'Сумма должна быть от 1 000 до 10 000 000 и кратна 1 000.'
      });
    }

    if (recipient.length < 2 || recipient.length > 100) {
      return sendJson(res, 400, {
        ok: false,
        error: 'Укажите имя получателя.'
      });
    }

    if (paymentDetails.length < 5 || paymentDetails.length > 200) {
      return sendJson(res, 400, {
        ok: false,
        error: 'Укажите корректные платёжные реквизиты.'
      });
    }

    if (user.balance < amount) {
      return sendJson(res, 400, {
        ok: false,
        error: 'Недостаточно средств.'
      });
    }

    user.balance -= amount;

    const request = {
      id: db.nextWithdrawalId++,
      userId: user.id,
      amount,
      recipient,
      paymentDetails,
      status: 'pending',
      adminComment: '',
      createdAt: now(),
      updatedAt: now()
    };

    db.withdrawals.unshift(request);
    addHistory(
      user.id,
      'withdrawal_reserved',
      -amount,
      `Средства зарезервированы для заявки на вывод №${request.id}`
    );

    saveDatabase();

    return sendJson(res, 201, {
      ok: true,
      request: withdrawalForUser(request),
      balance: user.balance
    });
  }

  // Заявки на вывод пользователя
  if (method === 'GET' && pathname === '/api/my-withdrawal-requests') {
    const user = requireUser(req, res);
    if (!user) return;

    return sendJson(res, 200, {
      ok: true,
      requests: db.withdrawals
        .filter(item => item.userId === user.id)
        .map(withdrawalForUser)
    });
  }

  // Тестовая игра
  if (method === 'POST' && pathname === '/api/demo-play') {
    const user = requireUser(req, res);
    if (!user) return;

    const bet = safeAmount(body.bet, 1000, 1000000);

    if (!bet || user.balance < bet) {
      return sendJson(res, 400, {
        ok: false,
        error: 'Некорректная ставка или недостаточно средств.'
      });
    }

    user.balance -= bet;

    const won = crypto.randomInt(0, 100) < 45;
    const payout = won ? bet * 2 : 0;

    user.balance += payout;

    addHistory(
      user.id,
      won ? 'game_win' : 'game_loss',
      payout,
      won ? 'Демо-игра: победа' : 'Демо-игра: проигрыш'
    );

    return sendJson(res, 200, {
      ok: true,
      won,
      payout,
      balance: user.balance
    });
  }

  // Apple of Fortune
  if (method === 'POST' && pathname === '/api/games/apple/start') {
    const user = requireUser(req, res);
    if (!user) return;
    return startApple(user, body, res);
  }

  if (method === 'POST' && pathname === '/api/games/apple/pick') {
    const user = requireUser(req, res);
    if (!user) return;
    return pickApple(user, body, res);
  }

  if (method === 'POST' && pathname === '/api/games/apple/cashout') {
    const user = requireUser(req, res);
    if (!user) return;
    return cashoutApple(user, res);
  }

  // Aviator
  if (method === 'POST' && pathname === '/api/games/aviator/start') {
    const user = requireUser(req, res);
    if (!user) return;
    return startAviator(user, body, res);
  }

  if (method === 'GET' && pathname === '/api/games/aviator/state') {
    const user = requireUser(req, res);
    if (!user) return;
    return aviatorState(user, res);
  }

  if (method === 'POST' && pathname === '/api/games/aviator/cashout') {
    const user = requireUser(req, res);
    if (!user) return;
    return cashoutAviator(user, res);
  }

  // Blackjack
  if (method === 'POST' && pathname === '/api/games/blackjack/start') {
    const user = requireUser(req, res);
    if (!user) return;
    return startBlackjack(user, body, res);
  }

  if (method === 'POST' && pathname === '/api/games/blackjack/hit') {
    const user = requireUser(req, res);
    if (!user) return;
    return blackjackHit(user, res);
  }

  if (method === 'POST' && pathname === '/api/games/blackjack/stand') {
    const user = requireUser(req, res);
    if (!user) return;
    return blackjackStand(user, res);
  }

  // Авторизация администратора
  if (method === 'POST' && pathname === '/api/admin/login') {
    const username = String(body.username || '').trim();
    const password = String(body.password || '');

    const passwordValid = ADMIN_PASSWORD
      ? crypto.timingSafeEqual(
          crypto.createHash('sha256').update(password).digest(),
          crypto.createHash('sha256').update(ADMIN_PASSWORD).digest()
        )
      : false;

    if (username !== ADMIN_USERNAME || !passwordValid) {
      return sendJson(res, 401, {
        ok: false,
        error: 'Неверный логин или пароль администратора.'
      });
    }

    const token = randomId(32);

    sessions.set(token, {
      role: 'admin',
      expiresAt: Date.now() + 7 * 24 * 60 * 60 * 1000
    });

    setSessionCookie(res, token);

    return sendJson(res, 200, { ok: true });
  }

  if (method === 'GET' && pathname === '/api/admin/me') {
    const session = currentSession(req);

    return sendJson(res, 200, {
      ok: true,
      isAdmin: Boolean(session && session.role === 'admin'),
      username: session && session.role === 'admin'
        ? ADMIN_USERNAME
        : null
    });
  }

  // Пользователи для администратора
  if (method === 'GET' && pathname === '/api/admin/users') {
    if (!requireAdmin(req, res)) return;

    return sendJson(res, 200, {
      ok: true,
      users: db.users.map(publicUser)
    });
  }

  // Заявки на пополнение для администратора
  if (method === 'GET' && pathname === '/api/admin/topup-requests') {
    if (!requireAdmin(req, res)) return;

    return sendJson(res, 200, {
      ok: true,
      requests: db.topups.map(topupForAdmin)
    });
  }

  // Просмотр чека — только администратор
  const receiptMatch = pathname.match(/^\/api\/admin\/receipts\/([^/]+)$/);

  if (method === 'GET' && receiptMatch) {
    if (!requireAdmin(req, res)) return;

    const filename = decodeURIComponent(receiptMatch[1]);

    if (path.basename(filename) !== filename) {
      return sendJson(res, 400, { ok: false, error: 'Некорректное имя файла.' });
    }

    const topup = db.topups.find(item => item.receiptFile === filename);

    if (!topup) {
      return sendJson(res, 404, { ok: false, error: 'Чек не найден.' });
    }

    const file = path.join(RECEIPTS_DIR, filename);

    if (!fs.existsSync(file)) {
      return sendJson(res, 404, { ok: false, error: 'Файл чека отсутствует.' });
    }

    const extension = path.extname(filename).toLowerCase();

    res.writeHead(200, {
      'Content-Type': MIME_TYPES[extension] || 'application/octet-stream',
      'Cache-Control': 'private, no-store',
      'X-Content-Type-Options': 'nosniff'
    });

    return fs.createReadStream(file).pipe(res);
  }

  // Одобрение или отклонение пополнения
  const topupAction = pathname.match(
    /^\/api\/admin\/topup-requests\/(\d+)\/(approve|reject)$/
  );

  if (method === 'POST' && topupAction) {
    if (!requireAdmin(req, res)) return;

    const id = Number(topupAction[1]);
    const action = topupAction[2];
    const request = db.topups.find(item => item.id === id);

    if (!request) {
      return sendJson(res, 404, { ok: false, error: 'Заявка не найдена.' });
    }

    if (request.status !== 'pending') {
      return sendJson(res, 409, {
        ok: false,
        error: 'Заявка уже обработана.'
      });
    }

    const owner = findUserById(request.userId);

    if (!owner) {
      return sendJson(res, 404, { ok: false, error: 'Пользователь не найден.' });
    }

    request.status = action === 'approve' ? 'approved' : 'rejected';
    request.updatedAt = now();
    request.adminComment = String(body.comment || '').slice(0, 500);

    if (action === 'approve') {
      owner.balance += request.amount;

      addHistory(
        owner.id,
        'topup',
        request.amount,
        `Пополнение одобрено, заявка №${request.id}`
      );
    } else {
      saveDatabase();
    }

    return sendJson(res, 200, {
      ok: true,
      request: topupForAdmin(request),
      user: publicUser(owner)
    });
  }

  // Заявки на вывод для администратора
  if (method === 'GET' && pathname === '/api/admin/withdrawal-requests') {
    if (!requireAdmin(req, res)) return;

    return sendJson(res, 200, {
      ok: true,
      requests: db.withdrawals.map(withdrawalForAdmin)
    });
  }

  // Одобрение или отклонение вывода
  const withdrawalAction = pathname.match(
    /^\/api\/admin\/withdrawal-requests\/(\d+)\/(approve|reject)$/
  );

  if (method === 'POST' && withdrawalAction) {
    if (!requireAdmin(req, res)) return;

    const id = Number(withdrawalAction[1]);
    const action = withdrawalAction[2];

    const request = db.withdrawals.find(item => item.id === id);

    if (!request) {
      return sendJson(res, 404, { ok: false, error: 'Заявка не найдена.' });
    }

    if (request.status !== 'pending') {
      return sendJson(res, 409, {
        ok: false,
        error: 'Заявка уже обработана.'
      });
    }

    const owner = findUserById(request.userId);

    if (!owner) {
      return sendJson(res, 404, { ok: false, error: 'Пользователь не найден.' });
    }

    request.status = action === 'approve' ? 'approved' : 'rejected';
    request.updatedAt = now();
    request.adminComment = String(body.comment || '').slice(0, 500);

    if (action === 'reject') {
      owner.balance += request.amount;

      addHistory(
        owner.id,
        'withdrawal_refund',
        request.amount,
        `Возврат после отклонения заявки №${request.id}`
      );
    } else {
      addHistory(
        owner.id,
        'withdrawal_approved',
        0,
        `Заявка на вывод №${request.id} одобрена администратором`
      );
    }

    saveDatabase();

    return sendJson(res, 200, {
      ok: true,
      request: withdrawalForAdmin(request),
      user: publicUser(owner)
    });
  }

  return sendJson(res, 404, {
    ok: false,
    error: 'API-маршрут не найден.'
  });
}

const server = http.createServer((req, res) => {
  handleRequest(req, res).catch(error => {
    console.error('Request error:', error);

    if (!res.headersSent) {
      sendJson(res, 500, {
        ok: false,
        error: 'Внутренняя ошибка сервера.'
      });
    } else if (!res.writableEnded) {
      res.end();
    }
  });
});

server.listen(PORT, HOST, () => {
  console.log(`DEPOSIT 2.0 server running on ${HOST}:${PORT}`);
  console.log(`Data directory: ${DATA_DIR}`);
});
