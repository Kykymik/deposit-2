<!doctype html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>DEPOSIT 2.0 — Игровой клуб</title>
<style>
:root{color-scheme:dark;--bg:#0b1020;--panel:#151d31;--gold:#f4c96b;--text:#f4f6ff;--muted:#a9b4ca;--border:#303b54;--green:#3bd69a;--red:#ff737d}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font:16px system-ui,Arial,sans-serif}
header{padding:22px 16px;background:#11192a;border-bottom:1px solid var(--border)}
.wrap{width:min(1000px,94%);margin:auto}
h1{margin:0;color:var(--gold);font-size:26px}
.subtitle{color:var(--muted);margin-top:5px}
main{padding:20px 0 50px}
.panel{background:var(--panel);border:1px solid var(--border);border-radius:16px;padding:18px;margin-bottom:16px}
.row{display:flex;gap:10px;flex-wrap:wrap;align-items:center}
input,select,button{font:inherit;border-radius:9px;padding:11px 12px}
input,select{background:#0d1425;color:var(--text);border:1px solid var(--border);max-width:100%}
button{border:0;background:var(--gold);color:#17130a;font-weight:700;cursor:pointer}
button.secondary{background:#26334d;color:var(--text)}
button.danger{background:#8f303d;color:white}
button:disabled{opacity:.45;cursor:not-allowed}
.hidden{display:none!important}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(245px,1fr));gap:14px}
.game{border:1px solid var(--border);background:#11192a;border-radius:14px;padding:16px}
.game h3{margin-top:0}
.balance{font-size:26px;color:var(--gold);font-weight:800}
.muted{color:var(--muted);font-size:14px}
.result{margin-top:12px;min-height:26px;white-space:pre-wrap}
.cards{font-size:25px;line-height:1.9;overflow-wrap:anywhere}
.apple-row{display:flex;gap:10px;flex-wrap:wrap;margin-top:14px}
.apple-row button{font-size:23px;min-width:54px}
.good{color:var(--green)}.bad{color:var(--red)}
a{color:var(--gold)}
hr{border:0;border-top:1px solid var(--border);margin:16px 0}
table{border-collapse:collapse;width:100%;font-size:14px}
th,td{text-align:left;padding:9px;border-bottom:1px solid var(--border);overflow-wrap:anywhere}
.table-wrap{overflow-x:auto}
@media(max-width:480px){.panel{padding:13px}input{width:100%}.row button{flex:1}}
</style>
</head>
<body>
<header>
<div class="wrap">
<h1>DEPOSIT 2.0</h1>
<div class="subtitle">Игровая платформа · демо-режим</div>
</div>
</header>

<main class="wrap">
<section id="auth" class="panel">
<h2 id="authTitle">Вход</h2>
<form id="authForm" class="row">
<input id="username" placeholder="Логин" minlength="3" maxlength="24" required>
<input id="password" type="password" placeholder="Пароль (от 8 символов)" minlength="8" required>
<button id="authSubmit">Войти</button>
</form>
<p><button class="secondary" id="toggleAuth" type="button">Создать аккаунт</button></p>
<div class="result" id="authMessage"></div>
</section>

<section id="app" class="hidden">
<div class="panel">
<div class="row" style="justify-content:space-between">
<div>
<div class="muted">Ваш игровой ID</div>
<strong id="gamerId">—</strong>
<div class="muted" id="playerName"></div>
</div>
<div>
<div class="muted">Виртуальный баланс</div>
<div class="balance"><span id="balance">0</span> UZS</div>
</div>
<button class="secondary" id="logout">Выйти</button>
</div>
<p class="muted">Все ставки и выигрыши в этом режиме виртуальные. Пополнения — тестовые заявки.</p>
</div>

<div class="panel">
<h2>Тестовое пополнение</h2>
<form id="topupForm" class="row">
<input id="topupAmount" type="number" min="1000" max="10000000" step="1000" value="50000" required>
<button>Создать заявку</button>
</form>
<div id="topupMessage" class="result"></div>
<h3>Мои заявки</h3>
<div id="myRequests" class="muted">Загрузка…</div>
</div>

<h2>Игры</h2>
<div class="grid">
<article class="game">
<h3>🍀 Luck</h3>
<p class="muted">45% шанс получить 2× ставки.</p>
<input id="bet-luck" type="number" min="100" max="1000000" step="100" value="100">
<button data-simple="luck">Играть</button>
<div class="result" id="result-luck"></div>
</article>

<article class="game">
<h3>🪙 Coin</h3>
<p class="muted">Угадай сторону монеты. Выигрыш 2×.</p>
<input id="bet-coin" type="number" min="100" max="1000000" step="100" value="100">
<button data-simple="coin">Подбросить</button>
<div class="result" id="result-coin"></div>
</article>

<article class="game">
<h3>🎯 Challenge</h3>
<p class="muted">Сложное испытание. Выигрыш 3×.</p>
<input id="bet-challenge" type="number" min="100" max="1000000" step="100" value="100">
<button data-simple="challenge">Испытать удачу</button>
<div class="result" id="result-challenge"></div>
</article>

<article class="game">
<h3>🍎 Apple of Fortune</h3>
<p class="muted">На каждом шаге выбери яблоко, избегая ловушки. Множитель растёт на 0,5× за шаг.</p>
<input id="bet-apple" type="number" min="100" max="1000000" step="100" value="100">
<button id="appleStart">Начать</button>
<div id="appleArea" class="hidden">
<div class="apple-row">
<button type="button" data-apple="0">🍎</button>
<button type="button" data-apple="1">🍎</button>
<button type="button" data-apple="2">🍎</button>
</div>
<p>Шаг: <strong id="appleStep">0</strong> · Множитель: <strong id="appleMultiplier">1×</strong></p>
<button id="appleCashout" class="secondary">Забрать выигрыш</button>
</div>
<div class="result" id="result-apple"></div>
</article>

<article class="game">
<h3>✈️ Aviator</h3>
<p class="muted">Забери выплату до падения самолёта. Множитель зависит от времени раунда.</p>
<input id="bet-aviator" type="number" min="100" max="1000000" step="100" value="100">
<button id="aviatorStart">Начать полёт</button>
<div id="aviatorArea" class="hidden">
<p>Множитель: <strong id="aviatorMultiplier">1.00×</strong></p>
<button id="aviatorCashout">Забрать выигрыш</button>
</div>
<div class="result" id="result-aviator"></div>
</article>

<article class="game">
<h3>🃏 21 очко — Blackjack</h3>
<p class="muted">Набери 21 или приблизься к ней, не перебрав. Дилер добирает до 17.</p>
<input id="bet-blackjack" type="number" min="100" max="1000000" step="100" value="100">
<button id="blackjackStart">Начать раунд</button>
<div id="blackjackArea" class="hidden">
<p>Ваши карты: <span id="bjPlayer" class="cards"></span></p>
<p>Ваши очки: <strong id="bjPlayerValue">0</strong></p>
<p>Карты дилера: <span id="bjDealer" class="cards"></span></p>
<p id="bjDealerValue"></p>
<div class="row">
<button id="bjHit">Ещё карту</button>
<button id="bjStand" class="secondary">Хватит</button>
</div>
</div>
<div class="result" id="result-blackjack"></div>
</article>
</div>

<div class="panel" style="margin-top:16px">
<h2>История операций</h2>
<button id="refreshHistory" class="secondary">Обновить</button>
<div id="history" class="table-wrap"></div>
</div>

<section id="adminPanel" class="panel hidden">
<h2>Админ-панель</h2>
<button id="refreshAdmin">Обновить заявки</button>
<div id="adminRequests" class="table-wrap"></div>
<h3>Пользователи</h3>
<div id="adminUsers" class="table-wrap"></div>
<div id="adminMessage" class="result"></div>
</section>
</section>
</main>

<script>
const $ = id => document.getElementById(id);
let user = null;
let isRegister = false;
let appleActive = false;
let aviatorActive = false;
let blackjackActive = false;
let aviatorTimer = null;

async function api(url, options = {}) {
  const response = await fetch(url, {
    credentials: "same-origin",
    headers: { "Content-Type": "application/json", ...(options.headers || {}) },
    ...options
  });

  let data;
  try { data = await response.json(); }
  catch { throw new Error("Сервер вернул неверный ответ"); }

  if (!response.ok) throw new Error(data.error || "Ошибка запроса");
  return data;
}

function showResult(id, text, good = false) {
  const el = $(id);
  el.textContent = text;
  el.className = "result " + (good ? "good" : "bad");
}

function money(value) {
  return Number(value || 0).toLocaleString("ru-RU");
}

async function refreshMe() {
  const data = await api("/api/me");
  user = data.user;
  $("balance").textContent = money(user.balance);
  $("gamerId").textContent = user.gamer_id;
  $("playerName").textContent = "Игрок: " + user.username;
}

async function refreshRequests() {
  const data = await api("/api/my-topup-requests");

  if (!data.requests.length) {
    $("myRequests").textContent = "Заявок пока нет.";
    return;
  }

  $("myRequests").innerHTML = "";
  const table = document.createElement("table");
  table.innerHTML = "<thead><tr><th>ID</th><th>Сумма</th><th>Статус</th><th>Дата</th></tr></thead>";
  const tbody = document.createElement("tbody");

  for (const request of data.requests) {
    const tr = document.createElement("tr");
    for (const value of [
      request.id,
      money(request.amount) + " UZS",
      request.status,
      request.created_at
    ]) {
      const td = document.createElement("td");
      td.textContent = value;
      tr.appendChild(td);
    }
    tbody.appendChild(tr);
  }

  table.appendChild(tbody);
  $("myRequests").appendChild(table);
}

async function refreshHistory() {
  const data = await api("/api/history");
  $("history").innerHTML = "";

  const table = document.createElement("table");
  table.innerHTML = "<thead><tr><th>Операция</th><th>Сумма</th><th>Баланс после</th><th>Дата</th></tr></thead>";
  const tbody = document.createElement("tbody");

  for (const item of data.history) {
    const tr = document.createElement("tr");
    const values = [
      item.type,
      money(item.amount) + " UZS",
      money(item.balance_after) + " UZS",
      item.created_at
    ];

    values.forEach(value => {
      const td = document.createElement("td");
      td.textContent = value;
      tr.appendChild(td);
    });

    tbody.appendChild(tr);
  }

  table.appendChild(tbody);
  $("history").appendChild(table);
}

async function refreshAdmin() {
  try {
    await api("/api/admin/me");
    $("adminPanel").classList.remove("hidden");

    const data = await api("/api/admin/topup-requests");
    $("adminRequests").innerHTML = "";

    const table = document.createElement("table");
    table.innerHTML = "<thead><tr><th>ID</th><th>Игрок</th><th>Game ID</th><th>Сумма</th><th>Статус</th><th>Действия</th></tr></thead>";
    const tbody = document.createElement("tbody");

    for (const r of data.requests) {
      const tr = document.createElement("tr");
      const vals = [r.id, r.username, r.gamer_id, money(r.amount) + " UZS", r.status];

      vals.forEach(v => {
        const td = document.createElement("td");
        td.textContent = v;
        tr.appendChild(td);
      });

      const td = document.createElement("td");

      if (r.status === "pending") {
        const approve = document.createElement("button");
        approve.textContent = "Одобрить";
        approve.addEventListener("click", () => reviewTopup(r.id, "approve"));

        const reject = document.createElement("button");
        reject.textContent = "Отклонить";
        reject.className = "danger";
        reject.style.marginLeft = "6px";
        reject.addEventListener("click", () => reviewTopup(r.id, "reject"));

        td.append(approve, reject);
      } else {
        td.textContent = "Обработана";
      }

      tr.appendChild(td);
      tbody.appendChild(tr);
    }

    table.appendChild(tbody);
    $("adminRequests").appendChild(table);

    const usersData = await api("/api/admin/users");
    $("adminUsers").innerHTML = "";

    const usersTable = document.createElement("table");
    usersTable.innerHTML = "<thead><tr><th>ID</th><th>Логин</th><th>Game ID</th><th>Баланс</th></tr></thead>";
    const usersBody = document.createElement("tbody");

    for (const u of usersData.users) {
      const tr = document.createElement("tr");

      [u.id, u.username, u.gamer_id, money(u.balance) + " UZS"].forEach(v => {
        const td = document.createElement("td");
        td.textContent = v;
        tr.appendChild(td);
      });

      usersBody.appendChild(tr);
    }

    usersTable.appendChild(usersBody);
    $("adminUsers").appendChild(usersTable);
  } catch (error) {
    $("adminPanel").classList.add("hidden");
  }
}

async function reviewTopup(id, action) {
  try {
    await api(`/api/admin/topup-requests/${id}/${action}`, { method: "POST", body: "{}" });
    showResult("adminMessage", "Заявка обработана.", true);
    await refreshAdmin();
    await refreshMe();
    await refreshRequests();
  } catch (error) {
    showResult("adminMessage", error.message);
  }
}

async function enterApp() {
  $("auth").classList.add("hidden");
  $("app").classList.remove("hidden");

  await refreshMe();
  await refreshRequests();
  await refreshHistory();
  await refreshAdmin();
}

$("toggleAuth").addEventListener("click", () => {
  isRegister = !isRegister;
  $("authTitle").textContent = isRegister ? "Регистрация" : "Вход";
  $("authSubmit").textContent = isRegister ? "Создать аккаунт" : "Войти";
  $("toggleAuth").textContent = isRegister ? "У меня уже есть аккаунт" : "Создать аккаунт";
});

$("authForm").addEventListener("submit", async e => {
  e.preventDefault();

  try {
    const data = await api(isRegister ? "/api/register" : "/api/login", {
      method: "POST",
      body: JSON.stringify({
        username: $("username").value.trim(),
        password: $("password").value
      })
    });

    user = data.user;
    $("authMessage").textContent = "";
    await enterApp();
  } catch (error) {
    showResult("authMessage", error.message);
  }
});

$("logout").addEventListener("click", async () => {
  stopAviatorTimer();

  try { await api("/api/logout", { method: "POST", body: "{}" }); }
  finally {
    user = null;
    $("app").classList.add("hidden");
    $("auth").classList.remove("hidden");
  }
});

$("topupForm").addEventListener("submit", async e => {
  e.preventDefault();

  try {
    const amount = Number($("topupAmount").value);
    await api("/api/topup-requests", {
      method: "POST",
      body: JSON.stringify({ amount })
    });

    showResult("topupMessage", "Тестовая заявка создана. Баланс изменится только после одобрения администратором.", true);
    await refreshRequests();
  } catch (error) {
    showResult("topupMessage", error.message);
  }
});

document.querySelectorAll("[data-simple]").forEach(button => {
  button.addEventListener("click", async () => {
    const game = button.dataset.simple;
    const bet = Number($("bet-" + game).value);

    try {
      const data = await api("/api/demo-play", {
        method: "POST",
        body: JSON.stringify({ game, bet })
      });

      showResult("result-" + game, `${data.result}\nВыплата: ${money(data.payout)} UZS`, data.payout > 0);
      await refreshMe();
      await refreshHistory();
    } catch (error) {
      showResult("result-" + game, error.message);
    }
  });
});

/* Apple */

$("appleStart").addEventListener("click", async () => {
  try {
    if (appleActive) throw new Error("Сначала завершите текущую игру");

    const data = await api("/api/games/apple/start", {
      method: "POST",
      body: JSON.stringify({ bet: Number($("bet-apple").value) })
    });

    appleActive = true;
    $("appleArea").classList.remove("hidden");
    $("appleStep").textContent = "0";
    $("appleMultiplier").textContent = "1×";
    showResult("result-apple", "Выберите одно из трёх яблок.", true);
    await refreshMe();
  } catch (error) {
    showResult("result-apple", error.message);
  }
});

document.querySelectorAll("[data-apple]").forEach(button => {
  button.addEventListener("click", async () => {
    if (!appleActive) return;

    try {
      const data = await api("/api/games/apple/pick", {
        method: "POST",
        body: JSON.stringify({ choice: Number(button.dataset.apple) })
      });

      if (data.lost) {
        appleActive = false;
        $("appleArea").classList.add("hidden");
        showResult("result-apple", data.message, false);
        await refreshMe();
        await refreshHistory();
        return;
      }

      $("appleStep").textContent = data.game.step;
      $("appleMultiplier").textContent = data.game.multiplier + "×";
      showResult("result-apple", "Удачный шаг! Можете рискнуть ещё раз или забрать выигрыш.", true);
    } catch (error) {
      showResult("result-apple", error.message);
    }
  });
});

$("appleCashout").addEventListener("click", async () => {
  try {
    const data = await api("/api/games/apple/cashout", {
      method: "POST",
      body: "{}"
    });

    appleActive = false;
    $("appleArea").classList.add("hidden");
    showResult("result-apple", `Вы забрали ${money(data.payout)} UZS (${data.multiplier}×).`, true);
    await refreshMe();
    await refreshHistory();
  } catch (error) {
    showResult("result-apple", error.message);
  }
});

/* Aviator */

function stopAviatorTimer() {
  if (aviatorTimer) clearInterval(aviatorTimer);
  aviatorTimer = null;
}

$("aviatorStart").addEventListener("click", async () => {
  try {
    if (aviatorActive) throw new Error("Сначала завершите текущий раунд");

    const data = await api("/api/games/aviator/start", {
      method: "POST",
      body: JSON.stringify({ bet: Number($("bet-aviator").value) })
    });

    aviatorActive = true;
    $("aviatorArea").classList.remove("hidden");
    showResult("result-aviator", "Самолёт взлетел. Заберите выигрыш до падения!", true);
    await refreshMe();

    stopAviatorTimer();
    aviatorTimer = setInterval(async () => {
      if (!aviatorActive) return;

      try {
        const state = await api("/api/games/aviator/state");

        if (state.crashed) {
          aviatorActive = false;
          stopAviatorTimer();
          $("aviatorArea").classList.add("hidden");
          showResult("result-aviator", `Самолёт упал на ${state.multiplier}×. Ставка потеряна.`);
          await refreshMe();
          await refreshHistory();
        } else {
          $("aviatorMultiplier").textContent = Number(state.multiplier).toFixed(2) + "×";
        }
      } catch (error) {
        aviatorActive = false;
        stopAviatorTimer();
        $("aviatorArea").classList.add("hidden");
        showResult("result-aviator", error.message);
      }
    }, 200);
  } catch (error) {
    showResult("result-aviator", error.message);
  }
});

$("aviatorCashout").addEventListener("click", async () => {
  try {
    const data = await api("/api/games/aviator/cashout", {
      method: "POST",
      body: "{}"
    });

    aviatorActive = false;
    stopAviatorTimer();
    $("aviatorArea").classList.add("hidden");

    showResult("result-aviator",
      data.crashed
        ? "Самолёт уже упал. Ставка потеряна."
        : `Вы забрали ${money(data.payout)} UZS (${Number(data.multiplier).toFixed(2)}×).`,
      !data.crashed
    );

    await refreshMe();
    await refreshHistory();
  } catch (error) {
    showResult("result-aviator", error.message);
  }
});

/* Blackjack */

function showCards(id, cards) {
  $(id).textContent = cards.map(c => c.rank + c.suit).join("  ");
}

function renderBlackjack(data) {
  showCards("bjPlayer", data.player || []);
  $("bjPlayerValue").textContent = data.playerValue ?? "";
  showCards("bjDealer", data.dealer || []);

  $("bjDealerValue").textContent =
    data.dealerValue == null ? "Очки дилера: скрыты" : "Очки дилера: " + data.dealerValue;

  if (data.finished !== undefined) {
    blackjackActive = !data.finished;
  }
}

async function blackjackAction(action) {
  try {
    const data = await api("/api/games/blackjack/" + action, {
      method: "POST",
      body: "{}"
    });

    if (data.player) renderBlackjack(data);

    if (data.finished !== false) {
      blackjackActive = false;
      $("blackjackArea").classList.add("hidden");
      showResult("result-blackjack",
        `${data.result}\nВыплата: ${money(data.payout)} UZS`,
        data.payout > 0
      );
      await refreshMe();
      await refreshHistory();
    }
  } catch (error) {
    showResult("result-blackjack", error.message);
  }
}

$("blackjackStart").addEventListener("click", async () => {
  try {
    if (blackjackActive) throw new Error("Сначала завершите текущий раунд");

    const data = await api("/api/games/blackjack/start", {
      method: "POST",
      body: JSON.stringify({ bet: Number($("bet-blackjack").value) })
    });

    $("blackjackArea").classList.remove("hidden");
    renderBlackjack(data);

    if (data.finished !== false) {
      $("blackjackArea").classList.add("hidden");
      showResult("result-blackjack", `${data.result}\nВыплата: ${money(data.payout)} UZS`, true);
      await refreshMe();
      await refreshHistory();
    } else {
      showResult("result-blackjack", "Ваш ход. Выберите действие.", true);
    }

    await refreshMe();
  } catch (error) {
    showResult("result-blackjack", error.message);
  }
});

$("bjHit").addEventListener("click", () => blackjackAction("hit"));
$("bjStand").addEventListener("click", () => blackjackAction("stand"));

$("refreshHistory").addEventListener("click", async () => {
  try {
    await refreshHistory();
    await refreshMe();
  } catch (error) {
    alert(error.message);
  }
});

$("refreshAdmin").addEventListener("click", refreshAdmin);

(async function init() {
  try {
    await enterApp();
  } catch {
    $("auth").classList.remove("hidden");
    $("app").classList.add("hidden");
  }
})();
</script>
</body>
</html>
