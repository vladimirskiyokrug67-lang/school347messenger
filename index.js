// ============================================================
// СЕРВЕР МЕССЕНДЖЕРА "school347" — v0.5
// ============================================================
// Что нового по сравнению с v0.4:
//   - Постоянное хранилище: если заданы переменные TURSO_DATABASE_URL и
//     TURSO_AUTH_TOKEN, данные хранятся в облачной базе Turso и НЕ пропадают
//     при перезапуске/засыпании сервера на Render. Без этих переменных
//     сервер работает с локальным файлом school347.db (удобно для тестов).
//   - Удаление и редактирование своих сообщений
//   - Реакции на сообщения (по одной реакции от пользователя на сообщение)
//   - Исправлен разбор WebSocket-кадров (большие сообщения, пинги)
//   - Исправлены утечки в списке личных чатов (точное сравнение почт)
//   - Один аккаунт может быть открыт в нескольких вкладках одновременно
// ============================================================

const http = require('http');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { promisify } = require('util');

const scrypt = promisify(crypto.scrypt);

const PORT = process.env.PORT || 8080;
const WEBSOCKET_MAGIC_STRING = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11';
const DB_PATH = path.join(__dirname, 'school347.db');

const MAX_TEXT = 4000;            // максимальная длина сообщения
const HISTORY_LIMIT = 300;        // сколько последних сообщений отдаём при открытии чата
const MAX_FRAME = 4 * 1024 * 1024; // максимальный размер одного сообщения WebSocket
const SESSION_TTL_MS = 90 * 24 * 60 * 60 * 1000; // сессия живёт 90 дней
const ALLOWED_REACTIONS = ['👍', '❤️', '😂', '😮', '😢', '🔥'];
const EMAIL_RE = /^[a-z0-9._%+-]{1,64}@gmail\.com$/;
const USERNAME_RE = /^[a-z0-9_]{3,12}$/;

// Список допустимых классов: 1-1, 1-2, 1-3, 2-1, ... 11-3
const ALL_CLASSES = [];
for (let grade = 1; grade <= 11; grade++) {
  for (let letter = 1; letter <= 3; letter++) ALL_CLASSES.push(`${grade}-${letter}`);
}

// ------------------------------------------------------------
// АДАПТЕР БАЗЫ ДАННЫХ
// ------------------------------------------------------------
// Единый асинхронный интерфейс для двух хранилищ:
//   - Turso (облако, постоянное)  — если заданы TURSO_* переменные
//   - локальный SQLite-файл       — иначе
// Весь остальной код не знает, с какой базой работает.
let db;
let storageDescription;

function createDatabase() {
  const tursoUrl = process.env.TURSO_DATABASE_URL;

  if (tursoUrl) {
    let createClient;
    try {
      // «web»-версия клиента — без нативных модулей, надёжно ставится на Render
      ({ createClient } = require('@libsql/client/web'));
    } catch (e) {
      ({ createClient } = require('@libsql/client'));
    }
    const client = createClient({ url: tursoUrl, authToken: process.env.TURSO_AUTH_TOKEN });
    storageDescription = 'Turso (облачная база, данные постоянные)';

    return {
      async all(sql, args = []) {
        const r = await client.execute({ sql, args: args.map((a) => (a === undefined ? null : a)) });
        // Собираем обычные объекты по именам колонок
        return r.rows.map((row) => Object.fromEntries(r.columns.map((c, i) => [c, row[i]])));
      },
      async run(sql, args = []) {
        const r = await client.execute({ sql, args: args.map((a) => (a === undefined ? null : a)) });
        return {
          changes: Number(r.rowsAffected || 0),
          lastInsertRowid: r.lastInsertRowid != null ? Number(r.lastInsertRowid) : null,
        };
      },
    };
  }

  const { DatabaseSync } = require('node:sqlite');
  const sqlite = new DatabaseSync(DB_PATH);
  const cache = new Map();
  const prep = (sql) => {
    let st = cache.get(sql);
    if (!st) { st = sqlite.prepare(sql); cache.set(sql, st); }
    return st;
  };
  storageDescription = `локальный файл ${DB_PATH}`;

  return {
    async all(sql, args = []) {
      return prep(sql).all(...args.map((a) => (a === undefined ? null : a))).map((r) => ({ ...r }));
    },
    async run(sql, args = []) {
      const r = prep(sql).run(...args.map((a) => (a === undefined ? null : a)));
      return { changes: Number(r.changes), lastInsertRowid: Number(r.lastInsertRowid) };
    },
  };
}

const dbAll = (sql, args) => db.all(sql, args);
const dbGet = async (sql, args) => (await db.all(sql, args))[0];
const dbRun = (sql, args) => db.run(sql, args);

const SCHEMA = [
  `CREATE TABLE IF NOT EXISTS users (
    email TEXT PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    display_name TEXT,
    avatar_data TEXT,
    class_name TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    password_salt TEXT NOT NULL,
    theme TEXT NOT NULL DEFAULT 'dark',
    notifications_enabled INTEGER NOT NULL DEFAULT 1,
    created_at INTEGER NOT NULL
  )`,
  `CREATE TABLE IF NOT EXISTS sessions (
    token TEXT PRIMARY KEY,
    email TEXT NOT NULL,
    created_at INTEGER NOT NULL
  )`,
  `CREATE TABLE IF NOT EXISTS direct_messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    conversation_key TEXT NOT NULL,
    from_email TEXT NOT NULL,
    text TEXT NOT NULL,
    timestamp INTEGER NOT NULL,
    edited_at INTEGER
  )`,
  `CREATE INDEX IF NOT EXISTS idx_direct_conv ON direct_messages (conversation_key, id)`,
  `CREATE TABLE IF NOT EXISTS class_chat_members (
    class_name TEXT NOT NULL,
    email TEXT NOT NULL,
    joined_at INTEGER NOT NULL,
    PRIMARY KEY (class_name, email)
  )`,
  `CREATE TABLE IF NOT EXISTS class_chat_messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    class_name TEXT NOT NULL,
    from_email TEXT NOT NULL,
    text TEXT NOT NULL,
    timestamp INTEGER NOT NULL,
    edited_at INTEGER
  )`,
  `CREATE INDEX IF NOT EXISTS idx_class_msgs ON class_chat_messages (class_name, id)`,
  `CREATE TABLE IF NOT EXISTS message_reactions (
    kind TEXT NOT NULL,
    message_id INTEGER NOT NULL,
    email TEXT NOT NULL,
    emoji TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    PRIMARY KEY (kind, message_id, email)
  )`,
];

// Для баз, созданных старыми версиями: добавляем недостающие колонки.
// Если колонка уже есть — база выдаст ошибку, её просто игнорируем.
const MIGRATIONS = [
  `ALTER TABLE users ADD COLUMN display_name TEXT`,
  `ALTER TABLE users ADD COLUMN avatar_data TEXT`,
  `ALTER TABLE users ADD COLUMN theme TEXT NOT NULL DEFAULT 'dark'`,
  `ALTER TABLE users ADD COLUMN notifications_enabled INTEGER NOT NULL DEFAULT 1`,
  `ALTER TABLE direct_messages ADD COLUMN edited_at INTEGER`,
  `ALTER TABLE class_chat_messages ADD COLUMN edited_at INTEGER`,
];

async function initDatabase() {
  db = createDatabase();
  for (const sql of SCHEMA) await dbRun(sql);
  for (const sql of MIGRATIONS) {
    try { await dbRun(sql); } catch (e) { /* колонка уже существует — это нормально */ }
  }
  console.log(`📦 База данных: ${storageDescription}`);
  if (!process.env.TURSO_DATABASE_URL && process.env.RENDER) {
    console.log('⚠️  ВНИМАНИЕ: сервер работает на Render БЕЗ Turso — локальный файл на бесплатном');
    console.log('    тарифе Render стирается при каждом перезапуске. Задайте TURSO_DATABASE_URL и TURSO_AUTH_TOKEN.');
  }
}

// ------------------------------------------------------------
// ПАРОЛИ (scrypt + соль; асинхронно, чтобы не блокировать сервер)
// ------------------------------------------------------------
async function hashPassword(password, salt) {
  return (await scrypt(password, salt, 64)).toString('hex');
}

async function createPasswordRecord(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = await hashPassword(password, salt);
  return { hash, salt };
}

async function verifyPassword(password, salt, expectedHash) {
  const actual = Buffer.from(await hashPassword(password, salt), 'hex');
  const expected = Buffer.from(expectedHash, 'hex');
  if (actual.length !== expected.length) return false;
  return crypto.timingSafeEqual(actual, expected);
}

// ------------------------------------------------------------
// ВРЕМЕННЫЕ ДАННЫЕ В ПАМЯТИ
// ------------------------------------------------------------
const pendingCodes = new Map();         // email -> { code, expiresAt }
const pendingRegistrations = new Map(); // email -> { className, username }
const clients = new Map();              // clientId -> { socket, email, buf, fragments, queue }

function conversationKey(a, b) { return [a, b].sort().join('|'); }
function escapeLike(s) { return s.replace(/[\\%_]/g, (c) => '\\' + c); }
function normEmail(v) { return String(v || '').trim().toLowerCase(); }

// ------------------------------------------------------------
// ПОЛЬЗОВАТЕЛИ И СЕССИИ
// ------------------------------------------------------------
const getUserByEmail = (email) => dbGet('SELECT * FROM users WHERE email = ?', [email]);
const getUserByUsername = (username) => dbGet('SELECT * FROM users WHERE username = ?', [username]);

function toPublicUser(row) {
  return {
    email: row.email,
    username: row.username,
    displayName: row.display_name || row.username,
    avatarData: row.avatar_data || null,
    className: row.class_name,
    theme: row.theme || 'dark',
    notificationsEnabled: Number(row.notifications_enabled) !== 0,
  };
}

async function createSession(email) {
  const token = crypto.randomBytes(32).toString('hex');
  await dbRun('INSERT INTO sessions (token, email, created_at) VALUES (?, ?, ?)', [token, email, Date.now()]);
  return token;
}

// ------------------------------------------------------------
// HTTP-СЕРВЕР
// ------------------------------------------------------------
const server = http.createServer((req, res) => {
  const url = (req.url || '/').split('?')[0];
  if (url === '/' || url === '/index.html') {
    const filePath = path.join(__dirname, 'client', 'index.html');
    fs.readFile(filePath, (err, data) => {
      if (err) { res.writeHead(500, { 'Content-Type': 'text/plain; charset=utf-8' }); res.end('Не удалось загрузить клиент'); return; }
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-cache' });
      res.end(data);
    });
  } else if (url === '/health') {
    res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
    res.end('ok');
  } else {
    res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
    res.end('Не найдено');
  }
});

// ------------------------------------------------------------
// WEBSOCKET: рукопожатие
// ------------------------------------------------------------
server.on('upgrade', (req, socket) => {
  const key = req.headers['sec-websocket-key'];
  if (!key) { socket.destroy(); return; }

  const acceptKey = crypto.createHash('sha1').update(key + WEBSOCKET_MAGIC_STRING).digest('base64');
  socket.write([
    'HTTP/1.1 101 Switching Protocols',
    'Upgrade: websocket',
    'Connection: Upgrade',
    `Sec-WebSocket-Accept: ${acceptKey}`,
    '\r\n',
  ].join('\r\n'));

  socket.setNoDelay(true);

  const clientId = crypto.randomUUID();
  clients.set(clientId, {
    socket,
    email: null,
    buf: Buffer.alloc(0),
    fragments: [],
    fragSize: 0,
    queue: Promise.resolve(),
  });

  socket.on('data', (chunk) => onSocketData(clientId, chunk));
  socket.on('close', () => clients.delete(clientId));
  socket.on('error', () => clients.delete(clientId));
});

// ------------------------------------------------------------
// WEBSOCKET: кадры
// ------------------------------------------------------------
// Данные по TCP приходят кусками произвольного размера: один кадр может быть
// разрезан на несколько кусков, а в одном куске может быть несколько кадров.
// Поэтому накапливаем байты в буфер клиента и вынимаем из него только
// полностью пришедшие кадры.
function onSocketData(clientId, chunk) {
  const client = clients.get(clientId);
  if (!client) return;

  client.buf = client.buf.length ? Buffer.concat([client.buf, chunk]) : chunk;

  while (true) {
    const buf = client.buf;
    if (buf.length < 2) return;

    const fin = (buf[0] & 0x80) !== 0;
    const opcode = buf[0] & 0x0f;
    const masked = (buf[1] & 0x80) !== 0;
    let len = buf[1] & 0x7f;
    let offset = 2;

    if (len === 126) {
      if (buf.length < 4) return;
      len = buf.readUInt16BE(2);
      offset = 4;
    } else if (len === 127) {
      if (buf.length < 10) return;
      len = Number(buf.readBigUInt64BE(2));
      offset = 10;
    }

    if (len > MAX_FRAME) { client.socket.destroy(); return; }

    let maskKey = null;
    if (masked) {
      if (buf.length < offset + 4) return;
      maskKey = Buffer.from(buf.subarray(offset, offset + 4));
      offset += 4;
    }

    if (buf.length < offset + len) return; // кадр ещё не пришёл целиком

    const payload = Buffer.from(buf.subarray(offset, offset + len));
    client.buf = buf.subarray(offset + len);
    if (masked) for (let i = 0; i < len; i++) payload[i] ^= maskKey[i & 3];

    if (opcode === 0x8) { // закрытие соединения
      try { client.socket.write(Buffer.from([0x88, 0x00])); } catch (e) { /* уже закрыт */ }
      client.socket.end();
      return;
    }
    if (opcode === 0x9) { // ping -> отвечаем pong с теми же данными
      if (len < 126) client.socket.write(Buffer.concat([Buffer.from([0x8a, len]), payload]));
      continue;
    }
    if (opcode === 0xa) continue; // pong — игнорируем

    if (opcode === 0x1 || opcode === 0x2) { client.fragments = []; client.fragSize = 0; client.fragOpcode = opcode; }
    client.fragments.push(payload);
    client.fragSize += payload.length;
    if (client.fragSize > MAX_FRAME) { client.socket.destroy(); return; }

    if (fin) {
      const full = Buffer.concat(client.fragments);
      client.fragments = [];
      client.fragSize = 0;
      if (client.fragOpcode === 0x1) dispatch(clientId, full.toString('utf8'));
    }
  }
}

function encodeFrame(message) {
  const payload = Buffer.from(JSON.stringify(message), 'utf8');
  const length = payload.length;
  let header;

  if (length < 126) header = Buffer.from([0x81, length]);
  else if (length < 65536) {
    header = Buffer.alloc(4);
    header[0] = 0x81; header[1] = 126;
    header.writeUInt16BE(length, 2);
  } else {
    header = Buffer.alloc(10);
    header[0] = 0x81; header[1] = 127;
    header.writeBigUInt64BE(BigInt(length), 2);
  }
  return Buffer.concat([header, payload]);
}

function sendTo(clientId, message) {
  const client = clients.get(clientId);
  if (!client || client.socket.destroyed) return;
  client.socket.write(encodeFrame(message));
}

// Отправить всем открытым вкладкам/устройствам одного аккаунта
function sendToEmail(email, message) {
  if (!email) return;
  const frame = encodeFrame(message);
  for (const c of clients.values()) {
    if (c.email === email && !c.socket.destroyed) c.socket.write(frame);
  }
}

// Раз в 25 секунд "пингуем" всех: так прокси Render не закрывает
// простаивающие WebSocket-соединения.
const PING_FRAME = Buffer.from([0x89, 0x00]);
setInterval(() => {
  for (const c of clients.values()) if (!c.socket.destroyed) c.socket.write(PING_FRAME);
}, 25000);

// ------------------------------------------------------------
// РОУТЕР ВХОДЯЩИХ СООБЩЕНИЙ
// ------------------------------------------------------------
function dispatch(clientId, text) {
  let data;
  try { data = JSON.parse(text); } catch (e) { return; }
  if (!data || typeof data !== 'object') return;

  const fn = HANDLERS[data.type];
  if (!fn) return;

  const client = clients.get(clientId);
  if (!client) return;

  // Сообщения одного клиента обрабатываем строго по очереди (важно для порядка),
  // а любая ошибка не должна ронять весь сервер.
  client.queue = client.queue
    .then(() => fn(clientId, data))
    .catch((err) => {
      console.error(`[ошибка] ${data.type}:`, err);
      sendTo(clientId, { type: 'error', context: data.type, message: 'Ошибка сервера, попробуйте ещё раз' });
    });
}

function authEmail(clientId) {
  const client = clients.get(clientId);
  return client && client.email ? client.email : null;
}

function sendError(clientId, context, message) {
  sendTo(clientId, { type: 'error', context, message });
}

// ============================================================
// РЕГИСТРАЦИЯ И ВХОД
// ============================================================
async function handleRequestCode(clientId, data) {
  const email = normEmail(data.email);

  if (!EMAIL_RE.test(email)) {
    return sendError(clientId, 'request_code', 'Разрешена только почта @gmail.com');
  }

  const code = String(Math.floor(100000 + Math.random() * 900000));
  pendingCodes.set(email, { code, expiresAt: Date.now() + 10 * 60 * 1000 });

  // ⚠️ ЗДЕСЬ В РЕАЛЬНОМ ПРОЕКТЕ НУЖНО ОТПРАВИТЬ EMAIL.
  // Пока код выводится в консоль и присылается клиенту для тестирования.
  console.log(`[КОД ПОДТВЕРЖДЕНИЯ] ${email} -> ${code}`);

  sendTo(clientId, { type: 'code_sent', email, devCode: code });
}

async function handleVerifyCode(clientId, data) {
  const email = normEmail(data.email);
  const code = String(data.code || '').trim();

  const pending = pendingCodes.get(email);
  if (!pending) return sendError(clientId, 'verify_code', 'Сначала запросите код');
  if (Date.now() > pending.expiresAt) { pendingCodes.delete(email); return sendError(clientId, 'verify_code', 'Код истёк, запросите новый'); }
  if (pending.code !== code) return sendError(clientId, 'verify_code', 'Неверный код');

  pendingCodes.delete(email);

  if (await getUserByEmail(email)) {
    return sendTo(clientId, { type: 'code_verified_existing', email });
  }

  pendingRegistrations.set(email, {});
  sendTo(clientId, { type: 'code_verified', email });
}

async function handleCheckUsername(clientId, data) {
  const username = String(data.username || '').trim().toLowerCase();

  if (!USERNAME_RE.test(username)) {
    return sendTo(clientId, { type: 'username_check_result', username, available: false, reason: 'От 3 до 12 символов: латинские буквы, цифры, нижнее подчёркивание' });
  }

  const taken = !!(await getUserByUsername(username));
  sendTo(clientId, { type: 'username_check_result', username, available: !taken, reason: taken ? 'Это имя уже занято' : null });
}

async function handleSetClassAndUsername(clientId, data) {
  const email = normEmail(data.email);
  const className = String(data.className || '').trim();
  const username = String(data.username || '').trim().toLowerCase();

  if (!pendingRegistrations.has(email)) {
    return sendError(clientId, 'set_class_and_username', 'Сессия регистрации истекла, начните заново');
  }
  if (!USERNAME_RE.test(username)) return sendError(clientId, 'set_class_and_username', 'Некорректный username');
  if (await getUserByUsername(username)) return sendError(clientId, 'set_class_and_username', 'Username уже занят');
  if (!ALL_CLASSES.includes(className)) return sendError(clientId, 'set_class_and_username', 'Не выбран класс');

  pendingRegistrations.set(email, { className, username });
  sendTo(clientId, { type: 'class_and_username_set' });
}

async function handleCompleteRegistrationPassword(clientId, data) {
  const email = normEmail(data.email);
  const password = String(data.password || '');

  const pending = pendingRegistrations.get(email);
  if (!pending || !pending.username || !pending.className) {
    return sendError(clientId, 'complete_registration_password', 'Сессия регистрации истекла, начните заново');
  }
  if (password.length < 6) {
    return sendError(clientId, 'complete_registration_password', 'Пароль должен быть не короче 6 символов');
  }

  const { hash, salt } = await createPasswordRecord(password);

  try {
    await dbRun(
      'INSERT INTO users (email, username, class_name, password_hash, password_salt, created_at) VALUES (?, ?, ?, ?, ?, ?)',
      [email, pending.username, pending.className, hash, salt, Date.now()]
    );
  } catch (e) {
    return sendError(clientId, 'complete_registration_password', 'Username или почта уже заняты, начните заново');
  }

  pendingRegistrations.delete(email);

  const client = clients.get(clientId);
  if (client) client.email = email;

  const token = await createSession(email);
  const row = await getUserByEmail(email);
  sendTo(clientId, { type: 'registration_complete', user: toPublicUser(row), sessionToken: token });
}

async function handleLoginPassword(clientId, data) {
  const email = normEmail(data.email);
  const password = String(data.password || '');

  const row = await getUserByEmail(email);
  if (!row) return sendError(clientId, 'login_password', 'Пользователь не найден');

  if (!(await verifyPassword(password, row.password_salt, row.password_hash))) {
    return sendError(clientId, 'login_password', 'Неверный пароль');
  }

  const client = clients.get(clientId);
  if (client) client.email = email;

  const token = await createSession(email);
  sendTo(clientId, { type: 'login_success', user: toPublicUser(row), sessionToken: token });
}

async function handleResumeSession(clientId, data) {
  const token = String(data.token || '');
  const session = await dbGet('SELECT * FROM sessions WHERE token = ?', [token]);
  if (!session) return sendTo(clientId, { type: 'session_invalid' });

  if (Date.now() - Number(session.created_at) > SESSION_TTL_MS) {
    await dbRun('DELETE FROM sessions WHERE token = ?', [token]);
    return sendTo(clientId, { type: 'session_invalid' });
  }

  const row = await getUserByEmail(session.email);
  if (!row) return sendTo(clientId, { type: 'session_invalid' });

  const client = clients.get(clientId);
  if (client) client.email = session.email;

  sendTo(clientId, { type: 'login_success', user: toPublicUser(row), sessionToken: token });
}

async function handleLogout(clientId, data) {
  const token = String(data.token || '');
  if (token) await dbRun('DELETE FROM sessions WHERE token = ?', [token]);
  const client = clients.get(clientId);
  if (client) client.email = null;
}

// ============================================================
// ПОИСК
// ============================================================
async function handleSearchUsers(clientId, data) {
  const email = authEmail(clientId);
  const query = String(data.query || '').trim().toLowerCase();

  const myRow = email ? await getUserByEmail(email) : null;
  const results = [];

  // Чат класса — первым пунктом, если запрос пустой или совпадает с названием класса / словом "класс"
  if (myRow) {
    const classLabel = `${myRow.class_name} класс`;
    if (!query || myRow.class_name.toLowerCase().includes(query) || 'класс'.includes(query)) {
      results.push({ type: 'class_chat', className: myRow.class_name, label: classLabel });
    }
  }

  if (query) {
    const rows = await dbAll(
      "SELECT email, username, class_name, display_name, avatar_data FROM users WHERE username LIKE ? ESCAPE '\\' LIMIT 20",
      [`%${escapeLike(query)}%`]
    );
    for (const r of rows) {
      if (r.email === email) continue;
      results.push({
        type: 'user',
        email: r.email,
        username: r.username,
        displayName: r.display_name || r.username,
        avatarData: r.avatar_data || null,
        className: r.class_name,
      });
    }
  }

  sendTo(clientId, { type: 'search_results', results });
}

// ============================================================
// СООБЩЕНИЯ: общие функции
// ============================================================
const TABLES = { direct: 'direct_messages', class: 'class_chat_messages' };

function formatMessage(kind, row, reactions) {
  return {
    id: Number(row.id),
    kind,
    from: row.from_email,
    fromUsername: row.username || null,
    fromDisplayName: row.display_name || row.username || null,
    text: row.text,
    timestamp: Number(row.timestamp),
    editedAt: row.edited_at ? Number(row.edited_at) : null,
    reactions: reactions || {},
  };
}

// Реакции для набора сообщений: id -> { "👍": [email, ...], ... }
async function loadReactions(kind, ids) {
  const map = new Map();
  for (let i = 0; i < ids.length; i += 400) {
    const chunk = ids.slice(i, i + 400);
    const placeholders = chunk.map(() => '?').join(',');
    const rows = await dbAll(
      `SELECT message_id, emoji, email FROM message_reactions WHERE kind = ? AND message_id IN (${placeholders})`,
      [kind, ...chunk]
    );
    for (const r of rows) {
      const id = Number(r.message_id);
      if (!map.has(id)) map.set(id, {});
      const obj = map.get(id);
      (obj[r.emoji] = obj[r.emoji] || []).push(r.email);
    }
  }
  return map;
}

async function loadHistory(kind, scope) {
  const where = kind === 'direct' ? 'm.conversation_key = ?' : 'm.class_name = ?';
  const rows = await dbAll(
    `SELECT m.id, m.from_email, m.text, m.timestamp, m.edited_at, u.username, u.display_name
     FROM ${TABLES[kind]} m LEFT JOIN users u ON u.email = m.from_email
     WHERE ${where} ORDER BY m.id DESC LIMIT ?`,
    [scope, HISTORY_LIMIT]
  );
  rows.reverse();
  const reactions = await loadReactions(kind, rows.map((r) => Number(r.id)));
  return rows.map((r) => formatMessage(kind, r, reactions.get(Number(r.id))));
}

async function getRawMessage(kind, id) {
  if (!TABLES[kind] || !Number.isInteger(id)) return null;
  return dbGet(`SELECT * FROM ${TABLES[kind]} WHERE id = ?`, [id]);
}

const isClassMember = async (className, email) =>
  !!(await dbGet('SELECT 1 AS x FROM class_chat_members WHERE class_name = ? AND email = ?', [className, email]));

// Разослать событие участникам чата, к которому относится сообщение.
// Для личных чатов каждому собеседнику подставляем "withEmail" — кто для него собеседник.
async function broadcastMessageEvent(kind, row, payload) {
  if (kind === 'direct') {
    const [a, b] = row.conversation_key.split('|');
    sendToEmail(a, { ...payload, withEmail: b });
    if (b !== a) sendToEmail(b, { ...payload, withEmail: a });
  } else {
    const members = await dbAll('SELECT email FROM class_chat_members WHERE class_name = ?', [row.class_name]);
    for (const m of members) sendToEmail(m.email, { ...payload, className: row.class_name });
  }
}

function parseKind(v) { return v === 'direct' || v === 'class' ? v : null; }

// ============================================================
// ЛИЧНЫЕ ЧАТЫ
// ============================================================
async function handleOpenConversation(clientId, data) {
  const email = authEmail(clientId);
  if (!email) return;

  const otherEmail = normEmail(data.withEmail);
  const messages = await loadHistory('direct', conversationKey(email, otherEmail));
  sendTo(clientId, { type: 'conversation_history', withEmail: otherEmail, messages });
}

async function handleSendDirectMessage(clientId, data) {
  const email = authEmail(clientId);
  if (!email) return;

  const toEmail = normEmail(data.toEmail);
  const text = String(data.text || '').trim().slice(0, MAX_TEXT);
  if (!text) return;

  const recipient = await getUserByEmail(toEmail);
  if (!recipient) return sendError(clientId, 'send_direct_message', 'Пользователь не найден');

  const fromUser = await getUserByEmail(email);
  const timestamp = Date.now();
  const key = conversationKey(email, toEmail);

  const r = await dbRun(
    'INSERT INTO direct_messages (conversation_key, from_email, text, timestamp) VALUES (?, ?, ?, ?)',
    [key, email, text, timestamp]
  );

  const message = formatMessage('direct', {
    id: r.lastInsertRowid, from_email: email, text, timestamp, edited_at: null,
    username: fromUser.username, display_name: fromUser.display_name,
  });

  sendToEmail(email, { type: 'direct_message', withEmail: toEmail, message });
  if (toEmail !== email) sendToEmail(toEmail, { type: 'direct_message', withEmail: email, message });
}

async function handleGetChatList(clientId) {
  const email = authEmail(clientId);
  if (!email) return;

  const e = escapeLike(email);
  const rows = await dbAll(
    `SELECT m.conversation_key, m.text, m.timestamp
     FROM direct_messages m
     JOIN (
       SELECT MAX(id) AS mid FROM direct_messages
       WHERE conversation_key LIKE ? ESCAPE '\\' OR conversation_key LIKE ? ESCAPE '\\'
       GROUP BY conversation_key
     ) x ON x.mid = m.id
     ORDER BY m.timestamp DESC`,
    [`${e}|%`, `%|${e}`]
  );

  const chats = [];
  for (const r of rows) {
    const [a, b] = r.conversation_key.split('|');
    if (a !== email && b !== email) continue; // строгая проверка: переписка точно этого пользователя
    const otherEmail = a === email ? b : a;
    const other = await getUserByEmail(otherEmail);
    if (!other) continue;

    chats.push({
      withEmail: otherEmail,
      withUsername: other.username,
      withDisplayName: other.display_name || other.username,
      withAvatarData: other.avatar_data || null,
      lastMessageText: r.text,
      lastMessageTime: Number(r.timestamp),
    });
  }

  sendTo(clientId, { type: 'chat_list', chats });
}

// ============================================================
// ЧАТ КЛАССА
// ============================================================
async function handleJoinClassChat(clientId, data) {
  const email = authEmail(clientId);
  if (!email) return;

  const className = String(data.className || '').trim();
  if (!ALL_CLASSES.includes(className)) return;

  await dbRun('INSERT OR IGNORE INTO class_chat_members (class_name, email, joined_at) VALUES (?, ?, ?)', [className, email, Date.now()]);
  sendTo(clientId, { type: 'class_chat_joined', className });
}

async function handleOpenClassChat(clientId, data) {
  const email = authEmail(clientId);
  if (!email) return;

  const className = String(data.className || '').trim();
  if (!(await isClassMember(className, email))) {
    return sendError(clientId, 'open_class_chat', 'Сначала вступите в чат класса');
  }

  const messages = await loadHistory('class', className);
  sendTo(clientId, { type: 'class_chat_history', className, messages });
}

async function handleSendClassMessage(clientId, data) {
  const email = authEmail(clientId);
  if (!email) return;

  const className = String(data.className || '').trim();
  const text = String(data.text || '').trim().slice(0, MAX_TEXT);
  if (!text) return;
  if (!(await isClassMember(className, email))) return;

  const fromUser = await getUserByEmail(email);
  const timestamp = Date.now();
  const r = await dbRun(
    'INSERT INTO class_chat_messages (class_name, from_email, text, timestamp) VALUES (?, ?, ?, ?)',
    [className, email, text, timestamp]
  );

  const message = formatMessage('class', {
    id: r.lastInsertRowid, from_email: email, text, timestamp, edited_at: null,
    username: fromUser.username, display_name: fromUser.display_name,
  });

  const members = await dbAll('SELECT email FROM class_chat_members WHERE class_name = ?', [className]);
  for (const m of members) sendToEmail(m.email, { type: 'class_message', className, message });
}

// ============================================================
// РЕДАКТИРОВАНИЕ, УДАЛЕНИЕ, РЕАКЦИИ
// ============================================================
async function handleEditMessage(clientId, data) {
  const email = authEmail(clientId);
  if (!email) return;

  const kind = parseKind(data.kind);
  const id = Number(data.id);
  const text = String(data.text || '').trim().slice(0, MAX_TEXT);
  if (!kind || !text) return sendError(clientId, 'edit_message', 'Сообщение не может быть пустым');

  const row = await getRawMessage(kind, id);
  if (!row || row.from_email !== email) {
    return sendError(clientId, 'edit_message', 'Можно редактировать только свои сообщения');
  }

  const editedAt = Date.now();
  await dbRun(`UPDATE ${TABLES[kind]} SET text = ?, edited_at = ? WHERE id = ?`, [text, editedAt, id]);
  await broadcastMessageEvent(kind, row, { type: 'message_edited', kind, id, text, editedAt });
}

async function handleDeleteMessage(clientId, data) {
  const email = authEmail(clientId);
  if (!email) return;

  const kind = parseKind(data.kind);
  const id = Number(data.id);
  if (!kind) return;

  const row = await getRawMessage(kind, id);
  if (!row || row.from_email !== email) {
    return sendError(clientId, 'delete_message', 'Можно удалять только свои сообщения');
  }

  await dbRun(`DELETE FROM ${TABLES[kind]} WHERE id = ?`, [id]);
  await dbRun('DELETE FROM message_reactions WHERE kind = ? AND message_id = ?', [kind, id]);
  await broadcastMessageEvent(kind, row, { type: 'message_deleted', kind, id });
}

async function handleReactMessage(clientId, data) {
  const email = authEmail(clientId);
  if (!email) return;

  const kind = parseKind(data.kind);
  const id = Number(data.id);
  const emoji = String(data.emoji || '');
  if (!kind || !ALLOWED_REACTIONS.includes(emoji)) return;

  const row = await getRawMessage(kind, id);
  if (!row) return;

  // Реагировать может только участник этого чата
  if (kind === 'direct') {
    const [a, b] = row.conversation_key.split('|');
    if (email !== a && email !== b) return;
  } else if (!(await isClassMember(row.class_name, email))) {
    return;
  }

  const existing = await dbGet(
    'SELECT emoji FROM message_reactions WHERE kind = ? AND message_id = ? AND email = ?',
    [kind, id, email]
  );

  if (existing && existing.emoji === emoji) {
    // Повторное нажатие на ту же реакцию — снимает её
    await dbRun('DELETE FROM message_reactions WHERE kind = ? AND message_id = ? AND email = ?', [kind, id, email]);
  } else {
    await dbRun(
      'INSERT OR REPLACE INTO message_reactions (kind, message_id, email, emoji, created_at) VALUES (?, ?, ?, ?, ?)',
      [kind, id, email, emoji, Date.now()]
    );
  }

  const reactions = (await loadReactions(kind, [id])).get(id) || {};
  await broadcastMessageEvent(kind, row, { type: 'reactions_updated', kind, id, reactions });
}

// ============================================================
// НАСТРОЙКИ ПРОФИЛЯ
// ============================================================
async function sendProfile(clientId, email) {
  sendTo(clientId, { type: 'profile_updated', user: toPublicUser(await getUserByEmail(email)) });
}

async function handleUpdateDisplayName(clientId, data) {
  const email = authEmail(clientId);
  if (!email) return;

  const displayName = String(data.displayName || '').trim().slice(0, 40);
  if (!displayName) return sendError(clientId, 'update_display_name', 'Имя не может быть пустым');

  await dbRun('UPDATE users SET display_name = ? WHERE email = ?', [displayName, email]);
  await sendProfile(clientId, email);
}

async function handleUpdateAvatar(clientId, data) {
  const email = authEmail(clientId);
  if (!email) return;

  const avatarData = data.avatarData ? String(data.avatarData) : null;

  if (avatarData && !/^data:image\/(png|jpeg|jpg|webp|gif);base64,/.test(avatarData)) {
    return sendError(clientId, 'update_avatar', 'Неподдерживаемый формат изображения');
  }
  if (avatarData && avatarData.length > 2 * 1024 * 1024) {
    return sendError(clientId, 'update_avatar', 'Изображение слишком большое (максимум ~1.5 МБ)');
  }

  await dbRun('UPDATE users SET avatar_data = ? WHERE email = ?', [avatarData, email]);
  await sendProfile(clientId, email);
}

async function handleUpdateUsername(clientId, data) {
  const email = authEmail(clientId);
  if (!email) return;

  const username = String(data.username || '').trim().toLowerCase();
  if (!USERNAME_RE.test(username)) {
    return sendError(clientId, 'update_username', 'От 3 до 12 символов: латинские буквы, цифры, нижнее подчёркивание');
  }

  const existing = await getUserByUsername(username);
  if (existing && existing.email !== email) return sendError(clientId, 'update_username', 'Это имя уже занято');

  try {
    await dbRun('UPDATE users SET username = ? WHERE email = ?', [username, email]);
  } catch (e) {
    return sendError(clientId, 'update_username', 'Это имя уже занято');
  }
  await sendProfile(clientId, email);
}

async function handleUpdateClass(clientId, data) {
  const email = authEmail(clientId);
  if (!email) return;

  const className = String(data.className || '').trim();
  if (!ALL_CLASSES.includes(className)) return sendError(clientId, 'update_class', 'Некорректный класс');

  await dbRun('UPDATE users SET class_name = ? WHERE email = ?', [className, email]);
  await sendProfile(clientId, email);
}

async function handleUpdatePassword(clientId, data) {
  const email = authEmail(clientId);
  if (!email) return;

  const currentPassword = String(data.currentPassword || '');
  const newPassword = String(data.newPassword || '');

  const row = await getUserByEmail(email);
  if (!(await verifyPassword(currentPassword, row.password_salt, row.password_hash))) {
    return sendError(clientId, 'update_password', 'Текущий пароль неверен');
  }
  if (newPassword.length < 6) {
    return sendError(clientId, 'update_password', 'Новый пароль должен быть не короче 6 символов');
  }

  const { hash, salt } = await createPasswordRecord(newPassword);
  await dbRun('UPDATE users SET password_hash = ?, password_salt = ? WHERE email = ?', [hash, salt, email]);
  sendTo(clientId, { type: 'password_updated' });
}

async function handleUpdateTheme(clientId, data) {
  const email = authEmail(clientId);
  if (!email) return;

  await dbRun('UPDATE users SET theme = ? WHERE email = ?', [data.theme === 'light' ? 'light' : 'dark', email]);
  await sendProfile(clientId, email);
}

async function handleUpdateNotifications(clientId, data) {
  const email = authEmail(clientId);
  if (!email) return;

  await dbRun('UPDATE users SET notifications_enabled = ? WHERE email = ?', [data.enabled ? 1 : 0, email]);
  await sendProfile(clientId, email);
}

// ------------------------------------------------------------
// ТАБЛИЦА ОБРАБОТЧИКОВ
// ------------------------------------------------------------
const HANDLERS = {
  request_code: handleRequestCode,
  verify_code: handleVerifyCode,
  check_username: handleCheckUsername,
  set_class_and_username: handleSetClassAndUsername,
  complete_registration_password: handleCompleteRegistrationPassword,
  login_password: handleLoginPassword,
  resume_session: handleResumeSession,
  logout: handleLogout,
  search_users: handleSearchUsers,
  open_conversation: handleOpenConversation,
  send_direct_message: handleSendDirectMessage,
  get_chat_list: handleGetChatList,
  join_class_chat: handleJoinClassChat,
  open_class_chat: handleOpenClassChat,
  send_class_message: handleSendClassMessage,
  edit_message: handleEditMessage,
  delete_message: handleDeleteMessage,
  react_message: handleReactMessage,
  update_display_name: handleUpdateDisplayName,
  update_avatar: handleUpdateAvatar,
  update_username: handleUpdateUsername,
  update_class: handleUpdateClass,
  update_password: handleUpdatePassword,
  update_theme: handleUpdateTheme,
  update_notifications: handleUpdateNotifications,
};

// Необработанная ошибка в одном запросе не должна останавливать весь сервер
process.on('unhandledRejection', (err) => console.error('[unhandledRejection]', err));
process.on('uncaughtException', (err) => console.error('[uncaughtException]', err));

// ------------------------------------------------------------
// ЗАПУСК
// ------------------------------------------------------------
async function main() {
  await initDatabase();
  server.listen(PORT, '0.0.0.0', () => {
    console.log(`✅ Сервер school347 запущен: http://localhost:${PORT}`);
  });
}

main().catch((err) => {
  console.error('Не удалось запустить сервер:', err);
  process.exit(1);
});
