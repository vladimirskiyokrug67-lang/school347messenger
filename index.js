// ============================================================
// СЕРВЕР МЕССЕНДЖЕРА "school347" — v0.3
// ============================================================
// Только встроенные модули Node.js — установка пакетов не нужна.
// Добавлено по сравнению с v0.2:
//   - База данных SQLite (данные не теряются при перезапуске)
//   - Пароли (хранятся в виде хеша, не в открытом виде) + вход по email+пароль
//   - Долгосрочные сессии (токен сохраняется в браузере, код вводить не нужно
//     при каждом входе)
//   - Групповые чаты класса (появляются в Поиске, вступление по кнопке)
// ============================================================

const http = require('http');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { DatabaseSync } = require('node:sqlite');

const PORT = 8080;
const WEBSOCKET_MAGIC_STRING = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11';
const DB_PATH = path.join(__dirname, 'school347.db');

// Список допустимых классов: 1-1, 1-2, 1-3, 2-1, ... 11-3
const ALL_CLASSES = [];
for (let grade = 1; grade <= 11; grade++) {
  for (let letter = 1; letter <= 3; letter++) ALL_CLASSES.push(`${grade}-${letter}`);
}

// ------------------------------------------------------------
// БАЗА ДАННЫХ
// ------------------------------------------------------------
const db = new DatabaseSync(DB_PATH);

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
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
  );

  CREATE TABLE IF NOT EXISTS sessions (
    token TEXT PRIMARY KEY,
    email TEXT NOT NULL,
    created_at INTEGER NOT NULL
  );

  CREATE TABLE IF NOT EXISTS direct_messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    conversation_key TEXT NOT NULL,
    from_email TEXT NOT NULL,
    text TEXT NOT NULL,
    timestamp INTEGER NOT NULL
  );

  CREATE TABLE IF NOT EXISTS class_chat_members (
    class_name TEXT NOT NULL,
    email TEXT NOT NULL,
    joined_at INTEGER NOT NULL,
    PRIMARY KEY (class_name, email)
  );

  CREATE TABLE IF NOT EXISTS class_chat_messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    class_name TEXT NOT NULL,
    from_email TEXT NOT NULL,
    text TEXT NOT NULL,
    timestamp INTEGER NOT NULL
  );
`);

// Плавная миграция для баз, созданных ДО этой версии (в них не было
// колонок display_name/avatar_data/theme/notifications_enabled).
// Если колонка уже есть, SQLite выдаст ошибку — просто её игнорируем.
function tryAddColumn(sql) {
  try { db.exec(sql); } catch (e) { /* колонка уже существует — это нормально */ }
}
tryAddColumn(`ALTER TABLE users ADD COLUMN display_name TEXT`);
tryAddColumn(`ALTER TABLE users ADD COLUMN avatar_data TEXT`);
tryAddColumn(`ALTER TABLE users ADD COLUMN theme TEXT NOT NULL DEFAULT 'dark'`);
tryAddColumn(`ALTER TABLE users ADD COLUMN notifications_enabled INTEGER NOT NULL DEFAULT 1`);

console.log(`📦 База данных: ${DB_PATH}`);

// ------------------------------------------------------------
// ХЕШИРОВАНИЕ ПАРОЛЕЙ
// ------------------------------------------------------------
// Пароль никогда не хранится в открытом виде. Для каждого пользователя
// генерируется случайная "соль", пароль хешируется вместе с ней —
// это защищает от готовых таблиц перебора (rainbow tables).
function hashPassword(password, salt) {
  return crypto.scryptSync(password, salt, 64).toString('hex');
}

function createPasswordRecord(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = hashPassword(password, salt);
  return { hash, salt };
}

function verifyPassword(password, salt, expectedHash) {
  const actualHash = hashPassword(password, salt);
  // timingSafeEqual защищает от атак по времени сравнения
  const a = Buffer.from(actualHash, 'hex');
  const b = Buffer.from(expectedHash, 'hex');
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

// ------------------------------------------------------------
// ВРЕМЕННЫЕ ДАННЫЕ В ПАМЯТИ (не требуют долгого хранения)
// ------------------------------------------------------------
const pendingCodes = new Map();     // email -> { code, expiresAt }
const pendingRegistrations = new Map(); // email -> { className, username } — копится по шагам до установки пароля
const clients = new Map();          // clientId -> { socket, email }

function conversationKey(a, b) { return [a, b].sort().join('|'); }

// ------------------------------------------------------------
// ПОДГОТОВЛЕННЫЕ SQL-ЗАПРОСЫ
// ------------------------------------------------------------
const q = {
  getUserByEmail: db.prepare('SELECT * FROM users WHERE email = ?'),
  getUserByUsername: db.prepare('SELECT * FROM users WHERE username = ?'),
  insertUser: db.prepare(`INSERT INTO users (email, username, class_name, password_hash, password_salt, created_at) VALUES (?, ?, ?, ?, ?, ?)`),
  searchUsers: db.prepare(`SELECT email, username, class_name, display_name, avatar_data FROM users WHERE username LIKE ? LIMIT 20`),

  updateDisplayName: db.prepare(`UPDATE users SET display_name = ? WHERE email = ?`),
  updateAvatar: db.prepare(`UPDATE users SET avatar_data = ? WHERE email = ?`),
  updateUsername: db.prepare(`UPDATE users SET username = ? WHERE email = ?`),
  updateClassName: db.prepare(`UPDATE users SET class_name = ? WHERE email = ?`),
  updatePassword: db.prepare(`UPDATE users SET password_hash = ?, password_salt = ? WHERE email = ?`),
  updateTheme: db.prepare(`UPDATE users SET theme = ? WHERE email = ?`),
  updateNotifications: db.prepare(`UPDATE users SET notifications_enabled = ? WHERE email = ?`),

  insertSession: db.prepare(`INSERT INTO sessions (token, email, created_at) VALUES (?, ?, ?)`),
  getSession: db.prepare(`SELECT * FROM sessions WHERE token = ?`),
  deleteSession: db.prepare(`DELETE FROM sessions WHERE token = ?`),

  insertDirectMessage: db.prepare(`INSERT INTO direct_messages (conversation_key, from_email, text, timestamp) VALUES (?, ?, ?, ?)`),
  getConversation: db.prepare(`SELECT * FROM direct_messages WHERE conversation_key = ? ORDER BY timestamp ASC`),
  getLastMessagesForUser: db.prepare(`
    SELECT conversation_key, from_email, text, timestamp FROM direct_messages
    WHERE id IN (
      SELECT MAX(id) FROM direct_messages WHERE conversation_key LIKE '%' || ? || '%' GROUP BY conversation_key
    )
    ORDER BY timestamp DESC
  `),

  joinClassChat: db.prepare(`INSERT OR IGNORE INTO class_chat_members (class_name, email, joined_at) VALUES (?, ?, ?)`),
  isClassChatMember: db.prepare(`SELECT 1 FROM class_chat_members WHERE class_name = ? AND email = ?`),
  getClassChatMembers: db.prepare(`SELECT email FROM class_chat_members WHERE class_name = ?`),

  insertClassMessage: db.prepare(`INSERT INTO class_chat_messages (class_name, from_email, text, timestamp) VALUES (?, ?, ?, ?)`),
  getClassMessages: db.prepare(`SELECT * FROM class_chat_messages WHERE class_name = ? ORDER BY timestamp ASC`),
  getLastClassMessage: db.prepare(`SELECT * FROM class_chat_messages WHERE class_name = ? ORDER BY timestamp DESC LIMIT 1`),
};

// ------------------------------------------------------------
// HTTP-СЕРВЕР
// ------------------------------------------------------------
const server = http.createServer((req, res) => {
  if (req.url === '/' || req.url === '/index.html') {
    const filePath = path.join(__dirname, '..', 'client', 'index.html');
    fs.readFile(filePath, (err, data) => {
      if (err) { res.writeHead(500); res.end('Не удалось загрузить клиент'); return; }
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end(data);
    });
  } else {
    res.writeHead(404);
    res.end('Не найдено');
  }
});

// ------------------------------------------------------------
// WEBSOCKET HANDSHAKE
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

  const clientId = crypto.randomUUID();
  clients.set(clientId, { socket, email: null });

  socket.on('data', (buffer) => handleIncomingFrame(clientId, buffer));
  socket.on('close', () => clients.delete(clientId));
  socket.on('error', () => clients.delete(clientId));
});

// ------------------------------------------------------------
// WEBSOCKET FRAME КОДИРОВАНИЕ / ДЕКОДИРОВАНИЕ
// ------------------------------------------------------------
function decodeFrame(buffer) {
  const opcode = buffer[0] & 0x0f;
  if (opcode === 0x8) return null;

  const secondByte = buffer[1];
  let payloadLength = secondByte & 0x7f;
  let offset = 2;

  if (payloadLength === 126) { payloadLength = buffer.readUInt16BE(offset); offset += 2; }
  else if (payloadLength === 127) { payloadLength = Number(buffer.readBigUInt64BE(offset)); offset += 8; }

  const maskKey = buffer.slice(offset, offset + 4);
  offset += 4;

  const data = buffer.slice(offset, offset + payloadLength);
  const decoded = Buffer.alloc(payloadLength);
  for (let i = 0; i < payloadLength; i++) decoded[i] = data[i] ^ maskKey[i % 4];
  return decoded.toString('utf8');
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

function findClientIdByEmail(email) {
  // Может быть несколько "мёртвых" записей с тем же email, если старые
  // соединения ещё не успели закрыться — ищем именно живой сокет.
  for (const [id, c] of clients.entries()) {
    if (c.email === email && !c.socket.destroyed) return id;
  }
  return null;
}

// Когда для одного email открывается новое соединение, старые записи
// с этим же email в карте clients считаем "осиротевшими" — иначе
// рассылка сообщений может случайно попасть в мёртвый сокет и потеряться.
function disconnectStaleSessionsForEmail(email, exceptClientId) {
  for (const [id, c] of clients.entries()) {
    if (id !== exceptClientId && c.email === email) {
      c.email = null; // не участвует в поиске/рассылке, но соединение не рвём принудительно
    }
  }
}

// ------------------------------------------------------------
// СЕССИИ
// ------------------------------------------------------------
function createSession(email) {
  const token = crypto.randomBytes(32).toString('hex');
  q.insertSession.run(token, email, Date.now());
  return token;
}

function toPublicUser(row) {
  return {
    email: row.email,
    username: row.username,
    displayName: row.display_name || row.username,
    avatarData: row.avatar_data || null,
    className: row.class_name,
    theme: row.theme || 'dark',
    notificationsEnabled: row.notifications_enabled !== 0,
  };
}

// ------------------------------------------------------------
// ОБРАБОТКА ВХОДЯЩИХ СООБЩЕНИЙ
// ------------------------------------------------------------
function handleIncomingFrame(clientId, buffer) {
  let text;
  try { text = decodeFrame(buffer); } catch (e) { return; }
  if (text === null) { clients.get(clientId)?.socket.end(); return; }

  let data;
  try { data = JSON.parse(text); } catch (e) { return; }

  const handlers = {
    request_code: handleRequestCode,
    verify_code: handleVerifyCode,
    check_username: handleCheckUsername,
    set_class_and_username: handleSetClassAndUsername,
    complete_registration_password: handleCompleteRegistrationPassword,
    login_password: handleLoginPassword,
    resume_session: handleResumeSession,
    search_users: handleSearchUsers,
    open_conversation: handleOpenConversation,
    send_direct_message: handleSendDirectMessage,
    get_chat_list: handleGetChatList,
    join_class_chat: handleJoinClassChat,
    open_class_chat: handleOpenClassChat,
    send_class_message: handleSendClassMessage,
    update_display_name: handleUpdateDisplayName,
    update_avatar: handleUpdateAvatar,
    update_username: handleUpdateUsername,
    update_class: handleUpdateClass,
    update_password: handleUpdatePassword,
    update_theme: handleUpdateTheme,
    update_notifications: handleUpdateNotifications,
  };

  const fn = handlers[data.type];
  if (fn) fn(clientId, data);
}

// ---------- Шаг 1: код на почту ----------
function handleRequestCode(clientId, data) {
  const email = (data.email || '').trim().toLowerCase();

  if (!email.endsWith('@gmail.com')) {
    return sendTo(clientId, { type: 'error', context: 'request_code', message: 'Разрешена только почта @gmail.com' });
  }

  const code = String(Math.floor(100000 + Math.random() * 900000));
  pendingCodes.set(email, { code, expiresAt: Date.now() + 10 * 60 * 1000 });

  // ⚠️ ЗДЕСЬ В РЕАЛЬНОМ ПРОЕКТЕ НУЖНО ОТПРАВИТЬ EMAIL.
  // Пока код выводится в консоль и присылается клиенту для тестирования.
  console.log(`[КОД ПОДТВЕРЖДЕНИЯ] ${email} -> ${code}`);

  sendTo(clientId, { type: 'code_sent', email, devCode: code });
}

// ---------- Шаг 2: проверка кода ----------
function handleVerifyCode(clientId, data) {
  const email = (data.email || '').trim().toLowerCase();
  const code = (data.code || '').trim();

  const pending = pendingCodes.get(email);
  if (!pending) return sendTo(clientId, { type: 'error', context: 'verify_code', message: 'Сначала запросите код' });
  if (Date.now() > pending.expiresAt) { pendingCodes.delete(email); return sendTo(clientId, { type: 'error', context: 'verify_code', message: 'Код истёк, запросите новый' }); }
  if (pending.code !== code) return sendTo(clientId, { type: 'error', context: 'verify_code', message: 'Неверный код' });

  pendingCodes.delete(email);

  const existingUser = q.getUserByEmail.get(email);
  if (existingUser) {
    // Уже зарегистрирован — почта просто подтверждена повторно, отправляем на экран входа паролем
    return sendTo(clientId, { type: 'code_verified_existing', email });
  }

  pendingRegistrations.set(email, {});
  sendTo(clientId, { type: 'code_verified', email });
}

// ---------- Проверка доступности username ----------
function handleCheckUsername(clientId, data) {
  const username = (data.username || '').trim().toLowerCase();
  const valid = /^[a-z0-9_]{3,12}$/.test(username);

  if (!valid) {
    return sendTo(clientId, { type: 'username_check_result', username, available: false, reason: 'От 3 до 12 символов: латинские буквы, цифры, нижнее подчёркивание' });
  }

  const taken = !!q.getUserByUsername.get(username);
  sendTo(clientId, { type: 'username_check_result', username, available: !taken, reason: taken ? 'Это имя уже занято' : null });
}

// ---------- Шаг 3+4: класс и username (промежуточное состояние до пароля) ----------
function handleSetClassAndUsername(clientId, data) {
  const email = (data.email || '').trim().toLowerCase();
  const className = (data.className || '').trim();
  const username = (data.username || '').trim().toLowerCase();

  if (!pendingRegistrations.has(email)) {
    return sendTo(clientId, { type: 'error', context: 'set_class_and_username', message: 'Сессия регистрации истекла, начните заново' });
  }
  if (!/^[a-z0-9_]{3,12}$/.test(username)) {
    return sendTo(clientId, { type: 'error', context: 'set_class_and_username', message: 'Некорректный username' });
  }
  if (q.getUserByUsername.get(username)) {
    return sendTo(clientId, { type: 'error', context: 'set_class_and_username', message: 'Username уже занят' });
  }
  if (!ALL_CLASSES.includes(className)) {
    return sendTo(clientId, { type: 'error', context: 'set_class_and_username', message: 'Не выбран класс' });
  }

  pendingRegistrations.set(email, { className, username });
  sendTo(clientId, { type: 'class_and_username_set' });
}

// ---------- Шаг 5: установка пароля -> завершение регистрации ----------
function handleCompleteRegistrationPassword(clientId, data) {
  const email = (data.email || '').trim().toLowerCase();
  const password = data.password || '';

  const pending = pendingRegistrations.get(email);
  if (!pending || !pending.username || !pending.className) {
    return sendTo(clientId, { type: 'error', context: 'complete_registration_password', message: 'Сессия регистрации истекла, начните заново' });
  }
  if (password.length < 6) {
    return sendTo(clientId, { type: 'error', context: 'complete_registration_password', message: 'Пароль должен быть не короче 6 символов' });
  }

  const { hash, salt } = createPasswordRecord(password);
  const createdAt = Date.now();

  try {
    q.insertUser.run(email, pending.username, pending.className, hash, salt, createdAt);
  } catch (e) {
    return sendTo(clientId, { type: 'error', context: 'complete_registration_password', message: 'Username уже занят, выберите другой' });
  }

  pendingRegistrations.delete(email);

  const client = clients.get(clientId);
  disconnectStaleSessionsForEmail(email, clientId);
  client.email = email;

  const token = createSession(email);
  const userRow = q.getUserByEmail.get(email);
  sendTo(clientId, { type: 'registration_complete', user: toPublicUser(userRow), sessionToken: token });
}

// ---------- Вход по email + пароль ----------
function handleLoginPassword(clientId, data) {
  const email = (data.email || '').trim().toLowerCase();
  const password = data.password || '';

  const row = q.getUserByEmail.get(email);
  if (!row) return sendTo(clientId, { type: 'error', context: 'login_password', message: 'Пользователь не найден' });

  if (!verifyPassword(password, row.password_salt, row.password_hash)) {
    return sendTo(clientId, { type: 'error', context: 'login_password', message: 'Неверный пароль' });
  }

  const client = clients.get(clientId);
  disconnectStaleSessionsForEmail(email, clientId);
  client.email = email;

  const token = createSession(email);
  sendTo(clientId, { type: 'login_success', user: toPublicUser(row), sessionToken: token });
}

// ---------- Восстановление сессии по токену (долгосрочный вход) ----------
function handleResumeSession(clientId, data) {
  const token = data.token || '';
  const session = q.getSession.get(token);
  if (!session) return sendTo(clientId, { type: 'session_invalid' });

  const row = q.getUserByEmail.get(session.email);
  if (!row) return sendTo(clientId, { type: 'session_invalid' });

  const client = clients.get(clientId);
  disconnectStaleSessionsForEmail(session.email, clientId);
  client.email = session.email;

  sendTo(clientId, { type: 'login_success', user: toPublicUser(row), sessionToken: token });
}

// ---------- Поиск пользователей + чат класса первым пунктом ----------
function handleSearchUsers(clientId, data) {
  const client = clients.get(clientId);
  const query = (data.query || '').trim().toLowerCase();

  const myRow = client?.email ? q.getUserByEmail.get(client.email) : null;
  const results = [];

  // Чат класса показывается первым, если запрос пустой или совпадает с названием класса / словом "класс"
  if (myRow) {
    const classLabel = `${myRow.class_name} класс`;
    if (!query || myRow.class_name.toLowerCase().includes(query) || 'класс'.includes(query)) {
      results.push({ type: 'class_chat', className: myRow.class_name, label: classLabel });
    }
  }

  if (query) {
    const rows = q.searchUsers.all(`%${query}%`);
    for (const r of rows) {
      if (r.email === client?.email) continue;
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

// ---------- Личные чаты: история ----------
function handleOpenConversation(clientId, data) {
  const client = clients.get(clientId);
  if (!client?.email) return;

  const otherEmail = (data.withEmail || '').trim().toLowerCase();
  const key = conversationKey(client.email, otherEmail);
  const rows = q.getConversation.all(key);
  const messages = rows.map((r) => ({ from: r.from_email, text: r.text, timestamp: r.timestamp }));

  sendTo(clientId, { type: 'conversation_history', withEmail: otherEmail, messages });
}

// ---------- Личные чаты: отправка ----------
function handleSendDirectMessage(clientId, data) {
  const client = clients.get(clientId);
  if (!client?.email) return;

  const toEmail = (data.toEmail || '').trim().toLowerCase();
  const text = (data.text || '').trim();
  if (!text) return;

  const fromUser = q.getUserByEmail.get(client.email);
  const timestamp = Date.now();
  const key = conversationKey(client.email, toEmail);

  q.insertDirectMessage.run(key, client.email, text, timestamp);

  const message = {
    from: client.email,
    fromUsername: fromUser?.username,
    fromDisplayName: fromUser?.display_name || fromUser?.username,
    fromAvatarData: fromUser?.avatar_data || null,
    text,
    timestamp,
  };
  sendTo(clientId, { type: 'direct_message', withEmail: toEmail, message });

  const recipientClientId = findClientIdByEmail(toEmail);
  if (recipientClientId) sendTo(recipientClientId, { type: 'direct_message', withEmail: client.email, message });
}

// ---------- Список личных чатов ----------
function handleGetChatList(clientId) {
  const client = clients.get(clientId);
  if (!client?.email) return;

  const rows = q.getLastMessagesForUser.all(client.email);
  const chats = [];

  for (const r of rows) {
    if (!r.conversation_key.includes(client.email)) continue;
    const [a, b] = r.conversation_key.split('|');
    const otherEmail = a === client.email ? b : a;
    const otherUser = q.getUserByEmail.get(otherEmail);
    if (!otherUser) continue;

    chats.push({
      withEmail: otherEmail,
      withUsername: otherUser.username,
      withDisplayName: otherUser.display_name || otherUser.username,
      withAvatarData: otherUser.avatar_data || null,
      lastMessageText: r.text,
      lastMessageTime: r.timestamp,
    });
  }

  chats.sort((a, b) => b.lastMessageTime - a.lastMessageTime);
  sendTo(clientId, { type: 'chat_list', chats });
}

// ---------- Вступление в чат класса ----------
function handleJoinClassChat(clientId, data) {
  const client = clients.get(clientId);
  if (!client?.email) return;

  const className = (data.className || '').trim();
  q.joinClassChat.run(className, client.email, Date.now());

  sendTo(clientId, { type: 'class_chat_joined', className });
}

// ---------- Открытие чата класса (история) ----------
function handleOpenClassChat(clientId, data) {
  const client = clients.get(clientId);
  if (!client?.email) return;

  const className = (data.className || '').trim();
  const isMember = q.isClassChatMember.get(className, client.email);
  if (!isMember) {
    return sendTo(clientId, { type: 'error', context: 'open_class_chat', message: 'Сначала вступите в чат класса' });
  }

  const rows = q.getClassMessages.all(className);
  const messages = rows.map((r) => ({ from: r.from_email, text: r.text, timestamp: r.timestamp }));
  sendTo(clientId, { type: 'class_chat_history', className, messages });
}

// ---------- Сообщение в чат класса ----------
function handleSendClassMessage(clientId, data) {
  const client = clients.get(clientId);
  if (!client?.email) return;

  const className = (data.className || '').trim();
  const text = (data.text || '').trim();
  if (!text) return;

  const isMember = q.isClassChatMember.get(className, client.email);
  if (!isMember) return;

  const fromUser = q.getUserByEmail.get(client.email);
  const timestamp = Date.now();
  q.insertClassMessage.run(className, client.email, text, timestamp);

  const message = {
    from: client.email,
    fromUsername: fromUser?.username,
    fromDisplayName: fromUser?.display_name || fromUser?.username,
    fromAvatarData: fromUser?.avatar_data || null,
    text,
    timestamp,
  };

  // Рассылаем всем участникам чата класса, кто сейчас онлайн
  const members = q.getClassChatMembers.all(className);
  for (const m of members) {
    const memberClientId = findClientIdByEmail(m.email);
    if (memberClientId) sendTo(memberClientId, { type: 'class_message', className, message });
  }
}

// ---------- Настройки профиля: смена отображаемого имени ----------
function handleUpdateDisplayName(clientId, data) {
  const client = clients.get(clientId);
  if (!client?.email) return;

  const displayName = (data.displayName || '').trim().slice(0, 40);
  if (!displayName) {
    return sendTo(clientId, { type: 'error', context: 'update_display_name', message: 'Имя не может быть пустым' });
  }

  q.updateDisplayName.run(displayName, client.email);
  sendTo(clientId, { type: 'profile_updated', user: toPublicUser(q.getUserByEmail.get(client.email)) });
}

// ---------- Настройки профиля: смена аватарки ----------
// avatarData — картинка в виде data URL (data:image/png;base64,...),
// клиент уже сжимает и кодирует её перед отправкой.
function handleUpdateAvatar(clientId, data) {
  const client = clients.get(clientId);
  if (!client?.email) return;

  const avatarData = data.avatarData || null;

  // Простая защита от слишком больших картинок (ограничение размера
  // сообщения WebSocket и базы данных) — не более ~2 МБ в base64.
  if (avatarData && avatarData.length > 2 * 1024 * 1024) {
    return sendTo(clientId, { type: 'error', context: 'update_avatar', message: 'Изображение слишком большое (максимум ~1.5 МБ)' });
  }

  q.updateAvatar.run(avatarData, client.email);
  sendTo(clientId, { type: 'profile_updated', user: toPublicUser(q.getUserByEmail.get(client.email)) });
}

// ---------- Настройки профиля: смена username ----------
function handleUpdateUsername(clientId, data) {
  const client = clients.get(clientId);
  if (!client?.email) return;

  const username = (data.username || '').trim().toLowerCase();
  if (!/^[a-z0-9_]{3,12}$/.test(username)) {
    return sendTo(clientId, { type: 'error', context: 'update_username', message: 'От 3 до 12 символов: латинские буквы, цифры, нижнее подчёркивание' });
  }

  const existing = q.getUserByUsername.get(username);
  if (existing && existing.email !== client.email) {
    return sendTo(clientId, { type: 'error', context: 'update_username', message: 'Это имя уже занято' });
  }

  q.updateUsername.run(username, client.email);
  sendTo(clientId, { type: 'profile_updated', user: toPublicUser(q.getUserByEmail.get(client.email)) });
}

// ---------- Настройки профиля: смена класса ----------
function handleUpdateClass(clientId, data) {
  const client = clients.get(clientId);
  if (!client?.email) return;

  const className = (data.className || '').trim();
  if (!ALL_CLASSES.includes(className)) {
    return sendTo(clientId, { type: 'error', context: 'update_class', message: 'Некорректный класс' });
  }

  q.updateClassName.run(className, client.email);
  sendTo(clientId, { type: 'profile_updated', user: toPublicUser(q.getUserByEmail.get(client.email)) });
}

// ---------- Настройки профиля: смена пароля ----------
function handleUpdatePassword(clientId, data) {
  const client = clients.get(clientId);
  if (!client?.email) return;

  const currentPassword = data.currentPassword || '';
  const newPassword = data.newPassword || '';

  const row = q.getUserByEmail.get(client.email);
  if (!verifyPassword(currentPassword, row.password_salt, row.password_hash)) {
    return sendTo(clientId, { type: 'error', context: 'update_password', message: 'Текущий пароль неверен' });
  }
  if (newPassword.length < 6) {
    return sendTo(clientId, { type: 'error', context: 'update_password', message: 'Новый пароль должен быть не короче 6 символов' });
  }

  const { hash, salt } = createPasswordRecord(newPassword);
  q.updatePassword.run(hash, salt, client.email);
  sendTo(clientId, { type: 'password_updated' });
}

// ---------- Настройки: тема (тёмная/светлая) ----------
function handleUpdateTheme(clientId, data) {
  const client = clients.get(clientId);
  if (!client?.email) return;

  const theme = data.theme === 'light' ? 'light' : 'dark';
  q.updateTheme.run(theme, client.email);
  sendTo(clientId, { type: 'profile_updated', user: toPublicUser(q.getUserByEmail.get(client.email)) });
}

// ---------- Настройки: уведомления вкл/выкл ----------
function handleUpdateNotifications(clientId, data) {
  const client = clients.get(clientId);
  if (!client?.email) return;

  const enabled = data.enabled ? 1 : 0;
  q.updateNotifications.run(enabled, client.email);
  sendTo(clientId, { type: 'profile_updated', user: toPublicUser(q.getUserByEmail.get(client.email)) });
}

// ------------------------------------------------------------
// ЗАПУСК
// ------------------------------------------------------------
server.listen(PORT, () => {
  console.log(`✅ Сервер school347 запущен: http://localhost:${PORT}`);
});
