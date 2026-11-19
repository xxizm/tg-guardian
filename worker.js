/**
 * TG Guardian Worker v1.4.18
 * Cloudflare Worker + KV (TG_GUARD_DATA) + Telegram Bot API.
 * Env: BOT_TOKEN, OWNER_ID, WEBHOOK_SECRET, KV binding TG_GUARD_DATA.
 * Author: TG https://t.me/ziixiix
 *
 * MULTI-ACCOUNT (v1.4.0): one bot watches several Telegram accounts that
 * all belong to the same owner. Every account has its own phone number;
 * all per-account state lives in KV under the prefix `acct:<phone>:`.
 * The first account is the original one; its old unprefixed keys are
 * migrated to the prefix the first time the monitor calls
 * POST /register-account. The monitor polls GET /pending every 120 seconds
 * and gets ALL accounts' data in one call, so 5 accounts still cost
 * about 720 requests/day and ~17k KV reads/day — inside the free
 * tier (100k requests, 100k KV reads, 1k KV writes per day).
 *
 * Adding an account happens from the bot, no server change needed:
 *   /add_account <手机号> [名字]  -> monitor sends a login code
 *   /code <验证码>               -> monitor finishes the login
 *   /2fa <二级密码>             -> only if the account has 2FA
 *   /cancel_add <手机号>         -> abort an in-progress add
 *   /accounts                    -> list accounts and their state
 *   /remove_account <手机号>     -> delete an account (two-step confirm)
 * The code / 2FA password travel through the bot and KV only until the
 * monitor's next poll (<= 60 s): the Worker strips them from the stored
 * record as soon as they are handed to the monitor, and the monitor
 * never logs them. They are single-use (code) or only ever held in
 * memory by the monitor (password, used once for sign-in).
 *
 * Routes (monitor auth: token = BOT_TOKEN):
 *   GET  /        = health check
 *   POST /webhook = Telegram updates (messages + inline button taps)
 *   POST /sync    = monitor reports a new device {account, ...}
 *   GET  /pending = monitor polls decisions for ALL accounts at once.
 *                   Also returns accounts, removed accounts, onboard
 *                   requests, and per-account settings.
 *   POST /code-alert = monitor reports a login-code request {account, ...}
 *   POST /code-freeze = monitor reports a protection result {account, ...}
 *   POST /heartbeat = monitor uploads heartbeat + snapshot {account, ...}
 *   POST /register-account = monitor self-registers its main account
 *                   {token, phone, name}; migrates legacy keys on first use.
 *   POST /onboard-status = monitor reports add-account progress
 *                   {token, phone, state, detail}; the Worker messages
 *                   the owner with the next step.
 * Commands: /login_guard, /flood_status, /security_check, /alert_on,
 *   /alert_off, /clear_alerts, /clear_flood, /check_flood, /set_guard,
 *   /set_revoke — all accept an
 *   optional account argument (phone or name); without one they show
 *   the single registered account directly, or ask which account when
 *   several are registered.
 * New-device flow: alert first; owner taps a button, or no reply within
 * the configured time (/set_revoke, default 600 s) and the monitor
 * auto-revokes the session.
 * Code flow: code requested -> alert with three buttons. 拒绝·冻结验证码
 * only burns the code (wrong code 5 times); 拒绝·冻结二级密码 only runs
 * the 2FA protection (fresh code entered correctly, then wrong 2FA
 * password 5 times to trigger PHONE_PASSWORD_FLOOD; recovery time is estimated
 * by trigger count in 24h (1st-3rd 1h, 4th 6h, 5th+ 24h)). No reply within the configured time (/set_guard,
 * default 300 s) -> the monitor auto-runs the 2FA protection only,
 * because its block lasts until next day while the code-request block
 * often clears sooner. Either protection also locks the owner out of
 * new-device logins for the same period; already-logged-in sessions are
 * unaffected.
 * Replies to EVERY message from the owner, so the bot is never silent.
 * Flood recovery sync (v1.4.7): a flood record is only an estimate —
 * Telegram never tells us when it really lifts. auth.sendCode itself
 * returns PHONE_PASSWORD_FLOOD / PHONE_NUMBER_FLOOD while a flood is
 * active, so a login code can only arrive after the flood has lifted.
 * When /code-alert or /sync reports a genuine code request / new
 * session for an account with a stored flood record, the Worker clears
 * the stale record and tells the owner once ("Flood保护已恢复").
 * /clear_flood clears a record by hand. Expired records render with
 * "（已过预计恢复时间）" instead of silently looking active.
 * Manual check (v1.4.8): /check_flood asks the monitor to probe the
 * account (one fresh code request on a throwaway client). Success
 * proves the flood has lifted, so the stale record is cleared; a flood
 * error proves it has not. POST /flood-probe carries the result, and
 * GET /pending carries the probe request (flood_probe) to the monitor.
 *
 * DECISION WAKE-UP (v1.4.9): tapping a decision button (allow / revoke /
 * code allow / deny) no longer waits for the monitor's next 30 s poll —
 * the Worker sends a short wake-up message from the bot, the monitor's
 * main client watches for it and polls /pending immediately; the message
 * is deleted a few seconds later so the owner's chat stays clean. If the
 * monitor misses it, the regular 30 s poll is still the backstop.
 *
 * FLOOD EXPIRY AUTO-CLEAR (v1.4.10): the flood lasts at most ~24h, so
 * once a record's estimated recovery time has passed, the hourly
 * heartbeat clears it without probing (reuses the "Flood保护已恢复"
 * notice). No extra polling, no code request is spent.
 *
 * DIRECT DECISION IN WAKE-UP (v1.4.11): the wake-up message now also
 * CARRIES the decision ("kind:phone:id:ts" on the second line), so the
 * monitor acts in seconds instead of waiting up to ~60 s for the KV
 * write to propagate to the /pending read. The KV record is still
 * written first and stays the source of truth; the /pending poll is the
 * backstop and the monitor dedupes, so a decision is never executed
 * twice. Applies to device allow / revoke and to all three code
 * decisions (allow, freeze code, freeze 2FA, both).
 *
 * SECONDS FOR /set_guard AND /set_revoke (v1.4.12): the two timing
 * commands now take seconds (60-3600) instead of minutes; the stored
 * values were already seconds, so existing settings keep working.
 *
 * FLOOD-RECORD RECENCY GUARD (v1.4.13): the freeze's own throwaway
 * login-flow session looks like a genuine new device, so /sync used to
 * clear the flood record one second after /code-freeze stored it
 * (main account, 2026-11-18 17:01). clearFloodIfActive now refuses to
 * delete a record stored less than 10 minutes ago when called from
 * /code-alert or /sync; a genuine recovery cannot arrive that fast
 * (sendCode returns the flood while it is active). /clear_flood still
 * clears by hand, and the hourly heartbeat expiry is unaffected.
 *
 * RECOVERY ESTIMATE 1 HOUR (v1.4.14): the flood recovery estimate is
 * now 1 hour instead of 24 (repeated live tests all recovered in about
 * an hour; the 1h/6h/24h escalation table found online did not hold).
 * The monitor stores now+1h in the flood record; the panel footnote and
 * the help texts now say 1 hour. The hourly heartbeat expiry uses the
 * stored estimate, so it clears sooner too.
 *
 * RECOVERY ESTIMATE BY TRIGGER COUNT + 120 S POLL (v1.4.15): the
 * flat 1h estimate did not hold for repeat floods (the main
 * account's 4th flood lasted 15h+), so the estimate now follows the
 * trigger count in the last 24h: 1st-3rd 1h, 4th 6h, 5th+ 24h. The Worker
 * keeps a per-account trigger history (acct:<phone>:flood_triggers,
 * pruned to 24h) and computes the estimate in POST /code-freeze,
 * returning it to the monitor for the result alert; the panel and
 * the heartbeat expiry use the stored estimate. The monitor polls
 * every 120 s now (the wake-up carries decisions directly, so the
 * poll is only a backstop). View commands (/status, /devices, /logs,
 * /login_guard, /flood_status, /security_check) now ask which
 * account when several are registered and none is given, instead of
 * showing all accounts; with a single account they show it directly.
 *
 * SUSTAINED FLOOD PROTECTION (v1.4.16): a one-shot timer. The owner
 * enables it with /sustain_flood_on [minutes] (default 30, max 1440)
 * or the big sustain button (top row, full width); it is off
 * by default and /sustain_flood_off cancels it. When the timer elapses
 * the monitor triggers the 2FA flood once and reports the result; the
 * timer record (acct:<phone>:sustain) is returned in GET /pending and
 * cleared by POST /code-freeze when the scheduled trigger reports
 * (event ids starting with "sustain:"). The scheduled trigger counts
 * toward the 24h trigger history like any other 2FA trigger.
 *
 * RENAME + SUSTAIN MODES (v1.4.17): /rename_account [account] <new name>
 * renames an account (the monitor picks the new name up from the
 * accounts list on its next poll). The sustain picker no longer repeats
 * the duration buttons once a timer is set: it now offers loop (trigger
 * every interval forever) and choose count (trigger N times then stop).
 * The sustain record carries mode/remaining/total; POST /code-freeze
 * reschedules a loop timer or decrements a count timer, and returns the
 * updated sustain state for the result alert.
 *
 * MANUAL PROBE ALWAYS PROBES (v1.4.18): /check_flood no longer refuses
 * when there is no stored flood record - a manual check always sends one
 * fresh code request and reports the real state. When the probe finds a
 * definite flood (FloodWait / PHONE_PASSWORD_FLOOD / PHONE_NUMBER_FLOOD)
 * with no stored record, the Worker creates one (mode 2fa, recovery from
 * the real FloodWait seconds when Telegram gives them, else unknown) so
 * the panel stops lying; with a stored record the real wait overwrites
 * the estimate. A failed/inconclusive probe changes nothing. An old
 * monitor (no flood_active field) keeps the previous behaviour.
 */

const VERSION = "1.4.18";

// Wake-up marker (v1.4.9): sent as a short bot message after any decision
// button tap so the monitor polls /pending immediately instead of waiting
// for its 120 s cycle. The monitor matches on this text from the bot. Since v1.4.11 the
// message may carry the decision itself on a second line.
const WAKEUP_TEXT = "⚡ TG Guardian：正在唤醒监控端…";

// --- Settings: auto times + alerts switch, per account, stored in KV,
// changed with bot commands (/set_guard, /set_revoke, /alert_on,
// /alert_off). The monitor reads them from GET /pending on every poll,
// so a change takes effect within two minutes.
const DEFAULT_SETTINGS = { auto_code_after: 300, auto_revoke_after: 600, alerts_enabled: true };

async function getSettings(env, phone) {
  try {
    const raw = await kvGetAcct(env, phone, "settings");
    if (!raw) return { ...DEFAULT_SETTINGS };
    const s = JSON.parse(raw);
    const out = { ...DEFAULT_SETTINGS };
    for (const k of ["auto_code_after", "auto_revoke_after"]) {
      const v = Number(s[k]);
      if (Number.isFinite(v) && v >= 60 && v <= 3600) out[k] = Math.round(v);
    }
    if (typeof s.alerts_enabled === "boolean") out.alerts_enabled = s.alerts_enabled;
    return out;
  } catch { return { ...DEFAULT_SETTINGS }; }
}

async function saveSettings(env, phone, settings) {
  return kvPutAcct(env, phone, "settings", JSON.stringify(settings));
}

// --- Accounts: [{phone, name}]. phone is digits only. The list is the
// source of truth the monitor reads from GET /pending. ---
function normalizePhone(s) {
  if (s === undefined || s === null) return null;
  const d = String(s).replace(/[^0-9]/g, "");
  return d.length >= 5 && d.length <= 15 ? d : null;
}

function displayPhone(p) {
  // Display only: every number the owner sees carries "+". Storage,
  // KV keys and callback_data stay digits-only — the two sides must
  // agree on ONE internal format (that mismatch was the v0.5.0 bug).
  const d = normalizePhone(p);
  return d ? "+" + d : String(p || "");
}

function accountLabel(a) {
  if (!a) return "未知账号";
  const tail = a.phone ? a.phone.slice(-4) : "????";
  return a.name ? `${a.name}（尾号 ${tail}）` : `尾号 ${tail}`;
}

async function getAccounts(env) {
  try {
    const raw = await kvGet(env, "accounts");
    if (!raw) return [];
    const list = JSON.parse(raw);
    return Array.isArray(list) ? list.filter((a) => a && normalizePhone(a.phone)) : [];
  } catch { return []; }
}

async function saveAccounts(env, list) {
  return kvPut(env, "accounts", JSON.stringify(list));
}

function findAccount(accounts, arg) {
  if (!arg) return null;
  const s = String(arg).trim();
  const phone = normalizePhone(s);
  if (phone) {
    const byPhone = accounts.find((a) => a.phone === phone);
    if (byPhone) return byPhone;
  }
  const byName = accounts.find((a) => a.name && a.name === s);
  if (byName) return byName;
  const byNamePart = accounts.filter((a) => a.name && a.name.includes(s));
  if (byNamePart.length === 1) return byNamePart[0];
  // A phone tail (e.g. 0968) is what the UI shows; match it when unique.
  if (/^\d{4,}$/.test(s)) {
    const byTail = accounts.filter((a) => a.phone.endsWith(s));
    if (byTail.length === 1) return byTail[0];
  }
  return null;
}

// Resolve an account argument for a command. args are the words after
// the command. Returns {account} or {error} or {needChoice} (no arg and
// several accounts) or {none} (no accounts at all yet).
async function resolveAccountArg(env, args) {
  const accounts = await getAccounts(env);
  if (!accounts.length) return { none: true, accounts };
  if (!args || !args.length) {
    if (accounts.length === 1) return { account: accounts[0], accounts };
    return { needChoice: true, accounts };
  }
  const found = findAccount(accounts, args[0]) || findAccount(accounts, args.join(" "));
  if (found) return { account: found, accounts };
  return { error: `没找到账号「${args.join(" ")}」，发 /accounts 看看已有的账号。`, accounts };
}

function choiceText(accounts) {
  return "有多个账号，请指定一个：\n" + accounts.map((a) => `· ${accountLabel(a)} — ${displayPhone(a.phone)}`).join("\n");
}

// --- KV: raw helpers + per-account keys. phone === null means the
// legacy unprefixed keys (only used before the first /register-account
// migrates them). ---
async function kvGet(env, key) {
  try { return await env.TG_GUARD_DATA.get(key); } catch { return null; }
}

async function kvPut(env, key, value) {
  try { await env.TG_GUARD_DATA.put(key, value); return true; } catch (e) { console.log("KV put error:", e); return false; }
}

async function kvDelete(env, key) {
  try { await env.TG_GUARD_DATA.delete(key); return true; } catch (e) { console.log("KV delete error:", e); return false; }
}

function acctKey(phone, key) {
  return phone ? `acct:${phone}:${key}` : key;
}

async function kvGetAcct(env, phone, key) {
  return kvGet(env, acctKey(phone, key));
}

async function kvPutAcct(env, phone, key, value) {
  return kvPut(env, acctKey(phone, key), value);
}

async function kvDeleteAcct(env, phone, key) {
  return kvDelete(env, acctKey(phone, key));
}

// One-time migration of the original single account's legacy keys to
// the acct: prefix. Runs on the first /register-account only.
const LEGACY_KEYS = ["pending_index", "code_index", "code_frozen", "alerts", "sessions", "mtproto_heartbeat", "settings"];

async function migrateLegacyKeys(env, phone) {
  for (const key of LEGACY_KEYS) {
    const raw = await kvGet(env, key);
    if (raw === null || raw === undefined) continue;
    if ((await kvGetAcct(env, phone, key)) !== null) continue; // already migrated
    await kvPutAcct(env, phone, key, raw);
  }
  // Per-item keys listed in the indexes.
  try {
    const pending = JSON.parse((await kvGet(env, "pending_index")) || "[]");
    for (const h of pending) {
      const raw = await kvGet(env, "pending:" + h);
      if (raw !== null && (await kvGetAcct(env, phone, "pending:" + h)) === null) {
        await kvPutAcct(env, phone, "pending:" + h, raw);
      }
    }
  } catch { /* ignore */ }
  try {
    const codes = JSON.parse((await kvGet(env, "code_index")) || "[]");
    for (const id of codes) {
      const raw = await kvGet(env, "code:" + id);
      if (raw !== null && (await kvGetAcct(env, phone, "code:" + id)) === null) {
        await kvPutAcct(env, phone, "code:" + id, raw);
      }
    }
  } catch { /* ignore */ }
}

// --- Onboard records: KV "onboard" = [{phone, name, state, created_at,
// detail?, code?, password?}]. The code/password are stripped from the
// stored record the moment GET /pending hands them to the monitor. ---
async function getOnboard(env) {
  try {
    const raw = await kvGet(env, "onboard");
    if (!raw) return [];
    const list = JSON.parse(raw);
    return Array.isArray(list) ? list : [];
  } catch { return []; }
}

async function saveOnboard(env, list) {
  return kvPut(env, "onboard", JSON.stringify(list));
}

// --- Display helpers: keep bot output short, Chinese, Singapore time ---
// fmtTime: ISO UTC -> "MM-DD HH:mm" in SGT (+08). Tolerates a suffix.
function fmtTime(iso) {
  if (!iso) return "?";
  const d = new Date(String(iso).slice(0, 19) + "Z");
  if (isNaN(d.getTime())) return String(iso);
  const sgt = new Date(d.getTime() + 8 * 3600 * 1000);
  const p = (n) => String(n).padStart(2, "0");
  return `${p(sgt.getUTCMonth() + 1)}-${p(sgt.getUTCDate())} ${p(sgt.getUTCHours())}:${p(sgt.getUTCMinutes())}`;
}

// --- Alerts log: one line per event, kept 30 days (v1.3.4). ---
const ALERT_RETENTION_MS = 30 * 24 * 3600 * 1000;

function alertLineTime(l) {
  const m = String(l).match(/\[([^\]]+)\]/);
  if (!m) return null;
  const t = Date.parse(m[1]);
  return isNaN(t) ? null : t;
}

function pruneAlertLines(text) {
  const cutoff = Date.now() - ALERT_RETENTION_MS;
  return String(text || "").split("\n").filter((l) => {
    if (!l.trim()) return false;
    const t = alertLineTime(l);
    return t === null || t >= cutoff;
  }).join("\n");
}

async function appendAlert(env, phone, line) {
  const prev = (await kvGetAcct(env, phone, "alerts")) || "";
  await kvPutAcct(env, phone, "alerts", pruneAlertLines((prev ? prev + "\n" : "") + line));
}

// Old log lines stored before v1.3.2 keep ISO timestamps; reformat them on
// display so /logs looks consistent. Also drops a redundant phrase.
function reformatOldLine(l) {
  return l
    .replace(/\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z/g, (m) => fmtTime(m))
    .replace("（预计恢复时间见记录）", "");
}
function fmtSession(s) {
  const dev = (s.device || "?") + (s.platform && s.platform !== "?" ? " · " + s.platform : "");
  const icon = /iphone|ipad|android/i.test(s.device || "") ? "📱" : "🖥️";
  const place = [s.country, s.region].filter((x) => x && x !== "?").join(" ");
  const lines = [`${icon} ${dev} · ${s.app || "?"}`];
  const meta = [];
  if (place) meta.push(place);
  if (s.created) meta.push("登录 " + fmtTime(s.created));
  if (s.active) meta.push("活跃 " + fmtTime(s.active));
  if (meta.length) lines.push(meta.join(" · "));
  if (s.current) lines.push("（监控本身）");
  return lines.join("\n");
}

const HELP_TEXT =
  "🛡️ TG Guardian（多账号）\n\n" +
  "👥 账号管理\n" +
  "/accounts — 账号列表和状态\n" +
  "/add_account <手机号> [名字] — 添加一个账号\n" +
  "/rename_account [手机号或名字] <新名字> — 改账号名字\n" +
  "/code <验证码> — 添加账号时提交验证码\n" +
  "/2fa <二级密码> — 添加账号时提交二级密码\n" +
  "/cancel_add <手机号> — 取消正在添加的账号\n" +
  "/remove_account <手机号> — 删除一个账号\n\n" +
  "📋 状态查询（多账号时需指定账号，如 /status +8613800138000）\n" +
  "/status — 整体状态\n" +
  "/security — 安全状态\n" +
  "/devices — 已登录设备\n" +
  "/logs — 最近告警\n\n" +
  "🛡️ 反登录防护\n" +
  "/login_guard — 防护状态和当前时间设置\n" +
  "/flood_status — 已记录的 Flood 状态\n" +
  "/security_check — 检查防护系统配置\n" +
  "/alert_on — 开启安全异常告警\n" +
  "/alert_off — 关闭安全异常告警\n" +
  "/clear_alerts — 手动清空最近告警\n" +
"/clear_flood — 手动清除已记录的 Flood 状态\n" +
"/check_flood — 手动检查 Flood 是否已恢复（可能会收到一次验证码，忽略即可）\n\n" +
  "⏱️ 时间设置（60–3600 秒，改完 2 分钟内生效）\n" +
  "/set_guard <秒> [账号] — 验证码无人确认后自动冻结二级密码的时间\n" +
  "/set_revoke <秒> [账号] — 新设备无人确认后自动注销的时间\n\n" +
  "⏰ 持续Flood保护（默认关）\n" +
  "/sustain_flood_on [分钟] [账号] — 开启，到时间自动触发一次 Flood 保护（不填默认 30 分钟，最长 1440 分钟）\n" +
  "/sustain_flood_off [账号] — 关闭\n\n" +
  "🔧 自检\n" +
  "/test — KV 读写测试\n" +
  "/ping — 机器人是否在线\n\n" +
  "ℹ️ 其他\n" +
  "/help — 显示本帮助\n" +
  "/start — 启动机器人\n\n" +
  "💡 新设备先告警，600 秒没回复自动注销（/set_revoke 可改）。\n" +
  "💡 验证码也会告警：同意放行，拒绝冻结验证码或二级密码（恢复时间按 24 小时内触发次数估算）；300 秒没回复自动冻结二级密码（/set_guard 可改）。";

const KEYBOARD = {
  inline_keyboard: [
    [{ text: "🌊 持续Flood保护", callback_data: "cmd:/sustain_flood_on" }],
    [{ text: "📊 状态", callback_data: "cmd:/status" }, { text: "📱 设备", callback_data: "cmd:/devices" }],
    [{ text: "🛡️ 安全", callback_data: "cmd:/security" }, { text: "📋 告警", callback_data: "cmd:/logs" }],
    [{ text: "👥 账号", callback_data: "cmd:/accounts" }, { text: "➕ 添加账号", callback_data: "cmd:/add_account" }],
    [{ text: "🔧 自检", callback_data: "cmd:/test" }, { text: "❓ 帮助", callback_data: "cmd:/help" }],
  ],
};

// Bottom-left command menu (Telegram setMyCommands). Stored server-side by
// Telegram, so it survives clearing the chat history. Set once per /start.
const BOT_COMMANDS = [
  { command: "start", description: "启动机器人" },
  { command: "accounts", description: "账号列表和状态" },
  { command: "add_account", description: "添加一个账号" },
  { command: "code", description: "添加账号时提交验证码" },
  { command: "2fa", description: "添加账号时提交二级密码" },
  { command: "cancel_add", description: "取消正在添加的账号" },
  { command: "remove_account", description: "删除一个账号" },
  { command: "rename_account", description: "改账号名字" },
  { command: "status", description: "整体状态" },
  { command: "security", description: "安全状态" },
  { command: "devices", description: "已登录设备" },
  { command: "logs", description: "最近告警" },
  { command: "login_guard", description: "反登录防护状态" },
  { command: "flood_status", description: "已记录的 Flood 状态" },
  { command: "security_check", description: "检查防护系统配置" },
  { command: "alert_on", description: "开启安全异常告警" },
  { command: "alert_off", description: "关闭安全异常告警" },
  { command: "clear_alerts", description: "手动清空最近告警" },
  { command: "clear_flood", description: "手动清除 Flood 记录" },
  { command: "check_flood", description: "手动检查 Flood 是否恢复" },
  { command: "set_guard", description: "设置自动冻结时间（秒）" },
  { command: "set_revoke", description: "设置自动注销时间（秒）" },
  { command: "sustain_flood_on", description: "开启持续Flood保护（定时触发）" },
  { command: "sustain_flood_off", description: "关闭持续Flood保护" },
  { command: "test", description: "KV 读写测试" },
  { command: "ping", description: "机器人是否在线" },
  { command: "help", description: "显示帮助" },
];

async function ensureMenu(env) {
  try {
    await fetch(`https://api.telegram.org/bot${env.BOT_TOKEN}/setMyCommands`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ commands: BOT_COMMANDS }),
    });
  } catch { /* menu is best-effort; typing the commands still works */ }
}

async function sendMessage(env, chatId, text, withKeyboard, customKeyboard) {
  try {
    await fetch(`https://api.telegram.org/bot${env.BOT_TOKEN}/sendMessage`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        chat_id: chatId,
        text,
        reply_markup: customKeyboard || (withKeyboard ? KEYBOARD : undefined),
      }),
    });
    return true;
  } catch (e) {
    console.log("sendMessage error:", e);
    return false;
  }
}

// Push, don't poll (v1.4.9): after a decision button is tapped, the Worker
// sends the owner a short wake-up message from the bot; the monitor's main
// client watches for it and polls /pending immediately. The message is
// deleted a few seconds later so the owner's chat stays clean. Best-effort:
// if the monitor misses it, the regular 120 s poll is still the backstop.
// v1.4.11: the wake-up may also CARRY the decision (second line
// "kind:phone:id:ts"), so the monitor acts in seconds instead of
// waiting up to ~60 s for the KV write to propagate to /pending.
// The KV record is still written first; the poll stays the backstop.
async function sendWakeup(env, payload) {
  const text = payload ? WAKEUP_TEXT + "\n" + payload : WAKEUP_TEXT;
  try {
    const res = await fetch(`https://api.telegram.org/bot${env.BOT_TOKEN}/sendMessage`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ chat_id: env.OWNER_ID, text }),
    });
    const data = await res.json().catch(() => null);
    const mid = data && data.result && data.result.message_id;
    if (!mid) return;
    await new Promise((resolve) => setTimeout(resolve, 5000));
    try {
      await fetch(`https://api.telegram.org/bot${env.BOT_TOKEN}/deleteMessage`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ chat_id: env.OWNER_ID, message_id: mid }),
      });
    } catch (e) { console.log("wakeup delete error:", e); }
  } catch (e) { console.log("wakeup error:", e); }
}

async function editMessage(env, chatId, messageId, text) {
  try {
    await fetch(`https://api.telegram.org/bot${env.BOT_TOKEN}/editMessageText`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ chat_id: chatId, message_id: messageId, text }),
    });
  } catch (e) { console.log("editMessage error:", e); }
}

async function answerCallback(env, callbackQueryId, text) {
  try {
    await fetch(`https://api.telegram.org/bot${env.BOT_TOKEN}/answerCallbackQuery`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ callback_query_id: callbackQueryId, text: text || "" }),
    });
  } catch (e) { console.log("answerCallback error:", e); }
}

function isOwner(env, fromId) {
  return String(fromId) === String(env.OWNER_ID);
}

async function getPendingList(env, phone) {
  const raw = await kvGetAcct(env, phone, "pending_index");
  if (!raw) return [];
  try {
    const list = JSON.parse(raw);
    const out = [];
    for (const h of list) {
      const itemRaw = await kvGetAcct(env, phone, "pending:" + h);
      if (!itemRaw) continue;
      try { out.push(JSON.parse(itemRaw)); } catch { /* skip */ }
    }
    return out;
  } catch { return []; }
}

async function savePendingList(env, phone, items) {
  const hashes = items.map((i) => String(i.hash));
  await kvPutAcct(env, phone, "pending_index", JSON.stringify(hashes));
  for (const item of items) {
    await kvPutAcct(env, phone, "pending:" + item.hash, JSON.stringify(item));
  }
}

async function getCodeEvents(env, phone) {
  const raw = await kvGetAcct(env, phone, "code_index");
  if (!raw) return [];
  try {
    const list = JSON.parse(raw);
    const out = [];
    for (const id of list) {
      const itemRaw = await kvGetAcct(env, phone, "code:" + id);
      if (!itemRaw) continue;
      try { out.push(JSON.parse(itemRaw)); } catch { /* skip */ }
    }
    return out;
  } catch { return []; }
}

async function saveCodeEvents(env, phone, items) {
  const ids = items.map((i) => String(i.id));
  await kvPutAcct(env, phone, "code_index", JSON.stringify(ids));
  for (const item of items) {
    await kvPutAcct(env, phone, "code:" + item.id, JSON.stringify(item));
  }
}

function describePending(item) {
  const place = [item.country, item.region].filter((x) => x && x !== "?").join(" ");
  const lines = [`${item.device || "?"} · ${item.app || "?"}`];
  if (place) lines.push(place);
  if (item.ip && item.ip !== "?") lines.push("IP " + item.ip);
  if (item.created) lines.push("创建 " + fmtTime(item.created));
  return lines.join("\n");
}

async function getWebhookInfo(env) {
  try {
    const res = await fetch(`https://api.telegram.org/bot${env.BOT_TOKEN}/getWebhookInfo`);
    const data = await res.json();
    return data.ok ? data.result : null;
  } catch { return null; }
}

// Delete every per-account KV key for one phone (used by /remove_account).
async function deleteAccountData(env, phone) {
  const pending = await getPendingList(env, phone);
  for (const p of pending) await kvDeleteAcct(env, phone, "pending:" + p.hash);
  const codes = await getCodeEvents(env, phone);
  for (const c of codes) await kvDeleteAcct(env, phone, "code:" + c.id);
  for (const key of ["pending_index", "code_index", "code_frozen", "alerts", "sessions", "mtproto_heartbeat", "settings"]) {
    await kvDeleteAcct(env, phone, key);
  }
}

// --- Per-account status pieces, shared by /status, /login_guard,
// /flood_status, /security_check and /accounts. ---
// --- Sustained Flood protection (v1.4.16): a one-shot timer. The owner
// sets a duration (default 30 min); when it elapses the monitor triggers
// the 2FA flood once. Off by default (no record = off); /sustain_flood_on
// sets the timer, /sustain_flood_off clears it. The record lives in KV at
// acct:<phone>:sustain and is returned in GET /pending so the monitor can
// fire it. POST /code-freeze clears it when the scheduled trigger reports
// (event ids starting with "sustain:").
const SUSTAIN_DEFAULT_MIN = 30;
const SUSTAIN_MAX_MIN = 1440; // 24h
const SUSTAIN_DURATIONS = [30, 60, 360, 720]; // picker buttons (minutes)

async function getSustain(env, phone) {
  try {
    const raw = await kvGetAcct(env, phone, "sustain");
    if (!raw) return null;
    const s = JSON.parse(raw);
    return s && s.trigger_at ? s : null;
  } catch { return null; }
}

async function setSustain(env, phone, minutes, mode = "once", total = 1) {
  const now = Date.now();
  const s = {
    trigger_at: new Date(now + minutes * 60 * 1000).toISOString(),
    set_at: new Date(now).toISOString(),
    minutes,
    mode, // "once" | "loop" | "count"
    remaining: mode === "loop" ? null : total,
    total: mode === "loop" ? null : total,
  };
  await kvPutAcct(env, phone, "sustain", JSON.stringify(s));
  return s;
}

async function setSustainMode(env, phone, mode, total = 1) {
  const s = await getSustain(env, phone);
  if (!s) return null;
  s.mode = mode;
  s.total = mode === "loop" ? null : total;
  s.remaining = mode === "loop" ? null : total;
  await kvPutAcct(env, phone, "sustain", JSON.stringify(s));
  return s;
}

async function clearSustain(env, phone) {
  await kvDeleteAcct(env, phone, "sustain");
}

function sustainLine(s) {
  if (!s) return "已关闭";
  if (s.mode === "loop") return `已开启，每 ${s.minutes} 分钟触发一次（循环），下次 ${fmtTime(s.trigger_at)} 触发`;
  if (s.mode === "count") return `已开启，每 ${s.minutes} 分钟触发一次（还剩 ${s.remaining} 次，共 ${s.total} 次），下次 ${fmtTime(s.trigger_at)} 触发`;
  return `已开启，${fmtTime(s.trigger_at)} 触发（${s.minutes} 分钟）`;
}

function sustainPickerKeyboard(phone, s) {
  // No timer yet: pick a duration to set it. A timer is already set:
  // the duration is chosen, so offer the mode instead (loop / count).
  if (!s) {
    return { inline_keyboard: [
      SUSTAIN_DURATIONS.map((m) => ({
        text: m >= 60 ? `${m / 60} 小时` : `${m} 分钟`,
        callback_data: `sustain_flood_on:${m}:${phone}`,
      })),
    ] };
  }
  return { inline_keyboard: [
    [
      { text: "🔁 循环", callback_data: `sustain_mode:loop:${phone}` },
      { text: "🔢 选择次数", callback_data: `sustain_mode:count:${phone}` },
    ],
    [{ text: "❌ 关闭", callback_data: `sustain_flood_off:${phone}` }],
  ] };
}

function sustainCountKeyboard(phone) {
  return { inline_keyboard: [
    [1, 3, 5, 10].map((n) => ({
      text: `${n} 次`,
      callback_data: `sustain_count:${n}:${phone}`,
    })),
    [{ text: "❌ 关闭", callback_data: `sustain_flood_off:${phone}` }],
  ] };
}

// Flood trigger history (v1.4.15): per-account list of trigger times
// (ISO strings) in KV key "flood_triggers", pruned to the last 24h.
// The recovery estimate follows the count: 1st-3rd triggers 1h,
// 4th 6h, 5th and later 24h.
const FLOOD_HISTORY_WINDOW_MS = 24 * 3600 * 1000;
function estimateHoursForCount(n) {
  if (n <= 3) return 1;
  if (n === 4) return 6;
  return 24;
}
async function recordFloodTrigger(env, phone, atMs) {
  let hist = [];
  try {
    const raw = await kvGetAcct(env, phone, "flood_triggers");
    if (raw) { const parsed = JSON.parse(raw); if (Array.isArray(parsed)) hist = parsed; }
  } catch { hist = []; }
  const cutoff = atMs - FLOOD_HISTORY_WINDOW_MS;
  hist = hist.filter((t) => { const ms = Date.parse(t); return Number.isFinite(ms) && ms > cutoff; });
  hist.push(new Date(atMs).toISOString());
  await kvPutAcct(env, phone, "flood_triggers", JSON.stringify(hist));
  return hist.length;
}

async function frozenInfo(env, phone) {
  const raw = await kvGetAcct(env, phone, "code_frozen");
  if (!raw) return null;
  try { return JSON.parse(raw); } catch { return { broken: true }; }
}

// A login code arriving (or a new session appearing) proves the code
// channel works again: auth.sendCode itself returns PHONE_PASSWORD_FLOOD /
// PHONE_NUMBER_FLOOD while a flood is active, so no code can arrive
// during one. Clear the stale record and tell the owner once.
// Called from /code-alert and /sync; no-ops when no record exists.
// Recency guard (v1.4.13): a record stored less than 10 minutes ago is
// never cleared here — a session that fast is the freeze's own throwaway
// client, not proof of recovery. /clear_flood bypasses the guard.
const FLOOD_RECENT_MS = 10 * 60 * 1000;
async function clearFloodIfActive(env, ctx, phone, notify = true, guardRecent = true) {
  const raw = await kvGetAcct(env, phone, "code_frozen");
  if (!raw) return false;
  if (guardRecent) {
    try {
      const rec = JSON.parse(raw);
      const frozenMs = rec && rec.frozen_at ? Date.parse(rec.frozen_at) : NaN;
      if (Number.isFinite(frozenMs) && Date.now() - frozenMs < FLOOD_RECENT_MS) return false;
    } catch { /* unparsable record: clear it as before */ }
  }
  await kvDeleteAcct(env, phone, "code_frozen");
  const label = await accountLabelFor(env, phone);
  await appendAlert(env, phone, `[${new Date().toISOString()}] Flood保护已恢复`);
  if (notify) {
    const notice = sendMessage(env, env.OWNER_ID, `✅ TG Guardian【${label}】：Flood保护已恢复。`);
    if (ctx) ctx.waitUntil(notice); else await notice;
  }
  return true;
}

// Did a layer actually trigger? New records (monitor v0.5.3+) carry
// explicit triggered / twofa_triggered flags. Older records have none,
// so infer from the outcome wording: anything saying it never started,
// was interrupted, failed, or hit the no-2FA anomaly means not triggered.
// A record that merely exists must never by itself read as "triggered".
function notTriggeredText(t) {
  return /未执行|未开始|中断|失败|^异常|已过期/.test(String(t || ""));
}
function codeTriggered(f) {
  if (f.triggered === true) return true;
  if (f.triggered === false) return false;
  if (!f.outcome) return false;
  return !notTriggeredText(f.outcome);
}
function twofaTriggered(f) {
  if (f.twofa_triggered === true) return true;
  if (f.twofa_triggered === false) return false;
  if (!f.twofa_outcome) return false;
  return !notTriggeredText(f.twofa_outcome);
}
function shortTwofaOutcome(f) {
const o = f.twofa_outcome || "";
if (/不需要二级密码|未设二级密码/.test(o)) return "未触发（账号未设二级密码）";
if (twofaTriggered(f) || /已触发限制/.test(o)) return "已触发";
if (!o || o === "未执行") return "未触发";
return o;
}

function frozenLine(f) {
  if (!f) return "未冻结";
  if (f.broken) return "已冻结（记录损坏）";
  const rec = fmtTime(f.expected_recovery_at);
  const ct = codeTriggered(f);
  const tt = twofaTriggered(f);
  let line;
  if (f.mode === "2fa") {
    line = tt ? `Flood保护已触发，预计恢复：${rec}` : "Flood保护未触发";
  } else if (f.mode === "code") {
    line = ct ? `验证码已冻结，预计恢复：${rec}` : "验证码冻结未触发";
  } else if (f.mode === "both") {
    if (ct && tt) line = `验证码 + Flood保护已触发，预计恢复：${rec}`;
    else if (ct) line = `验证码已冻结，预计恢复：${rec}；Flood保护未触发`;
    else if (tt) line = `Flood保护已触发，预计恢复：${rec}；验证码冻结未触发`;
    else line = "验证码 + Flood保护均未触发";
  } else {
    line = `已冻结，预计恢复：${rec}`;
  }
  const recMs = f.expected_recovery_at ? Date.parse(f.expected_recovery_at) : NaN;
  if (Number.isFinite(recMs) && Date.now() > recMs && (ct || tt)) line += "（已过预计恢复时间）";
  if (f.twofa_outcome && /不需要二级密码|未设二级密码/.test(f.twofa_outcome)) line += "；账号未设二级密码";
  if (!ct && f.outcome) line += `；验证码：${f.outcome}`;
  return line;
}

async function accountSummary(env, acct) {
  const phone = acct.phone;
  const settings = await getSettings(env, phone);
  const guardSec = settings.auto_code_after;
  const revokeSec = settings.auto_revoke_after;
  const pending = await getPendingList(env, phone);
  const open = pending.filter((p) => p.status === "pending");
  const codeEvents = await getCodeEvents(env, phone);
  const openCode = codeEvents.filter((c) => c.status === "pending");
  const f = await frozenInfo(env, phone);
  const hb = await kvGetAcct(env, phone, "mtproto_heartbeat");
  const hbMs = hb ? Date.parse(hb) : NaN;
  const hbAgeMin = Number.isFinite(hbMs) ? Math.round((Date.now() - hbMs) / 60000) : null;
  const sessionsRaw = await kvGetAcct(env, phone, "sessions");
  let sessionCount = null;
  if (sessionsRaw) {
    try {
      const arr = JSON.parse(sessionsRaw);
      if (Array.isArray(arr)) sessionCount = arr.length;
    } catch { sessionCount = null; }
  }
  return {
    acct, settings, guardSec, revokeSec, open, openCode, frozen: f,
    hb, hbAgeMin, sessionCount, sessionsRaw,
  };
}

async function runCommand(env, chatId, fromId, rawText) {
  const text = (rawText || "").trim();
  const cmd = text.split(/\s+/)[0].toLowerCase().replace(/@.*$/, "");
  const args = text.split(/\s+/).slice(1);

  if (!isOwner(env, fromId)) {
    return sendMessage(env, chatId, "⛔ 这个机器人只接受管理员指令。");
  }

  if (cmd === "/start") {
    await ensureMenu(env);
    return sendMessage(env, chatId, "✅ TG Guardian 已启动，监控正在运行。\n\n" + HELP_TEXT, true);
  }
  if (cmd === "/help") {
    return sendMessage(env, chatId, HELP_TEXT, true);
  }
  if (cmd === "/ping") {
    return sendMessage(env, chatId, "🏓 在线。Worker、Webhook、KV 都正常。");
  }
  if (cmd === "/test") {
    try {
      await env.TG_GUARD_DATA.put("kv_test", String(Date.now()));
      const back = await env.TG_GUARD_DATA.get("kv_test");
      return sendMessage(env, chatId, back ? "✅ 自检通过：Worker、KV、Bot 通信都正常。" : "❌ KV 读取失败。");
    } catch (e) {
      console.log("KV test error:", e);
      return sendMessage(env, chatId, "❌ KV 测试出错：" + String((e && e.message) || e));
    }
  }

  // --- Account management ---
  if (cmd === "/accounts") {
    const accounts = await getAccounts(env);
    const onboard = await getOnboard(env);
    if (!accounts.length && !onboard.length) {
      return sendMessage(env, chatId, "👥 还没有账号。\n发 /add_account <手机号> [名字] 添加第一个账号。", true);
    }
    let out = "👥 账号列表\n\n";
    for (const acct of accounts) {
      const s = await accountSummary(env, acct);
      const hbLine = s.hb
        ? (s.hbAgeMin !== null && s.hbAgeMin <= 120 ? `心跳正常（${s.hbAgeMin} 分钟前）` : `⚠️ 心跳超时（上次 ${fmtTime(s.hb)}）`)
        : "❌ 没有心跳";
      out += `${accountLabel(acct)} — ${displayPhone(acct.phone)}\n` +
        `  设备：${s.sessionCount !== null ? s.sessionCount + " 个" : "未知"} · ${hbLine}\n` +
        `  待确认：新设备 ${s.open.length} 个，验证码请求 ${s.openCode.length} 个\n` +
        `  Flood：${frozenLine(s.frozen)}\n\n`;
    }
    if (onboard.length) {
      out += "⏳ 正在添加：\n";
      for (const o of onboard) {
        const stateText = {
          pending_send: "正在发验证码…",
          code_sent: "验证码已发出，等你发 /code",
          code_received: "验证码已收到，正在登录…",
          code_invalid: "验证码不对，等你重发 /code",
          awaiting_2fa: "需要二级密码，等你发 /2fa",
          password_received: "二级密码已收到，正在验证…",
          password_invalid: "二级密码不对，等你重发 /2fa",
          send_failed: "验证码发送失败",
          flood: "请求验证码太频繁，被限流",
          cancelled: "正在取消…",
        }[o.state] || o.state;
        out += `· ${displayPhone(o.phone)}${o.name ? "（" + o.name + "）" : ""}：${stateText}\n`;
      }
    }
    return sendMessage(env, chatId, out, true);
  }
  if (cmd === "/add_account") {
    const phone = normalizePhone(args[0]);
    if (!phone) {
      return sendMessage(env, chatId, "用法：/add_account <手机号> [名字]\n例如：/add_account +8613800138000 小号", true);
    }
    const name = args.slice(1).join(" ") || "";
    const accounts = await getAccounts(env);
    if (accounts.find((a) => a.phone === phone)) {
      return sendMessage(env, chatId, `账号 ${displayPhone(phone)} 已经在监控了，发 /accounts 看看。`, true);
    }
    const onboard = await getOnboard(env);
    const existing = onboard.find((o) => o.phone === phone);
    if (existing) {
      return sendMessage(env, chatId, `账号 ${displayPhone(phone)} 正在添加中，当前状态：${existing.state}。\n取消请发 /cancel_add ${displayPhone(phone)}`, true);
    }
    onboard.push({ phone, name, state: "pending_send", created_at: new Date().toISOString() });
    await saveOnboard(env, onboard);
    return sendMessage(env, chatId,
      `已登记账号 ${displayPhone(phone)}${name ? "（" + name + "）" : ""}，监控端正在发验证码（最多 1 分钟）。\n` +
      "收到验证码后发给我：/code <验证码>\n\n" +
      "注意：验证码和二级密码只经过机器人中转，监控端收到就用、用完就删，不会存下来。", true);
  }
  if (cmd === "/code") {
    const code = (args[0] || "").replace(/[^0-9]/g, "");
    if (!/^\d{4,8}$/.test(code)) {
      return sendMessage(env, chatId, "用法：/code <验证码>，只发数字。\n现在没有正在等验证码的账号时，发了也没用，先发 /add_account <手机号>。", true);
    }
    const onboard = await getOnboard(env);
    const item = onboard.find((o) => ["code_sent", "code_invalid"].includes(o.state));
    if (!item) {
      return sendMessage(env, chatId, "现在没有正在等验证码的账号。先发 /add_account <手机号> 添加账号。", true);
    }
    item.code = code;
    item.state = "code_received";
    await saveOnboard(env, onboard);
    return sendMessage(env, chatId, `收到，正在给账号 ${displayPhone(item.phone)} 登录…（验证码不会显示出来）`, true);
  }
  if (cmd === "/2fa") {
    const password = args.join(" ");
    if (!password) {
      return sendMessage(env, chatId, "用法：/2fa <二级密码>\n只有正在添加、且账号开了二级密码时才需要发。", true);
    }
    const onboard = await getOnboard(env);
    const item = onboard.find((o) => ["awaiting_2fa", "password_invalid"].includes(o.state));
    if (!item) {
      return sendMessage(env, chatId, "现在没有正在等二级密码的账号。", true);
    }
    item.password = password;
    item.state = "password_received";
    await saveOnboard(env, onboard);
    return sendMessage(env, chatId, `收到，正在给账号 ${displayPhone(item.phone)} 验证二级密码…（密码不会显示出来）`, true);
  }
  if (cmd === "/cancel_add") {
    const phone = normalizePhone(args[0]);
    if (!phone) {
      return sendMessage(env, chatId, "用法：/cancel_add <手机号>", true);
    }
    const onboard = await getOnboard(env);
    const item = onboard.find((o) => o.phone === phone);
    if (!item) {
      return sendMessage(env, chatId, `账号 ${displayPhone(phone)} 没有在添加中。`, true);
    }
    if (item.state === "cancelled") {
      return sendMessage(env, chatId, `账号 ${displayPhone(phone)} 正在取消…`, true);
    }
    item.state = "cancelled";
    delete item.code;
    delete item.password;
    await saveOnboard(env, onboard);
    return sendMessage(env, chatId, `正在取消添加账号 ${displayPhone(phone)}…`, true);
  }
  if (cmd === "/remove_account") {
    const phone = normalizePhone(args[0]);
    if (!phone) {
      return sendMessage(env, chatId, "用法：/remove_account <手机号>\n删除会清掉这个账号的全部记录（待确认、冻结记录、告警、设置），监控端也会删掉它的会话文件。", true);
    }
    const accounts = await getAccounts(env);
    const acct = accounts.find((a) => a.phone === phone);
    if (!acct) {
      return sendMessage(env, chatId, `没找到账号 ${displayPhone(phone)}，发 /accounts 看看已有的账号。`, true);
    }
    if (accounts.length <= 1) {
      return sendMessage(env, chatId, "至少要保留一个账号，不能删掉最后一个。", true);
    }
    const confirm = args[1] === "确认";
    if (!confirm) {
      await kvPut(env, "pending_removal", JSON.stringify({ phone, at: Date.now() }));
      return sendMessage(env, chatId,
        `确定要删除账号 ${accountLabel(acct)}（${displayPhone(phone)}）吗？\n` +
        "会清掉：待确认记录、冻结记录、告警、设置、设备快照，监控端也会删掉它的会话文件。\n\n" +
        `确认删除请再发一次：/remove_account ${displayPhone(phone)} 确认`, true);
    }
    let pend = null;
    try { pend = JSON.parse((await kvGet(env, "pending_removal")) || "null"); } catch { pend = null; }
    if (!pend || pend.phone !== phone || Date.now() - pend.at > 5 * 60 * 1000) {
      return sendMessage(env, chatId, "确认已过期，请重新发 /remove_account <手机号> 再确认一次。", true);
    }
    await kvDelete(env, "pending_removal");
    await deleteAccountData(env, phone);
    await saveAccounts(env, accounts.filter((a) => a.phone !== phone));
    const removed = await getRemoved(env);
    if (!removed.find((r) => r.phone === phone)) removed.push({ phone, at: Date.now() });
    await saveRemoved(env, removed);
    return sendMessage(env, chatId, `✅ 已删除账号 ${accountLabel(acct)}（${displayPhone(phone)}）的全部记录，监控端会随后删掉它的会话文件。`, true);
  }

// --- Status commands: optional account arg; without one they show
// the single registered account directly, or ask which account when several are registered. ---
if (cmd === "/security" || cmd === "/status" || cmd === "/check") {
const res = await resolveAccountArg(env, args);
if (res.none) return sendMessage(env, chatId, "👥 还没有账号。发 /add_account <手机号> [名字] 添加第一个账号。", true);
if (res.error) return sendMessage(env, chatId, res.error, true);
if (res.needChoice) return sendMessage(env, chatId, choiceText(res.accounts) + `\n用法：${cmd} <手机号或名字>`, true);
const targets = res.account? [res.account]: res.accounts;
let out = "🛡️ TG Guardian " + (cmd === "/status"? "整体状态": "安全状态") + "\n\n" +
"管理机器人：在线 ✅\n" +
"Webhook：已连接 ✅\n" +
"KV 存储：正常 ✅\n";
for (const acct of targets) {
const s = await accountSummary(env, acct);
const hbLine = s.hb
? (s.hbAgeMin!== null && s.hbAgeMin <= 120? fmtTime(s.hb): `⚠️ 超时（上次 ${fmtTime(s.hb)}）`)
: "未知（监控未上报心跳）";
out += `\n【${accountLabel(acct)}】\n` +
`MTProto 监控心跳：${hbLine}\n` +
`设备快照：${s.sessionCount!== null? s.sessionCount + " 个已确认设备": "（快照在服务器本地）"}\n` +
`待确认的新设备：${s.open.length? s.open.length + ` 个，${s.revokeSec} 秒内没回复会自动注销`: "无"}\n` +
`待确认的验证码请求：${s.openCode.length? s.openCode.length + ` 个，${s.guardSec} 秒内没回复会自动冻结二级密码`: "无"}\n` +
`验证码功能：${frozenLine(s.frozen)}\n` +
`异常告警：${s.settings.alerts_enabled? "开 ✅": "关（只自动处理，不弹窗）"}\n`;
}
if (targets.length === 1) {
const s = await accountSummary(env, targets[0]);
out += `\n新设备登录时先发告警，${s.revokeSec} 秒内没回复自动注销，不用手动盯着。`;
}
return sendMessage(env, chatId, out, true);
}
if (cmd === "/devices" || cmd === "/sessions" || cmd === "/list") {
const res = await resolveAccountArg(env, args);
if (res.none) return sendMessage(env, chatId, "👥 还没有账号。发 /add_account <手机号> [名字] 添加第一个账号。", true);
if (res.error) return sendMessage(env, chatId, res.error, true);
if (res.needChoice) return sendMessage(env, chatId, choiceText(res.accounts) + `\n用法：${cmd} <手机号或名字>`, true);
const targets = res.account? [res.account]: res.accounts;
let out = "";
for (const acct of targets) {
const s = await accountSummary(env, acct);
out += `📱 【${accountLabel(acct)}】已登录设备\n\n`;
if (s.open.length) {
out += `⚠️ 待确认的新设备（${s.revokeSec} 秒内没回复会自动注销）：\n\n`;
for (const p of s.open) out += describePending(p) + "\n\n";
}
if (s.sessionsRaw) {
let rendered = null;
try {
const arr = JSON.parse(s.sessionsRaw);
if (Array.isArray(arr) && arr.length) {
rendered = arr.map((x, i) => `${i + 1}. ${fmtSession(x)}`).join("\n\n");
}
} catch { /* old plain-text snapshot, show as-is */}
out += `已确认设备快照：\n${rendered || s.sessionsRaw}\n\n`;
} else if (!s.open.length) {
out += "MTProto 监控端还没有把设备快照同步到 KV。\n" +
"监控本身每 5 分钟检查一次，基线已保存在服务器上；有新设备登录时会立即通过本机器人告警。\n" +
"也可以在 Telegram 设置 → 设备里直接查看当前登录设备。\n\n";
}
}
return sendMessage(env, chatId, out.trim(), true);
}
if (cmd === "/logs" || cmd === "/alerts") {
const res = await resolveAccountArg(env, args);
if (res.none) return sendMessage(env, chatId, "👥 还没有账号。发 /add_account <手机号> [名字] 添加第一个账号。", true);
if (res.error) return sendMessage(env, chatId, res.error, true);
if (res.needChoice) return sendMessage(env, chatId, choiceText(res.accounts) + `\n用法：${cmd} <手机号或名字>`, true);
const targets = res.account? [res.account]: res.accounts;
let out = "";
for (const acct of targets) {
const logs = await kvGetAcct(env, acct.phone, "alerts");
out += `📋 【${accountLabel(acct)}】最近告警（保留 30 天）\n\n`;
if (!logs) {
out += "最近没有告警记录。\n\n";
continue;
}
const lines = pruneAlertLines(logs).split("\n").filter((l) => l.trim()).slice(-15).map(reformatOldLine);
out += lines.join("\n") + "\n\n";
}
return sendMessage(env, chatId, out.trim(), true);
}
if (cmd === "/sustain_flood_on") {
  // /sustain_flood_on [minutes] [account]: turn on the one-shot timer.
  // No minutes = show the current state + a duration picker (default 30).
  // A numeric arg is minutes only when it fits 1-1440; a longer number
  // is a phone (account), so /sustain_flood_on <phone> shows the picker.
  const minutesArg = args.find((a) => /^\d+$/.test(a) && parseInt(a, 10) <= SUSTAIN_MAX_MIN);
  const rest = args.filter((a) => a !== minutesArg);
  const res = await resolveAccountArg(env, rest);
  if (res.none) return sendMessage(env, chatId, "👥 还没有账号。发 /add_account <手机号> [名字] 添加第一个账号。", true);
  if (res.error) return sendMessage(env, chatId, res.error, true);
  if (res.needChoice) return sendMessage(env, chatId, choiceText(res.accounts) + `\n用法：${cmd} [分钟] <手机号或名字>`, true);
  const acct = (res.account ? [res.account] : res.accounts)[0];
  if (!minutesArg) {
    const s = await getSustain(env, acct.phone);
    const state = s ? `持续Flood保护：${sustainLine(s)}` : "持续Flood保护：已关闭";
    const hint = s ? "选一个模式：循环是每隔设定时间触发一次不停，选择次数是触发指定次数后停止。" : "选一个时间，到时间自动触发一次 Flood 保护（默认 30 分钟）。";
    return sendMessage(env, chatId, `🌊 持续Flood保护\n\n【${accountLabel(acct)}】\n${state}\n\n${hint}`, true, sustainPickerKeyboard(acct.phone, s));
  }
  const minutes = parseInt(minutesArg, 10);
  if (minutes < 1) return sendMessage(env, chatId, `⏰ 时间要在 1–${SUSTAIN_MAX_MIN} 分钟之间（默认 30 分钟）。`, true);
  const s = await setSustain(env, acct.phone, minutes);
  return sendMessage(env, chatId, `✅ 持续Flood保护已开启【${accountLabel(acct)}】\n${minutes} 分钟后（${fmtTime(s.trigger_at)}）自动触发一次 Flood 保护。\n\n下面可以改成循环（每隔 ${minutes} 分钟触发一次不停）或指定次数；不选就是只触发一次，到时间自动关闭；随时用 /sustain_flood_off [账号] 取消。`, true, sustainPickerKeyboard(acct.phone, s));
}
if (cmd === "/sustain_flood_off") {
  const res = await resolveAccountArg(env, args);
  if (res.none) return sendMessage(env, chatId, "👥 还没有账号。发 /add_account <手机号> [名字] 添加第一个账号。", true);
  if (res.error) return sendMessage(env, chatId, res.error, true);
  if (res.needChoice) return sendMessage(env, chatId, choiceText(res.accounts) + `\n用法：${cmd} <手机号或名字>`, true);
  const acct = (res.account ? [res.account] : res.accounts)[0];
  await clearSustain(env, acct.phone);
  return sendMessage(env, chatId, `✅ 持续Flood保护已关闭【${accountLabel(acct)}】`, true);
}
if (cmd === "/rename_account") {
  // /rename_account [account] <new name>: rename an account. The last
  // argument is the new name; the rest identify the account (with one
  // account, just the new name is enough).
  if (!args.length) {
    return sendMessage(env, chatId, "用法：/rename_account [手机号或名字] <新名字>\n例如：/rename_account 0968 小号", true);
  }
  const newName = args[args.length - 1].trim();
  if (!newName || newName.length > 20 || /^\d+$/.test(newName)) {
    return sendMessage(env, chatId, "新名字不能为空、不要超过 20 个字、不能是纯数字。\n用法：/rename_account [手机号或名字] <新名字>", true);
  }
  const res = await resolveAccountArg(env, args.slice(0, -1));
  if (res.none) return sendMessage(env, chatId, "👥 还没有账号。发 /add_account <手机号> [名字] 添加第一个账号。", true);
  if (res.error) return sendMessage(env, chatId, res.error, true);
  if (res.needChoice) return sendMessage(env, chatId, choiceText(res.accounts) + `\n用法：${cmd} <手机号或名字> <新名字>`, true);
  const acct = (res.account ? [res.account] : res.accounts)[0];
  const list = await getAccounts(env);
  const clash = list.find((a) => a.phone !== acct.phone && a.name && a.name === newName);
  if (clash) {
    return sendMessage(env, chatId, `「${newName}」已经被【${accountLabel(clash)}】用了，换一个名字吧。`, true);
  }
  const target = list.find((a) => a.phone === acct.phone);
  if (!target) return sendMessage(env, chatId, "账号找不到了，发 /accounts 看看。", true);
  const oldLabel = accountLabel(target);
  target.name = newName;
  await saveAccounts(env, list);
  return sendMessage(env, chatId, `✅ 已改名：【${oldLabel}】→【${newName}（尾号 ${target.phone.slice(-4)}）】`, true);
}
if (cmd === "/login_guard") {
const res = await resolveAccountArg(env, args);
if (res.none) return sendMessage(env, chatId, "👥 还没有账号。发 /add_account <手机号> [名字] 添加第一个账号。", true);
if (res.error) return sendMessage(env, chatId, res.error, true);
if (res.needChoice) return sendMessage(env, chatId, choiceText(res.accounts) + `\n用法：${cmd} <手机号或名字>`, true);
const targets = res.account? [res.account]: res.accounts;
let out = "🛡️ 反登录防护状态\n";
for (const acct of targets) {
const s = await accountSummary(env, acct);
out += `\n【${accountLabel(acct)}】\n` +
`验证码自动保护：${s.guardSec} 秒无回复 → 自动冻结二级密码\n` +
`新设备自动注销：${s.revokeSec} 秒无回复 → 自动注销\n` +
`异常告警：${s.settings.alerts_enabled? "开 ✅": "关（只自动处理，不弹窗）"}\n` +
`待确认的新设备：${s.open.length? s.open.length + " 个": "无"}\n` +
`待确认的验证码请求：${s.openCode.length? s.openCode.length + " 个": "无"}\n` +
`Flood 状态：${frozenLine(s.frozen)}\n` +
`持续Flood保护：${sustainLine(await getSustain(env, acct.phone))}\n`;
}
out += "\n改时间：/set_guard <秒> [账号] 改自动冻结时间，/set_revoke <秒> [账号] 改自动注销时间（60–3600 秒，2 分钟内生效）。";
return sendMessage(env, chatId, out, true);
}
if (cmd === "/flood_status") {
const res = await resolveAccountArg(env, args);
if (res.none) return sendMessage(env, chatId, "👥 还没有账号。发 /add_account <手机号> [名字] 添加第一个账号。", true);
if (res.error) return sendMessage(env, chatId, res.error, true);
if (res.needChoice) return sendMessage(env, chatId, choiceText(res.accounts) + `\n用法：${cmd} <手机号或名字>`, true);
const targets = res.account? [res.account]: res.accounts;
let out = "🌊 Flood 状态\n";
let any = false;
for (const acct of targets) {
const f = await frozenInfo(env, acct.phone);
const s = await accountSummary(env, acct);
if (!f &&!s.openCode.length) continue;
any = true;
out += `\n【${accountLabel(acct)}】\n`;
if (f &&!f.broken) {
const rec = f.expected_recovery_at || "";
const recDate = rec? new Date(rec): null;
const inWindow = recDate &&!isNaN(recDate.getTime()) && Date.now() < recDate.getTime();
const ct = codeTriggered(f);
const tt = twofaTriggered(f);
const what = f.mode === "2fa"? "Flood保护": f.mode === "code"? "验证码冻结": f.mode === "both"? "验证码冻结 + Flood保护": "冻结";
out += `最近一次保护：${what}\n` +
`触发时间：${fmtTime(f.frozen_at)}\n` +
(f.flood_count ? `触发次数（24 小时内）：第 ${f.flood_count} 次\n` : "") +
(ct || tt? `预计恢复：${rec? fmtTime(rec): "未知"}\n` +
`当前状态：${!rec ? "限制中（恢复时间未知）" : inWindow ? "限制中" : "已过预计恢复时间"}\n`: `当前状态：未触发限制\n`) +
`验证码输错：${f.attempts || 0} 次\n` +
(f.twofa_outcome? `Flood保护：${shortTwofaOutcome(f)}。\n`: "") +
(f.outcome? `结果：${f.outcome}\n`: "");
} else if (f) {
out += "冻结记录损坏，读不出来。\n";
}
if (s.openCode.length) out += `待确认的验证码请求：${s.openCode.length} 个（超时会自动冻结二级密码）。\n`;
}
if (!any) out += "\n没有已记录的 Flood，也没有待确认的验证码请求。";
else out += "\n恢复时间按 24 小时内触发次数估算（前 3 次 1 小时，第 4 次 6 小时，第 5 次起 24 小时）；已登录的设备不受影响。";
return sendMessage(env, chatId, out, true);
}
if (cmd === "/security_check") {
const res = await resolveAccountArg(env, args);
if (res.none) return sendMessage(env, chatId, "👥 还没有账号。发 /add_account <手机号> [名字] 添加第一个账号。", true);
if (res.error) return sendMessage(env, chatId, res.error, true);
if (res.needChoice) return sendMessage(env, chatId, choiceText(res.accounts) + `\n用法：${cmd} <手机号或名字>`, true);
const targets = res.account? [res.account]: res.accounts;
const wh = await getWebhookInfo(env);
const whLine = wh
? (wh.url && wh.url.includes("tg-guardian")? `✅ 已指向 ${wh.url}`: `⚠️ Webhook 地址异常：${wh.url || "空"}`)
: "❌ 查不到 Webhook 信息";
const whPending = wh && wh.pending_update_count? `（积压 ${wh.pending_update_count} 条未处理更新）`: "";
let out = "🔍 防护系统检查\n\n" +
"管理机器人：在线 ✅\n" +
`Webhook：${whLine}${whPending}\n` +
"KV 存储：正常 ✅\n";
for (const acct of targets) {
const s = await accountSummary(env, acct);
const hbLine = s.hb
? (s.hbAgeMin!== null && s.hbAgeMin <= 120? `✅ 正常（${fmtTime(s.hb)}，${s.hbAgeMin} 分钟前）`: `⚠️ 超过 2 小时没上报（上次 ${fmtTime(s.hb)}）`)
: "❌ 未知（监控未上报心跳）";
out += `\n【${accountLabel(acct)}】\n` +
`MTProto 监控心跳：${hbLine}\n` +
`设备快照：${s.sessionCount!== null? s.sessionCount + " 个已确认设备": "未知（快照在服务器本地）"}\n` +
`待确认：新设备 ${s.open.length} 个，验证码请求 ${s.openCode.length} 个\n` +
`Flood 记录：${s.frozen? "有（/flood_status 看详情）": "无"}\n` +
`异常告警：${s.settings.alerts_enabled? "开 ✅": "关"}\n`;
}
out += "\n这是防护系统自己的检查。账号本身的二级密码、恢复邮箱机器人看不到，请在 Telegram 设置 → 隐私 → 两步验证里自己确认。";
return sendMessage(env, chatId, out, true);
}

if (cmd === "/alert_on" || cmd === "/alert_off") {
const res = await resolveAccountArg(env, args);
if (res.none) return sendMessage(env, chatId, "👥 还没有账号。发 /add_account <手机号> [名字] 添加第一个账号。", true);
if (res.error) return sendMessage(env, chatId, res.error, true);
if (res.needChoice) return sendMessage(env, chatId, choiceText(res.accounts) + `\n用法：${cmd} <手机号或名字>`, true);
const settings = await getSettings(env, res.account.phone);
settings.alerts_enabled = cmd === "/alert_on";
await saveSettings(env, res.account.phone, settings);
return sendMessage(env, chatId,
settings.alerts_enabled
? `✅ 账号【${accountLabel(res.account)}】告警已开启。`
: `🔕 账号【${accountLabel(res.account)}】告警已关闭：不再弹窗，超时仍会自动处理，结果仍会通知你。\n\n想重新开启：/alert_on ${displayPhone(res.account.phone)}`, true);
}
if (cmd === "/clear_alerts" || cmd === "/clear_logs") {
const res = await resolveAccountArg(env, args);
if (res.none) return sendMessage(env, chatId, "👥 还没有账号。发 /add_account <手机号> [名字] 添加第一个账号。", true);
if (res.error) return sendMessage(env, chatId, res.error, true);
if (res.needChoice) return sendMessage(env, chatId, choiceText(res.accounts) + `\n用法：${cmd} <手机号或名字>`, true);
const logs = (await kvGetAcct(env, res.account.phone, "alerts")) || "";
const n = logs.split("\n").filter((l) => l.trim()).length;
await kvPutAcct(env, res.account.phone, "alerts", "");
return sendMessage(env, chatId, n? `✅ 已手动清空账号【${accountLabel(res.account)}】的最近告警，共清掉 ${n} 条。`: `📋 账号【${accountLabel(res.account)}】最近没有告警记录，不用清空。`, true);
}
if (cmd === "/clear_flood") {
const res = await resolveAccountArg(env, args);
if (res.none) return sendMessage(env, chatId, "👥 还没有账号。发 /add_account <手机号> [名字] 添加第一个账号。", true);
if (res.error) return sendMessage(env, chatId, res.error, true);
if (res.needChoice) return sendMessage(env, chatId, choiceText(res.accounts) + `\n用法：${cmd} <手机号或名字>`, true);
const cleared = await clearFloodIfActive(env, null, res.account.phone, false, false);
return sendMessage(env, chatId, cleared? `✅ 已手动清除账号【${accountLabel(res.account)}】的 Flood 记录，面板将显示未触发。`: `📋 账号【${accountLabel(res.account)}】没有已记录的 Flood，不用清除。`, true);
}
if (cmd === "/check_flood") {
const res = await resolveAccountArg(env, args);
if (res.none) return sendMessage(env, chatId, "👥 还没有账号。发 /add_account <手机号> [名字] 添加第一个账号。", true);
if (res.error) return sendMessage(env, chatId, res.error, true);
if (res.needChoice) return sendMessage(env, chatId, choiceText(res.accounts) + `\n用法：${cmd} <手机号或名字>`, true);
const existing = await kvGetAcct(env, res.account.phone, "flood_probe");
if (existing) return sendMessage(env, chatId, `🔍 账号【${accountLabel(res.account)}】已经在检查了，稍等，结果会通知你。`, true);
await kvPutAcct(env, res.account.phone, "flood_probe", JSON.stringify({ requested_at: new Date().toISOString() }));
return sendMessage(env, chatId, `🔍 已安排检查账号【${accountLabel(res.account)}】的 Flood 状态，监控端 2 分钟内开始探测，结果会通知你。\n\n可能会收到一次验证码，忽略即可。`, true);
}
if (cmd === "/set_guard" || cmd === "/set_revoke") {
// Accept seconds and account in either order: /set_guard 300,
// /set_guard +8613800138000 300, /set_guard 300 小号
let seconds = null;
const rest = [];
for (const a of args) {
const n = Number(a);
if (seconds === null && Number.isFinite(n) && Number.isInteger(n)) seconds = n;
else rest.push(a);
}
if (seconds === null || seconds < 60 || seconds > 3600) {
const which = cmd === "/set_guard"? "自动冻结二级密码": "自动注销新设备";
return sendMessage(env, chatId, `用法：${cmd} <秒> [账号]，秒是 60–3600 的整数。\n例如：${cmd} 300 就是把${which}的时间改成 300 秒。`, true);
}
const res = await resolveAccountArg(env, rest);
if (res.none) return sendMessage(env, chatId, "👥 还没有账号。发 /add_account <手机号> [名字] 添加第一个账号。", true);
if (res.error) return sendMessage(env, chatId, res.error, true);
if (res.needChoice) return sendMessage(env, chatId, choiceText(res.accounts) + `\n用法：${cmd} ${seconds} <手机号或名字>`, true);
const settings = await getSettings(env, res.account.phone);
settings[cmd === "/set_guard"? "auto_code_after": "auto_revoke_after"] = seconds;
await saveSettings(env, res.account.phone, settings);
const which = cmd === "/set_guard"? "验证码无人确认后自动冻结二级密码": "新设备无人确认后自动注销";
return sendMessage(env, chatId, `✅ 已设置：账号【${accountLabel(res.account)}】${which}的时间改成 ${seconds} 秒，2 分钟内生效。\n当前设置：冻结 ${settings.auto_code_after} 秒，注销 ${settings.auto_revoke_after} 秒。`, true);
}
// Unknown text / command from the owner: one short hint only, never the
// full help text (typing anything used to dump the whole help).
return sendMessage(env, chatId, "没这个指令，点左下角菜单或发 /help 看看。", true);
}

// Removed-account tombstones: KV "removed_accounts" = [{phone, at}].
// The monitor drops the client + session file for a listed phone, and
// the Worker clears entries older than 1 hour on each /pending.
async function getRemoved(env) {
  try {
    const raw = await kvGet(env, "removed_accounts");
    if (!raw) return [];
    const list = JSON.parse(raw);
    if (!Array.isArray(list)) return [];
    return list
      .map((r) => (typeof r === "string" ? { phone: r, at: 0 } : r))
      .filter((r) => r && normalizePhone(r.phone));
  } catch { return []; }
}

async function saveRemoved(env, list) {
return kvPut(env, "removed_accounts", JSON.stringify(list));
}

async function handleCodeDecision(env, cb, kind, phone, id) {
const events = await getCodeEvents(env, phone);
const item = events.find((c) => String(c.id) === String(id));
// Legacy "deny" (Worker <= 1.3.7, one 拒绝 button) is treated as
// deny_2fa here only for the callback text; the stored status stays
// "deny" so an older monitor still runs its combined protection.
const answerText = kind === "allow"? "已同意这次登录"
: kind === "deny_code"? "已拒绝，正在冻结验证码"
: kind === "deny_2fa"? "已拒绝，正在冻结二级密码"
: "已拒绝，正在冻结验证码并触发Flood保护";
await answerCallback(env, cb.id, answerText);
if (!item) {
return sendMessage(env, cb.message.chat.id, "⚠️ 没找到这条验证码记录，可能已处理或已过期。");
}
if (item.status!== "pending") {
const done = item.status === "allow"? "已同意"
: item.status === "deny_code"? "已拒绝·冻结验证码"
: item.status === "deny_2fa"? "已拒绝·冻结二级密码"
: "已处理";
return sendMessage(env, cb.message.chat.id, `这条验证码请求已经是「${done}」状态，不用重复操作。`);
}
item.status = kind;
item.decided_at = new Date().toISOString();
await saveCodeEvents(env, phone, events);
const verdict = kind === "allow"
? "✅ 已同意这次登录请求"
: kind === "deny_code"
? "🧊 已拒绝，监控端正在处理，过程中会再收到验证码消息忽略即可。"
: kind === "deny_2fa"
? "🔒 已拒绝，监控端正在处理，过程中会再收到验证码消息忽略即可。"
: "⛔ 已拒绝，监控端正在处理，过程中会再收到验证码消息忽略即可。";
const label = await accountLabelFor(env, phone);
await editMessage(env, cb.message.chat.id, cb.message.message_id,
`⚠️ TG Guardian【${label}】：有人正在请求登录验证码！\n\n` +
verdict);
if (kind!== "allow") {
const what = kind === "deny_code"? "冻结验证码功能": kind === "deny_2fa"? "冻结二级密码": "冻结验证码功能并触发Flood保护";
await sendMessage(env, cb.message.chat.id, `正在${what}，完成后会通知你预计恢复时间。`);
}
}

async function accountLabelFor(env, phone) {
const accounts = await getAccounts(env);
const acct = accounts.find((a) => a.phone === phone);
return accountLabel(acct || { phone, name: ""});
}

async function handleDecision(env, cb, kind, phone, hash) {
const pending = await getPendingList(env, phone);
const item = pending.find((p) => String(p.hash) === String(hash));
await answerCallback(env, cb.id, kind === "allow"? "已放行该设备": "已安排注销该设备");
if (!item) {
return sendMessage(env, cb.message.chat.id, "⚠️ 没找到这条待确认记录，可能已处理或已过期。");
}
if (item.status!== "pending") {
return sendMessage(env, cb.message.chat.id, `这条记录已经是「${item.status === "allow"? "已放行": "已注销"}」状态，不用重复操作。`);
}
item.status = kind;
item.decided_at = new Date().toISOString();
await savePendingList(env, phone, pending);
const verdict = kind === "allow"? "✅ 已放行": "⛔ 已注销";
const label = await accountLabelFor(env, phone);
await editMessage(env, cb.message.chat.id, cb.message.message_id,
`🚨 TG Guardian【${label}】：新设备登录\n\n${describePending(item)}\n\n${verdict}`);
if (kind === "revoke") {
await sendMessage(env, cb.message.chat.id, "正在注销该设备，监控端确认后会再通知。");
}
}

export default {
async fetch(request, env, ctx) {
const url = new URL(request.url);

if (request.method === "GET" && url.pathname === "/") {
const checks = {
BOT_TOKEN:!!env.BOT_TOKEN,
OWNER_ID:!!env.OWNER_ID,
WEBHOOK_SECRET:!!env.WEBHOOK_SECRET,
TG_GUARD_DATA:!!env.TG_GUARD_DATA,
};
try {
if (env.TG_GUARD_DATA) {
await env.TG_GUARD_DATA.put("health_check", "ok");
checks.KV_PUT = true;
checks.KV_GET = (await env.TG_GUARD_DATA.get("health_check")) === "ok";
}
} catch (e) {
checks.KV_PUT = false;
checks.KV_GET = false;
console.log("health KV error:", e);
}
const accounts = await getAccounts(env);
return Response.json({ ok: true, service: "TG Guardian", version: VERSION, status: "running", accounts: accounts.length, checks});
}

// Which account does a monitor call belong to? The monitor always
// sends body.account (v0.5.0+). Without it: the single account if
// there is exactly one, or legacy unprefixed keys if none yet.
async function resolveBodyAccount(body) {
const p = normalizePhone(body && body.account);
if (p) return p;
const accounts = await getAccounts(env);
if (accounts.length === 1) return accounts[0].phone;
if (accounts.length === 0) return null;
return undefined; // ambiguous: several accounts, none named
}

// MTProto monitor polls owner decisions for ALL accounts at once.
// Auth:?token=<BOT_TOKEN>. One call per minute covers every
// account, so adding accounts does not multiply request counts.
if (request.method === "GET" && url.pathname === "/pending") {
if (url.searchParams.get("token")!== env.BOT_TOKEN) {
return new Response("Forbidden", { status: 403});
}
const accounts = await getAccounts(env);
const per_account = {};
for (const acct of accounts) {
const probeRaw = await kvGetAcct(env, acct.phone, "flood_probe");
let flood_probe = null;
try { flood_probe = probeRaw ? JSON.parse(probeRaw) : null; } catch { flood_probe = null; }
per_account[acct.phone] = {
pending: await getPendingList(env, acct.phone),
code_events: await getCodeEvents(env, acct.phone),
settings: await getSettings(env, acct.phone),
flood_probe,
sustain: await getSustain(env, acct.phone),
};
}
// Onboard requests: hand secrets to the monitor exactly once.
// The code / password are stripped from the stored record as soon
// as they are handed over, so they never sit in KV afterwards.
const onboard = await getOnboard(env);
let onboardChanged = false;
const onboardOut = onboard.map((o) => {
const out = {...o};
if (out.code || out.password) {
onboardChanged = true;
delete o.code;
delete o.password;
}
return out;
});
if (onboardChanged) await saveOnboard(env, onboard);
const removed = (await getRemoved(env))
.filter((r) => r && r.phone && (!r.at || Date.now() - r.at < 3600 * 1000))
.map((r) => r.phone);
const first = accounts[0];
return Response.json({
ok: true,
accounts,
removed,
onboard: onboardOut,
per_account,
// Legacy top-level fields for the first account, so an older
// monitor keeps working during the deploy window.
pending: first? per_account[first.phone].pending: [],
code_events: first? per_account[first.phone].code_events: [],
settings: first? per_account[first.phone].settings: {...DEFAULT_SETTINGS},
});
}

// Monitor self-registers its main account on startup. The first
// registration also migrates the original single account's legacy
// KV keys to the acct: prefix.
if (request.method === "POST" && url.pathname === "/register-account") {
let body;
try { body = await request.json();} catch { return new Response("Bad Request", { status: 400});}
if (body.token!== env.BOT_TOKEN) {
return new Response("Forbidden", { status: 403});
}
const phone = normalizePhone(body.phone);
if (!phone) return new Response("Bad Request", { status: 400});
const name = String(body.name || "").trim();
const accounts = await getAccounts(env);
const first = accounts.length === 0;
if (first) await migrateLegacyKeys(env, phone);
const existing = accounts.find((a) => a.phone === phone);
if (existing) {
if (name) existing.name = name;
} else {
accounts.push({ phone, name});
}
await saveAccounts(env, accounts);
return Response.json({ ok: true, accounts});
}

// Monitor reports add-account progress. The Worker updates the
// onboard record and messages the owner with the next step.
if (request.method === "POST" && url.pathname === "/onboard-status") {
let body;
try { body = await request.json();} catch { return new Response("Bad Request", { status: 400});}
if (body.token!== env.BOT_TOKEN) {
return new Response("Forbidden", { status: 403});
}
const phone = normalizePhone(body.phone);
const state = String(body.state || "");
const detail = String(body.detail || "");
if (!phone ||!state) return new Response("Bad Request", { status: 400});
const onboard = await getOnboard(env);
const item = onboard.find((o) => o.phone === phone);
if (!item) return Response.json({ ok: false, error: "no such onboard"});
const label = item.name? `${item.name}（尾号 ${phone.slice(-4)}）`: `尾号 ${phone.slice(-4)}`;
const terminal = ["done", "failed", "send_failed", "flood", "cancelled_done"];
const messages = {
code_sent: `📩 验证码已发到账号【${label}】，请发 /code <验证码>（只发数字）`,
code_invalid: `⚠️ 账号【${label}】的验证码不对或已过期，请重新发一次：/code <验证码>`,
awaiting_2fa: `🔐 账号【${label}】需要二级密码，请发：/2fa <二级密码>`,
password_invalid: `⚠️ 账号【${label}】的二级密码不对，请重新发：/2fa <二级密码>`,
done: `✅ 账号【${label}】已添加并开始监控。`,
failed: `❌ 账号【${label}】添加失败：${detail || "未知原因"}，可重新 /add_account ${displayPhone(phone)} 添加。`,
send_failed: `❌ 账号【${label}】验证码发送失败：${detail || "未知原因"}，请过一会儿重新发 /add_account ${displayPhone(phone)} 再试。`,
flood: `⏳ 账号【${label}】请求验证码太频繁，被 Telegram 限流${detail? "：" + detail: ""}，过一会儿再发 /add_account ${displayPhone(phone)} 重试。`,
cancelled_done: `🗑️ 已取消添加账号【${label}】。`,
};
if (state === "done") {
const accounts = await getAccounts(env);
if (!accounts.find((a) => a.phone === phone)) {
accounts.push({ phone, name: item.name || ""});
await saveAccounts(env, accounts);
}
}
if (terminal.includes(state)) {
await saveOnboard(env, onboard.filter((o) => o.phone!== phone));
} else {
item.state = state;
if (detail) item.detail = detail;
await saveOnboard(env, onboard);
}
if (messages[state]) {
ctx.waitUntil(sendMessage(env, env.OWNER_ID, messages[state], true));
}
return Response.json({ ok: true});
}

// MTProto monitor uploads a heartbeat + device snapshot once an hour
// per account. Auth: JSON {token: <BOT_TOKEN>, account,...}.
if (request.method === "POST" && url.pathname === "/heartbeat") {
let body;
try { body = await request.json();} catch { return new Response("Bad Request", { status: 400});}
if (body.token!== env.BOT_TOKEN) {
return new Response("Forbidden", { status: 403});
}
const phone = await resolveBodyAccount(body);
if (phone === undefined) return new Response("Bad Request", { status: 400});
// Flood record expiry (v1.4.10): the flood lasts at most ~1h, so once the
// estimated recovery time has passed, clear the record without probing.
// Checked on the hourly heartbeat: +1 KV read per account per hour, and
// the clear lands within 1h of expiry. Reuses clearFloodIfActive's delete
// + log + "Flood保护已恢复" notice.
const fr = await frozenInfo(env, phone);
if (fr) {
const recMs = fr.expected_recovery_at ? Date.parse(fr.expected_recovery_at) : NaN;
if (Number.isFinite(recMs) && Date.now() > recMs && (codeTriggered(fr) || twofaTriggered(fr))) {
await clearFloodIfActive(env, ctx, phone);
}
}
const at = body.at || new Date().toISOString();
await kvPutAcct(env, phone, "mtproto_heartbeat", at);
if (Array.isArray(body.sessions) && body.sessions.length) {
await kvPutAcct(env, phone, "sessions", JSON.stringify(body.sessions));
}
return Response.json({ ok: true});
}

// MTProto monitor reports a login-code request.
// Auth: JSON {token: <BOT_TOKEN>, account,...}.
if (request.method === "POST" && url.pathname === "/code-alert") {
let body;
try { body = await request.json();} catch { return new Response("Bad Request", { status: 400});}
if (body.token!== env.BOT_TOKEN ||!body.event_id) {
return new Response("Forbidden", { status: 403});
}
const phone = await resolveBodyAccount(body);
if (phone === undefined) return new Response("Bad Request", { status: 400});
await clearFloodIfActive(env, ctx, phone);
const item = {
id: String(body.event_id),
detected_at: body.detected_at || new Date().toISOString(),
status: "pending",
};
const events = await getCodeEvents(env, phone);
const existing = events.find((c) => c.id === item.id);
if (existing && existing.status === "pending") {
return Response.json({ ok: true, already_pending: true});
}
const next = events.filter((c) => c.id!== item.id);
next.push(item);
await saveCodeEvents(env, phone, next);
const label = await accountLabelFor(env, phone);
await appendAlert(env, phone, `[${item.detected_at}] 验证码请求待确认`);
const settings = await getSettings(env, phone);
const guardSec = settings.auto_code_after;
const alertText =
`⚠️ TG Guardian【${label}】：有人正在请求登录验证码！\n\n` +
"是你本人在登录吗？\n\n" +
"🧊 拒绝·冻结验证码：约 1 小时收不到验证码。\n" +
"🔒 拒绝·冻结二级密码：触发洪水保护，恢复时间按触发次数估算，期间谁都登不上去。\n" +
`${guardSec} 秒内没回复会自动冻结二级密码。`;
const kb = {
inline_keyboard: [
[{ text: "✅ 同意", callback_data: `code_allow:${phone}:${item.id}`}],
[
{ text: "🧊 拒绝·冻结验证码", callback_data: `code_deny_code:${phone}:${item.id}`},
{ text: "🔒 拒绝·冻结二级密码", callback_data: `code_deny_2fa:${phone}:${item.id}`},
],
],
};
// Alerts off (/alert_off): still store the event so the monitor can
// auto-act on it, but do not pop up a message.
if (settings.alerts_enabled!== false) {
ctx.waitUntil(sendMessage(env, env.OWNER_ID, alertText, false, kb));
}
return Response.json({ ok: true, alert_sent: settings.alerts_enabled!== false});
}

// MTProto monitor reports a code-freeze result.
// Auth: JSON {token: <BOT_TOKEN>, account,...}.
// MTProto monitor reports a manual flood check (/check_flood).
// Auth: JSON {token: <BOT_TOKEN>, account, lifted, detail}.
if (request.method === "POST" && url.pathname === "/flood-probe") {
let body;
try { body = await request.json();} catch { return new Response("Bad Request", { status: 400});}
if (body.token!== env.BOT_TOKEN ||!body.account) {
return new Response("Forbidden", { status: 403});
}
const phone = await resolveBodyAccount(body);
if (phone === undefined) return new Response("Bad Request", { status: 400});
await kvDeleteAcct(env, phone, "flood_probe");
const label = await accountLabelFor(env, phone);
if (body.lifted) {
await kvDeleteAcct(env, phone, "code_frozen");
await appendAlert(env, phone, `[${new Date().toISOString()}] Flood保护已恢复（手动检查）`);
ctx.waitUntil(sendMessage(env, env.OWNER_ID, `✅ TG Guardian【${label}】：Flood保护已恢复。`));
} else {
const waitSec = Number(body.wait_seconds);
const hasWait = Number.isFinite(waitSec) && waitSec > 0;
const nowMs = Date.now();
const nowIso = new Date(nowMs).toISOString();
if (body.flood_active === true) {
let rec = await frozenInfo(env, phone);
if (rec && !rec.broken) {
if (hasWait) {
rec.expected_recovery_at = new Date(nowMs + waitSec * 1000).toISOString();
await kvPutAcct(env, phone, "code_frozen", JSON.stringify(rec));
}
} else {
rec = {
event_id: `probe:${phone}:${Math.floor(nowMs / 1000)}`,
frozen_at: nowIso,
expected_recovery_at: hasWait ? new Date(nowMs + waitSec * 1000).toISOString() : "",
mode: "2fa",
attempts: 0,
outcome: "仍在限制中（手动检查）",
twofa_attempts: 0,
twofa_outcome: "已触发（手动检查）",
triggered: true,
twofa_triggered: true,
};
await kvPutAcct(env, phone, "code_frozen", JSON.stringify(rec));
}
const recTime = rec && rec.expected_recovery_at ? fmtTime(rec.expected_recovery_at) : "未知";
await appendAlert(env, phone, `[${nowIso}] Flood检查：仍在限制中（${body.detail || ""}）`);
ctx.waitUntil(sendMessage(env, env.OWNER_ID, `🌊 TG Guardian【${label}】：Flood保护还在限制中，预计恢复 ${recTime}。`));
} else if (body.flood_active === false) {
await appendAlert(env, phone, `[${nowIso}] Flood检查失败（${body.detail || ""}）`);
ctx.waitUntil(sendMessage(env, env.OWNER_ID, `⚠️ TG Guardian【${label}】：Flood 检查失败（${body.detail || "未知原因"}），没有改动记录，稍后再试。`));
} else {
const f = await frozenInfo(env, phone);
const rec = f && f.expected_recovery_at ? fmtTime(f.expected_recovery_at) : "未知";
await appendAlert(env, phone, `[${nowIso}] Flood检查：仍在限制中（${body.detail || ""}）`);
ctx.waitUntil(sendMessage(env, env.OWNER_ID, `🌊 TG Guardian【${label}】：Flood保护还在限制中，预计恢复 ${rec}。`));
}
}
return Response.json({ ok: true});
}

if (request.method === "POST" && url.pathname === "/code-freeze") {
let body;
try { body = await request.json();} catch { return new Response("Bad Request", { status: 400});}
if (body.token!== env.BOT_TOKEN ||!body.event_id) {
return new Response("Forbidden", { status: 403});
}
const phone = await resolveBodyAccount(body);
if (phone === undefined) return new Response("Bad Request", { status: 400});
const record = {
event_id: String(body.event_id),
frozen_at: body.frozen_at || new Date().toISOString(),
expected_recovery_at: body.expected_recovery_at || "",
mode: body.mode || "",
attempts: body.attempts || 0,
outcome: body.outcome || "",
twofa_attempts: body.twofa_attempts || 0,
twofa_outcome: body.twofa_outcome || "",
};
if (body.triggered !== undefined) record.triggered = !!body.triggered;
if (body.twofa_triggered !== undefined) record.twofa_triggered = !!body.twofa_triggered;
// Recovery estimate by trigger count (v1.4.15): the 2FA flood estimate
// follows how many times this account triggered in the last 24h
// (1st-3rd 1h, 4th 6h, 5th+ 24h). The Worker owns the estimate so the
// panel and the monitor's result alert agree; the monitor's own
// value is only a fallback for an older Worker.
let floodCount = 0;
let estimateHours = 0;
if (twofaTriggered(record)) {
  floodCount = await recordFloodTrigger(env, phone, Date.parse(record.frozen_at) || Date.now());
  estimateHours = estimateHoursForCount(floodCount);
  const frozenMs = Date.parse(record.frozen_at) || Date.now();
  record.expected_recovery_at = new Date(frozenMs + estimateHours * 3600 * 1000).toISOString();
  record.flood_count = floodCount;
  record.estimate_hours = estimateHours;
}
await kvPutAcct(env, phone, "code_frozen", JSON.stringify(record));
// A scheduled (sustain) trigger fired: one-shot clears the timer;
// loop reschedules it, count decrements and reschedules until done.
let sustainOut = null;
if (String(record.event_id || '').startsWith("sustain:")) {
  const s = await getSustain(env, phone);
  if (s) {
    if (s.mode === "loop") {
      s.trigger_at = new Date(Date.now() + (s.minutes || SUSTAIN_DEFAULT_MIN) * 60 * 1000).toISOString();
      await kvPutAcct(env, phone, "sustain", JSON.stringify(s));
      sustainOut = { mode: "loop", remaining: null, total: null, next_trigger_at: s.trigger_at, minutes: s.minutes };
    } else if (s.mode === "count") {
      const left = Math.max(0, (s.remaining || 1) - 1);
      if (left > 0) {
        s.remaining = left;
        s.trigger_at = new Date(Date.now() + (s.minutes || SUSTAIN_DEFAULT_MIN) * 60 * 1000).toISOString();
        await kvPutAcct(env, phone, "sustain", JSON.stringify(s));
        sustainOut = { mode: "count", remaining: left, total: s.total, next_trigger_at: s.trigger_at, minutes: s.minutes };
      } else {
        await clearSustain(env, phone);
        sustainOut = { mode: "count", remaining: 0, total: s.total, next_trigger_at: null, minutes: s.minutes };
      }
    } else {
      // "once" (or an older record without a mode): clear it.
      await clearSustain(env, phone);
      sustainOut = { mode: "once", remaining: 0, total: 1, next_trigger_at: null, minutes: s.minutes };
    }
  }
}
const events = await getCodeEvents(env, phone);
const item = events.find((c) => c.id === record.event_id);
if (item) {
item.status = "frozen";
item.frozen_at = record.frozen_at;
item.expected_recovery_at = record.expected_recovery_at;
await saveCodeEvents(env, phone, events);
}
let line;
if (record.mode === "2fa") {
line = `[${record.frozen_at}] Flood保护：${shortTwofaOutcome(record)}` +
(twofaTriggered(record) && record.expected_recovery_at? `，预计恢复 ${record.expected_recovery_at}`: "");
} else if (record.mode === "code") {
line = `[${record.frozen_at}] 验证码冻结：` +
(codeTriggered(record) && record.expected_recovery_at? `已触发，预计恢复 ${record.expected_recovery_at}`: `未触发，${record.outcome}`);
} else {
line = `[${record.frozen_at}] 验证码冻结：` +
(codeTriggered(record) && record.expected_recovery_at? `已触发，预计恢复 ${record.expected_recovery_at}`: "未触发");
if (record.twofa_outcome) line += `；Flood保护：${shortTwofaOutcome(record)}`;
}
await appendAlert(env, phone, line);
return Response.json({ ok: true, ...(floodCount ? { flood_count: floodCount, estimate_hours: estimateHours, expected_recovery_at: record.expected_recovery_at } : {}), ...(sustainOut ? { sustain: sustainOut } : {}) });
}

// MTProto monitor reports a new device.
// Auth: JSON {token: <BOT_TOKEN>, account,...}.
if (request.method === "POST" && url.pathname === "/sync") {
let body;
try { body = await request.json();} catch { return new Response("Bad Request", { status: 400});}
if (body.token!== env.BOT_TOKEN ||!body.hash) {
return new Response("Forbidden", { status: 403});
}
const phone = await resolveBodyAccount(body);
if (phone === undefined) return new Response("Bad Request", { status: 400});
await clearFloodIfActive(env, ctx, phone);
const item = {
hash: String(body.hash),
device: body.device || "?",
platform: body.platform || "?",
app: body.app || "?",
ip: body.ip || "?",
country: body.country || "?",
region: body.region || "",
created: body.created || "?",
detected_at: body.detected_at || new Date().toISOString(),
status: "pending",
};
const pending = await getPendingList(env, phone);
const existing = pending.find((p) => p.hash === item.hash);
if (existing && existing.status === "pending") {
return Response.json({ ok: true, already_pending: true});
}
const next = pending.filter((p) => p.hash!== item.hash);
next.push(item);
await savePendingList(env, phone, next);
const label = await accountLabelFor(env, phone);
const line = `[${item.detected_at}] 新设备待确认：${item.device} ${item.app} ${item.country}`;
await appendAlert(env, phone, line);
const settings = await getSettings(env, phone);
const revokeSec = settings.auto_revoke_after;
const alertText =
`🚨 TG Guardian【${label}】：新设备登录\n\n` +
describePending(item) + "\n\n" +
`是你本人吗？${revokeSec} 秒没回复自动注销。`;
const kb = {
inline_keyboard: [[
{ text: "✅ 是我本人", callback_data: `allow:${phone}:${item.hash}`},
{ text: "⛔ 踢掉", callback_data: `revoke:${phone}:${item.hash}`},
]],
};
// Alerts off (/alert_off): still store the event so the monitor can
// auto-act on it, but do not pop up a message.
if (settings.alerts_enabled!== false) {
ctx.waitUntil(sendMessage(env, env.OWNER_ID, alertText, false, kb));
}
return Response.json({ ok: true, alert_sent: settings.alerts_enabled!== false});
}

if (request.method === "POST" && url.pathname === "/webhook") {
const secret = request.headers.get("X-Telegram-Bot-Api-Secret-Token");
if (secret && env.WEBHOOK_SECRET && secret!== env.WEBHOOK_SECRET) {
console.log("webhook secret mismatch");
return new Response("Forbidden", { status: 403});
}
let update;
try {
update = await request.json();
} catch {
return new Response("Bad Request", { status: 400});
}
console.log("webhook update:", JSON.stringify(update).slice(0, 2000));
if (update.callback_query) {
const cb = update.callback_query;
const data = cb.data || "";
ctx.waitUntil((async () => {
if (!isOwner(env, cb.from.id)) {
await answerCallback(env, cb.id, "只有管理员才可以操作");
return;
}
// Callback data carries the account: kind:<phone>:<id|hash>.
// Old messages without a phone fall back to the first account.
const accounts = await getAccounts(env);
const firstPhone = accounts[0]? accounts[0].phone: null;
const parseCb = (prefix) => {
const rest = data.slice(prefix.length);
const parts = rest.split(":");
if (parts.length >= 2) return { phone: parts[0], id: parts.slice(1).join(":")};
return { phone: firstPhone, id: parts[0]};
};
if (data.startsWith("code_allow:")) { const p = parseCb("code_allow:"); await handleCodeDecision(env, cb, "allow", p.phone, p.id); ctx.waitUntil(sendWakeup(env, `code_allow:${p.phone}:${p.id}:${Math.floor(Date.now()/1000)}`)); return;}
if (data.startsWith("code_deny_code:")) { const p = parseCb("code_deny_code:"); await handleCodeDecision(env, cb, "deny_code", p.phone, p.id); ctx.waitUntil(sendWakeup(env, `code_deny_code:${p.phone}:${p.id}:${Math.floor(Date.now()/1000)}`)); return;}
if (data.startsWith("code_deny_2fa:")) { const p = parseCb("code_deny_2fa:"); await handleCodeDecision(env, cb, "deny_2fa", p.phone, p.id); ctx.waitUntil(sendWakeup(env, `code_deny_2fa:${p.phone}:${p.id}:${Math.floor(Date.now()/1000)}`)); return;}
if (data.startsWith("code_deny:")) { const p = parseCb("code_deny:"); await handleCodeDecision(env, cb, "deny", p.phone, p.id); ctx.waitUntil(sendWakeup(env, `code_deny:${p.phone}:${p.id}:${Math.floor(Date.now()/1000)}`)); return;}
if (data.startsWith("allow:")) { const p = parseCb("allow:"); await handleDecision(env, cb, "allow", p.phone, p.id); ctx.waitUntil(sendWakeup(env, `allow:${p.phone}:${p.id}:${Math.floor(Date.now()/1000)}`)); return;}
if (data.startsWith("revoke:")) { const p = parseCb("revoke:"); await handleDecision(env, cb, "revoke", p.phone, p.id); ctx.waitUntil(sendWakeup(env, `revoke:${p.phone}:${p.id}:${Math.floor(Date.now()/1000)}`)); return;}
if (data.startsWith("sustain_flood_on:")) { const parts = data.split(":"); const minutes = parseInt(parts[1] || '', 10); const phone = normalizePhone(parts[2] || ''); if (phone && minutes >= 1 && minutes <= SUSTAIN_MAX_MIN) { const s = await setSustain(env, phone, minutes); await answerCallback(env, cb.id, `已开启，${minutes} 分钟后触发`); await sendMessage(env, cb.message.chat.id, `✅ 持续Flood保护已开启【${displayPhone(phone)}】\n${minutes} 分钟后（${fmtTime(s.trigger_at)}）自动触发一次 Flood 保护。\n\n下面可以改成循环或指定次数；不选就是只触发一次，到时间自动关闭；随时用 /sustain_flood_off 取消。`, true, sustainPickerKeyboard(phone, s)); } else { await answerCallback(env, cb.id, "时间无效"); } return; }
if (data.startsWith("sustain_flood_off:")) { const phone = normalizePhone((data.split(":")[1] || '')); if (phone) { await clearSustain(env, phone); await answerCallback(env, cb.id, "已关闭"); await sendMessage(env, cb.message.chat.id, `✅ 持续Flood保护已关闭【${displayPhone(phone)}】`, true); } else { await answerCallback(env, cb.id, "账号无效"); } return; }
if (data.startsWith("sustain_mode:loop:")) { const phone = normalizePhone((data.split(":")[2] || '')); const s = phone ? await setSustainMode(env, phone, "loop") : null; if (s) { await answerCallback(env, cb.id, "已改成循环"); await sendMessage(env, cb.message.chat.id, `🔁 持续Flood保护已改成循环【${displayPhone(phone)}】\n每 ${s.minutes} 分钟触发一次 Flood 保护，一直循环，直到用 /sustain_flood_off 取消。\n下次触发：${fmtTime(s.trigger_at)}。`, true); } else { await answerCallback(env, cb.id, "先设置一个时间"); } return; }
if (data.startsWith("sustain_mode:count:")) { const phone = normalizePhone((data.split(":")[2] || '')); const s = phone ? await getSustain(env, phone) : null; if (s) { await answerCallback(env, cb.id, "选次数"); await sendMessage(env, cb.message.chat.id, `🔢 持续Flood保护【${displayPhone(phone)}】\n每 ${s.minutes} 分钟触发一次，选一共触发几次，到次数就自动停止。`, true, sustainCountKeyboard(phone)); } else { await answerCallback(env, cb.id, "先设置一个时间"); } return; }
if (data.startsWith("sustain_count:")) { const parts = data.split(":"); const n = parseInt(parts[1] || '', 10); const phone = normalizePhone(parts[2] || ''); const s = (phone && n >= 1 && n <= 100) ? await setSustainMode(env, phone, "count", n) : null; if (s) { await answerCallback(env, cb.id, `共 ${n} 次`); await sendMessage(env, cb.message.chat.id, `🔢 持续Flood保护已设置【${displayPhone(phone)}】\n每 ${s.minutes} 分钟触发一次 Flood 保护，共 ${n} 次，到次数自动停止。\n下次触发：${fmtTime(s.trigger_at)}。`, true); } else { await answerCallback(env, cb.id, "次数无效"); } return; }
const cmd = data.startsWith("cmd:")? data.slice(4): data;
await answerCallback(env, cb.id);
await runCommand(env, cb.message.chat.id, cb.from.id, cmd);
})());
return Response.json({ ok: true});
}
const msg = update.message || update.edited_message;
if (msg && msg.chat) {
ctx.waitUntil(runCommand(env, msg.chat.id, msg.from && msg.from.id, msg.text || ""));
}
return Response.json({ ok: true});
}

return new Response("Not Found", { status: 404});
},
};
