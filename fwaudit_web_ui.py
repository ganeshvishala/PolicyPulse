"""Static front-end files for fwaudit_web.py (HTML, CSS, JS as strings).

Kept in one Python module so the tool still ships as plain .py files
with no build step and works fully offline (no CDN, no web fonts).
"""

INDEX_HTML = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>PolicyPulse - Firewall Change Audit</title>
<link rel="stylesheet" href="/app.css">
</head>
<body>
<div id="app"><div class="boot">Loading PolicyPulse...</div></div>
<script src="/app.js"></script>
</body>
</html>
"""

APP_CSS = r"""
:root{
  --bg:#f4f6fa; --panel:#ffffff; --panel2:#f8fafc; --line:#e3e8ef; --line2:#cfd7e3;
  --ink:#0f1b2d; --ink2:#43536b; --ink3:#6b7a90;
  --brand:#1d4ed8; --brand2:#1e40af; --brand-soft:#e8efff;
  --side:#0d1b31; --side2:#13284a; --side-ink:#c8d3e6;
  --yes:#c62828; --yes-bg:#fdecec; --no:#1b7f45; --no-bg:#e6f5ec;
  --rev:#a35b00; --rev-bg:#fff3dc; --na:#5b6577; --na-bg:#eef1f5;
  --hi:#1b7f45; --mid:#a35b00; --lo:#c62828;
  --shadow:0 1px 2px rgba(15,27,45,.06),0 4px 14px rgba(15,27,45,.06);
  --r:10px;
}
:root[data-theme="dark"]{
  --bg:#0b1220; --panel:#111a2b; --panel2:#0e1726; --line:#1f2b40; --line2:#2b3a55;
  --ink:#e6ecf5; --ink2:#a9b6ca; --ink3:#7d8aa0;
  --brand:#5b8cff; --brand2:#7aa2ff; --brand-soft:#16244a;
  --side:#080e1a; --side2:#111d35; --side-ink:#a9b6ca;
  --yes:#ff7a7a; --yes-bg:#3a1618; --no:#5fd08f; --no-bg:#0f2e1e;
  --rev:#ffbf5e; --rev-bg:#3a2a0e; --na:#9aa6b8; --na-bg:#1b2436;
  --hi:#5fd08f; --mid:#ffbf5e; --lo:#ff7a7a;
  --shadow:0 1px 2px rgba(0,0,0,.4);
}
:root[data-theme="dark"] .btn.ok,:root[data-theme="dark"] .btn.bad,:root[data-theme="dark"] .btn.pri{color:#08101e;font-weight:650}
*{box-sizing:border-box}
html,body{margin:0;height:100%}
body{background:var(--bg);color:var(--ink);font:14px/1.45 "Segoe UI",system-ui,-apple-system,Roboto,Helvetica,Arial,sans-serif}
a{color:var(--brand);text-decoration:none}
a:hover{text-decoration:underline}
button,input,select,textarea{font:inherit;color:inherit}
.boot{padding:40px;color:var(--ink3)}
.mono{font-family:Consolas,"SF Mono",Menlo,monospace;font-size:12.5px}
.muted{color:var(--ink3)}
.small{font-size:12px}
.hidden{display:none!important}
.sp{flex:1}

/* shell */
.shell{display:grid;grid-template-columns:232px 1fr;min-height:100vh}
.side{background:var(--side);color:var(--side-ink);display:flex;flex-direction:column;position:sticky;top:0;height:100vh}
.logo{display:flex;align-items:center;gap:10px;padding:18px 18px 14px;color:#fff;font-weight:700;font-size:16px;letter-spacing:.2px}
.logo .mark{width:30px;height:30px;border-radius:8px;background:linear-gradient(135deg,#3b82f6,#22c55e);display:grid;place-items:center;font-size:15px}
.logo small{display:block;font-weight:400;font-size:11px;color:var(--side-ink);opacity:.8}
.nav{padding:6px 10px;flex:1}
.nav a{display:flex;align-items:center;gap:10px;padding:9px 12px;border-radius:8px;color:var(--side-ink);margin:2px 0}
.nav a:hover{background:var(--side2);text-decoration:none;color:#fff}
.nav a.on{background:var(--brand);color:#fff}
.nav .ic{width:18px;text-align:center;opacity:.9}
.nav .badge{margin-left:auto;background:#f59e0b;color:#111;border-radius:10px;font-size:11px;padding:0 7px;font-weight:700}
.side-foot{padding:12px 18px;font-size:11px;opacity:.7}
.main{min-width:0}
.top{display:flex;align-items:center;gap:12px;padding:12px 26px;background:var(--panel);border-bottom:1px solid var(--line);position:sticky;top:0;z-index:5}
.top h1{font-size:18px;margin:0;font-weight:650}
.top .sp{flex:1}
.who{display:flex;align-items:center;gap:8px;color:var(--ink2)}
.role{font-size:11px;text-transform:uppercase;letter-spacing:.5px;padding:2px 8px;border-radius:10px;background:var(--brand-soft);color:var(--brand)}
.page{padding:22px 26px 60px;max-width:1500px}

/* elements */
.btn{display:inline-flex;align-items:center;gap:6px;border:1px solid var(--line2);background:var(--panel);padding:7px 14px;border-radius:8px;cursor:pointer;white-space:nowrap}
.btn:hover{border-color:var(--brand);text-decoration:none}
.btn.pri{background:var(--brand);border-color:var(--brand);color:#fff}
.btn.pri:hover{background:var(--brand2)}
.btn.ok{background:var(--no);border-color:var(--no);color:#fff}
.btn.bad{background:var(--yes);border-color:var(--yes);color:#fff}
.btn.ghost{border-color:transparent;background:transparent}
.btn.sm{padding:4px 10px;font-size:12.5px}
.btn[disabled]{opacity:.5;cursor:not-allowed}
.card{background:var(--panel);border:1px solid var(--line);border-radius:var(--r);box-shadow:var(--shadow);padding:18px 20px;margin-bottom:18px}
.card h2{font-size:15px;margin:0 0 12px;font-weight:650}
.card h3{font-size:13.5px;margin:16px 0 8px;font-weight:650;color:var(--ink2)}
.row{display:flex;gap:12px;align-items:center;flex-wrap:wrap}
.grid{display:grid;gap:18px}
.g2{grid-template-columns:1fr 1fr}
.g3{grid-template-columns:repeat(3,1fr)}
.grid.g3{margin-bottom:16px}
@media (max-width:1100px){.g2,.g3{grid-template-columns:1fr}}
input[type=text],input[type=password],input[type=date],select,textarea{border:1px solid var(--line2);background:var(--panel);border-radius:8px;padding:7px 10px;outline:none}
input:focus,select:focus,textarea:focus{border-color:var(--brand);box-shadow:0 0 0 3px var(--brand-soft)}
textarea{width:100%;min-height:80px;resize:vertical}
label.f{display:block;font-size:12px;color:var(--ink2);margin:10px 0 4px;font-weight:600}
.err{background:var(--yes-bg);color:var(--yes);border-radius:8px;padding:9px 12px;margin:8px 0}
.note{background:var(--brand-soft);color:var(--ink);border-radius:8px;padding:10px 12px;margin:8px 0}
.warnbox{background:var(--rev-bg);color:var(--ink);border-left:4px solid var(--rev);border-radius:8px;padding:10px 12px;margin:8px 0}

/* KPI */
.kpis{display:grid;grid-template-columns:repeat(auto-fill,minmax(140px,1fr));gap:14px;margin-bottom:18px}
.kpi{background:var(--panel);border:1px solid var(--line);border-radius:var(--r);padding:14px 16px;box-shadow:var(--shadow)}
.kpi .l{font-size:12px;color:var(--ink3);font-weight:600;text-transform:uppercase;letter-spacing:.4px}
.kpi .v{font-size:28px;font-weight:700;margin-top:4px}
.kpi .s{font-size:12px;color:var(--ink3)}
.kpi.yes .v{color:var(--yes)} .kpi.rev .v{color:var(--rev)} .kpi.no .v{color:var(--no)}

/* pills */
.pill{display:inline-block;padding:2px 9px;border-radius:12px;font-size:12px;font-weight:700;letter-spacing:.2px;white-space:nowrap}
.p-YES{background:var(--yes-bg);color:var(--yes)}
.p-NO{background:var(--no-bg);color:var(--no)}
.p-REVIEW{background:var(--rev-bg);color:var(--rev)}
.p-NA{background:var(--na-bg);color:var(--na)}
.p-done{background:var(--no-bg);color:var(--no)} .p-running{background:var(--brand-soft);color:var(--brand)}
.p-failed{background:var(--yes-bg);color:var(--yes)} .p-draft{background:var(--na-bg);color:var(--na)}
.p-proposed{background:var(--rev-bg);color:var(--rev)} .p-approved{background:var(--no-bg);color:var(--no)}
.p-rejected,.p-revoked{background:var(--na-bg);color:var(--na)}
.conf{font-size:12px;font-weight:700}
.c-High{color:var(--hi)} .c-Medium{color:var(--mid)} .c-Low{color:var(--lo)} .c-NA{color:var(--na)}
.arrow{color:var(--ink3);margin:0 4px}

/* tables */
.tw{overflow:auto;border:1px solid var(--line);border-radius:var(--r);background:var(--panel)}
table{border-collapse:collapse;width:100%}
th,td{padding:8px 10px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top}
th{position:sticky;top:0;background:var(--panel2);font-size:12px;color:var(--ink2);font-weight:650;white-space:nowrap;z-index:1}
tr.click{cursor:pointer}
tr.click:hover td{background:var(--brand-soft)}
tr.sel td{background:var(--brand-soft)}
td.trunc{max-width:340px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
td.wrap{max-width:360px;white-space:normal;word-break:break-word}
.filters{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin-bottom:12px}
.filters input[type=text]{min-width:240px}
.tabs{display:flex;gap:4px;border-bottom:1px solid var(--line);margin-bottom:14px}
.tabs a{padding:9px 14px;color:var(--ink2);border-bottom:2px solid transparent;margin-bottom:-1px;font-weight:600}
.tabs a.on{color:var(--brand);border-color:var(--brand);text-decoration:none}
.tabs a .cnt{font-size:11px;background:var(--na-bg);color:var(--ink2);padding:0 6px;border-radius:8px;margin-left:4px}

/* drawer */
.drawer-bg{position:fixed;inset:0;background:rgba(10,18,32,.35);z-index:20}
.drawer{position:fixed;top:0;right:0;bottom:0;width:min(820px,96vw);background:var(--bg);z-index:21;overflow:auto;box-shadow:-8px 0 30px rgba(0,0,0,.18)}
.drawer .dh{position:sticky;top:0;background:var(--panel);border-bottom:1px solid var(--line);padding:14px 20px;display:flex;gap:12px;align-items:flex-start;z-index:2}
.drawer .dh h2{margin:0;font-size:16px;word-break:break-all}
.drawer .db{padding:16px 20px}
.verdict{display:flex;gap:14px;align-items:center;flex-wrap:wrap}
.verdict .box{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:8px 12px}
.verdict .box .l{font-size:11px;color:var(--ink3);text-transform:uppercase;font-weight:650}
.steps{list-style:none;margin:0;padding:0}
.steps li{display:grid;grid-template-columns:22px 250px 1fr;gap:8px;padding:6px 0;border-bottom:1px dashed var(--line)}
.steps .i{font-weight:800;text-align:center}
.steps .PASS .i{color:var(--no)} .steps .FAIL .i{color:var(--yes)} .steps .INFO .i{color:var(--brand)}
.kv{display:grid;grid-template-columns:130px 1fr;gap:6px 12px}
.kv .k{color:var(--ink3);font-size:12.5px}
.kv .v{word-break:break-word}
.bad-txt{color:var(--yes);font-weight:650}
td.hit{background:var(--no-bg)}
td.miss{background:var(--yes-bg)}
tr.used td:first-child{box-shadow:inset 3px 0 0 var(--brand)}

/* upload */
.drop{border:2px dashed var(--line2);border-radius:var(--r);padding:18px;text-align:center;background:var(--panel2);transition:.15s}
.drop.over{border-color:var(--brand);background:var(--brand-soft)}
.drop h3{margin:0 0 4px;font-size:14px}
.drop .req{color:var(--yes);font-size:11px;font-weight:700}
.flist{list-style:none;padding:0;margin:10px 0 0;text-align:left;max-height:220px;overflow:auto}
.flist li{display:flex;gap:8px;align-items:center;padding:4px 6px;border-bottom:1px solid var(--line);font-size:12.5px}
.flist li .nm{flex:1;word-break:break-all}
.flist li .st-ok{color:var(--no)} .flist li .st-err{color:var(--yes)} .flist li .st-up{color:var(--brand)}
.log{background:#0b1220;color:#cfe3ff;border-radius:8px;padding:12px;max-height:340px;overflow:auto;font:12px/1.5 Consolas,Menlo,monospace;white-space:pre-wrap}

/* charts */
.bars{display:flex;align-items:flex-end;gap:6px;height:170px;padding:6px 4px 0;border-bottom:1px solid var(--line)}
.bar{flex:1;display:flex;flex-direction:column-reverse;min-width:10px;max-width:46px;cursor:pointer}
.bar span{display:block}
.bar .y{background:var(--yes)} .bar .r{background:var(--rev)} .bar .n{background:var(--no)}
.legend{display:flex;gap:14px;font-size:12px;color:var(--ink2);margin-top:8px}
.legend i{display:inline-block;width:10px;height:10px;border-radius:2px;margin-right:5px;vertical-align:-1px}
.legend i.y{background:var(--yes)} .legend i.r{background:var(--rev)} .legend i.n{background:var(--no)}
.hbar{display:grid;grid-template-columns:230px 1fr 40px;gap:10px;align-items:center;margin:6px 0;font-size:12.5px}
.hbar .t{height:10px;background:var(--na-bg);border-radius:6px;overflow:hidden}
.hbar .t span{display:block;height:100%;background:var(--brand)}

/* login */
.login{min-height:100vh;display:grid;place-items:center;background:radial-gradient(circle at 30% 20%,#1e3a8a 0,#0b1220 55%)}
.login .card{width:min(380px,92vw);padding:26px 28px}
.login h1{margin:0 0 2px;font-size:20px}
.login .btn{width:100%;justify-content:center;margin-top:16px}
.toast{position:fixed;bottom:20px;right:20px;background:var(--ink);color:var(--bg);padding:10px 16px;border-radius:8px;z-index:50;box-shadow:var(--shadow);max-width:420px}
.toast.bad{background:var(--yes);color:#fff}
@media (max-width:820px){.shell{grid-template-columns:1fr}.side{position:static;height:auto}.nav{display:flex;flex-wrap:wrap}.side-foot{display:none}.steps li{grid-template-columns:22px 1fr}.steps li .d{grid-column:2}}
"""

APP_JS = r"""
'use strict';
(function () {
const S = { me: null, runs: [], cache: {}, poll: null, theme: null };
const $app = document.getElementById('app');

/* ---------- helpers ---------- */
function el(tag, attrs, ...kids) {
  const e = document.createElement(tag);
  if (attrs) for (const k in attrs) {
    const v = attrs[k];
    if (v === null || v === undefined || v === false) continue;
    if (k === 'class') e.className = v;
    else if (k === 'text') e.textContent = v;
    else if (k.startsWith('on')) e.addEventListener(k.slice(2), v);
    else if (k === 'value') e.value = v;
    else e.setAttribute(k, v === true ? '' : v);
  }
  for (const c of kids.flat(9)) {
    if (c === null || c === undefined || c === false) continue;
    e.appendChild(typeof c === 'string' || typeof c === 'number' ? document.createTextNode(String(c)) : c);
  }
  return e;
}
function svg(tag, attrs, ...kids) {
  const e = document.createElementNS('http://www.w3.org/2000/svg', tag);
  for (const k in attrs || {}) e.setAttribute(k, attrs[k]);
  kids.flat().forEach(c => c && e.appendChild(c));
  return e;
}
function clear(n) { while (n.firstChild) n.removeChild(n.firstChild); return n; }
function pill(st) { const c = st === 'N/A' ? 'NA' : st; return el('span', { class: 'pill p-' + c, text: st || '-' }); }
function conf(c) { return el('span', { class: 'conf c-' + (c === 'N/A' ? 'NA' : (c || 'NA')), text: c || '-' }); }
function fmtSize(n) { return n > 1048576 ? (n / 1048576).toFixed(1) + ' MB' : Math.max(1, Math.round(n / 1024)) + ' KB'; }
function can(role) { const R = ['viewer', 'analyst', 'reviewer', 'admin']; return S.me && R.indexOf(S.me.role) >= R.indexOf(role); }
function toast(msg, bad) {
  const t = el('div', { class: 'toast' + (bad ? ' bad' : ''), text: msg });
  document.body.appendChild(t); setTimeout(() => t.remove(), bad ? 6000 : 3000);
}
async function api(method, url, body, raw) {
  const opt = { method, headers: { 'X-PP': '1' }, credentials: 'same-origin' };
  if (raw) { opt.body = raw; opt.headers['Content-Type'] = 'application/octet-stream'; }
  else if (body !== undefined) { opt.body = JSON.stringify(body); opt.headers['Content-Type'] = 'application/json'; }
  const r = await fetch('/api/' + url, opt);
  let d = null;
  try { d = await r.json(); } catch (e) { d = {}; }
  if (r.status === 401 && url !== 'login') { S.me = null; renderLogin(); throw new Error(d.error || 'Please sign in'); }
  if (!r.ok) throw new Error(d.error || ('HTTP ' + r.status));
  return d;
}
function setTheme(t) {
  S.theme = t; document.documentElement.setAttribute('data-theme', t);
  try { localStorage.setItem('pp_theme', t); } catch (e) {}
}
try { setTheme(localStorage.getItem('pp_theme') || (matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light')); } catch (e) { setTheme('light'); }

/* ---------- login ---------- */
function renderLogin(msg) {
  stopPoll();
  const u = el('input', { type: 'text', autocomplete: 'username', placeholder: 'User name' });
  const p = el('input', { type: 'password', autocomplete: 'current-password', placeholder: 'Password' });
  const err = el('div', { class: msg ? 'err' : 'hidden', text: msg || '' });
  const go = async (ev) => {
    ev.preventDefault();
    try {
      await api('POST', 'login', { user: u.value, password: p.value });
      await boot();
    } catch (e) { err.className = 'err'; err.textContent = e.message; }
  };
  clear($app).appendChild(el('div', { class: 'login' },
    el('form', { class: 'card', onsubmit: go },
      el('div', { class: 'logo' }, el('div', { class: 'mark', text: '◆' })),
      el('h1', { text: 'PolicyPulse' }),
      el('div', { class: 'muted small', text: 'Firewall change audit - AlgoSec vs RFC' }),
      err,
      el('label', { class: 'f', text: 'User name' }), u,
      el('label', { class: 'f', text: 'Password' }), p,
      el('button', { class: 'btn pri', type: 'submit', text: 'Sign in' }))));
  u.style.width = '100%'; p.style.width = '100%';
  u.focus();
}

/* ---------- shell ---------- */
const NAV = [
  ['dashboard', 'Dashboard', '▣', 'viewer'],
  ['new', 'New audit', '＋', 'analyst'],
  ['runs', 'Audit runs', '☰', 'viewer'],
  ['overrides', 'Overrides', '✔', 'viewer'],
  ['trail', 'Audit trail', '⧗', 'reviewer'],
  ['users', 'Users', '☺', 'admin'],
  ['help', 'How it works', '?', 'viewer'],
];
let pendingCount = 0;
function shell(title, active, content, actions) {
  const nav = el('nav', { class: 'nav' }, NAV.filter(n => can(n[3])).map(n =>
    el('a', { href: '#/' + n[0], class: active === n[0] ? 'on' : '' },
      el('span', { class: 'ic', text: n[2] }), n[1],
      n[0] === 'overrides' && pendingCount ? el('span', { class: 'badge', text: pendingCount }) : null)));
  const themeBtn = el('button', { class: 'btn ghost sm', title: 'Light / dark', text: S.theme === 'dark' ? '☀' : '☾',
    onclick: () => { setTheme(S.theme === 'dark' ? 'light' : 'dark'); route(); } });
  clear($app).appendChild(el('div', { class: 'shell' },
    el('aside', { class: 'side' },
      el('div', { class: 'logo' }, el('div', { class: 'mark', text: '◆' }),
        el('div', {}, 'PolicyPulse', el('small', { text: 'Firewall change audit' }))),
      nav,
      el('div', { class: 'side-foot', text: 'Engine ' + S.me.version + ' · Web ' + S.me.web_version })),
    el('main', { class: 'main' },
      el('div', { class: 'top' }, el('h1', { text: title }), el('div', { class: 'sp' }), actions || null, themeBtn,
        el('div', { class: 'who' }, el('span', { text: S.me.user }), el('span', { class: 'role', text: S.me.role }),
          el('button', { class: 'btn ghost sm', text: 'Password', onclick: pwDialog }),
          el('button', { class: 'btn sm', text: 'Sign out', onclick: async () => { await api('POST', 'logout', {}); S.me = null; renderLogin(); } }))),
      el('div', { class: 'page' }, content))));
}
function pwDialog() {
  const o = el('input', { type: 'password', placeholder: 'Current password' });
  const n = el('input', { type: 'password', placeholder: 'New password (min 10)' });
  const close = () => { bg.remove(); box.remove(); };
  const bg = el('div', { class: 'drawer-bg', onclick: close });
  const box = el('div', { class: 'drawer' }, el('div', { class: 'dh' }, el('h2', { text: 'Change password' }), el('div', { class: 'sp' }),
    el('button', { class: 'btn sm', text: 'Close', onclick: close })),
    el('div', { class: 'db' }, el('label', { class: 'f', text: 'Current' }), o, el('label', { class: 'f', text: 'New' }), n,
      el('div', { class: 'row' }, el('button', { class: 'btn pri', text: 'Save', onclick: async () => {
        try { await api('POST', 'me/password', { old: o.value, new: n.value }); toast('Password changed'); close(); } catch (e) { toast(e.message, true); }
      } }))));
  document.body.append(bg, box);
}

/* ---------- router ---------- */
function stopPoll() { if (S.poll) { clearTimeout(S.poll); S.poll = null; } }
async function route() {
  stopPoll();
  closeDrawer();
  const h = (location.hash || '#/dashboard').slice(2).split('/');
  try {
    if (h[0] === 'new') return await viewNew(h[1]);
    if (h[0] === 'runs') return await viewRuns();
    if (h[0] === 'run') return await viewRun(h[1], h[2] || 'queue');
    if (h[0] === 'overrides') return await viewOverrides(h[1] || 'proposed');
    if (h[0] === 'trail') return await viewTrail();
    if (h[0] === 'users') return await viewUsers();
    if (h[0] === 'help') return viewHelp();
    return await viewDashboard();
  } catch (e) {
    if (S.me) shell('Error', '', el('div', { class: 'err', text: e.message }));
  }
}
window.addEventListener('hashchange', route);
document.addEventListener('keydown', e => { if (e.key === 'Escape') closeDrawer(); });
async function refreshPending() {
  try { const d = await api('GET', 'overrides'); pendingCount = d.overrides.filter(o => o.state === 'proposed').length; } catch (e) { }
}

/* ---------- dashboard ---------- */
async function viewDashboard() {
  await refreshPending();
  const d = await api('GET', 'dashboard');
  const L = d.latest, s = (L && L.summary) || { counts: {}, tool_counts: {}, overrides: {} };
  const c = s.counts || {}, tc = s.tool_counts || {};
  if (!L) {
    return shell('Dashboard', 'dashboard', el('div', { class: 'card' },
      el('h2', { text: 'Welcome to PolicyPulse' }),
      el('p', { text: 'No audit has been run yet. Upload the AlgoSec change reports and the RFC port sheets to start.' }),
      can('analyst') ? el('a', { class: 'btn pri', href: '#/new', text: 'Start a new audit' }) : null));
  }
  const kp = (cls, l, v, sub) => el('div', { class: 'kpi ' + (cls || '') }, el('div', { class: 'l', text: l }), el('div', { class: 'v', text: v }), el('div', { class: 's', text: sub || '' }));
  const kpis = el('div', { class: 'kpis' },
    kp('', 'Rules audited', s.rules || 0, 'Report ' + (L.report_date || '')),
    kp('yes', 'PIR issue (final)', c.YES || 0, 'Tool said ' + (tc.YES || 0)),
    kp('rev', 'Needs review', c.REVIEW || 0, 'Tool said ' + (tc.REVIEW || 0)),
    kp('no', 'Implemented as RFC', c.NO || 0, ''),
    kp('', 'Overrides applied', (s.overrides || {}).applied || 0, d.fp_rate === null ? '' : d.fp_rate + '% of flagged rules'),
    kp('rev', 'Pending approval', d.pending, 'maker-checker'),
    kp('', 'QA accuracy', d.qa.accuracy === null ? '-' : d.qa.accuracy + '%', d.qa.correct + ' correct / ' + d.qa.wrong + ' wrong'));
  const max = Math.max(1, ...d.trend.map(t => t.rules || 0));
  const bars = el('div', { class: 'bars' }, d.trend.map(t => {
    const b = el('div', { class: 'bar', title: (t.date || t.id) + ' - YES ' + (t.counts.YES || 0) + ', REVIEW ' + (t.counts.REVIEW || 0) + ', NO ' + (t.counts.NO || 0), onclick: () => location.hash = '#/run/' + t.id });
    [['n', 'NO'], ['r', 'REVIEW'], ['y', 'YES']].forEach(([k, st]) => { const sp = el('span', { class: k }); sp.style.height = (150 * (t.counts[st] || 0) / max) + 'px'; b.appendChild(sp); });
    return b;
  }));
  const rs = d.reasons, rmax = Math.max(1, ...rs.map(r => r[1]));
  const reasons = rs.length ? rs.map(([n, v]) => { const sp = el('span'); sp.style.width = (100 * v / rmax) + '%'; return el('div', { class: 'hbar' }, el('div', { text: n }), el('div', { class: 't' }, sp), el('div', { text: v })); })
    : el('div', { class: 'muted', text: 'No approved overrides yet.' });
  shell('Dashboard', 'dashboard', [kpis,
    el('div', { class: 'grid g2' },
      el('div', { class: 'card' }, el('h2', { text: 'Final verdicts per audit run' }), bars,
        el('div', { class: 'legend' }, el('span', {}, el('i', { class: 'y' }), 'PIR issue'), el('span', {}, el('i', { class: 'r' }), 'Review'), el('span', {}, el('i', { class: 'n' }), 'Implemented'))),
      el('div', { class: 'card' }, el('h2', { text: 'Why verdicts were overridden (false-positive causes)' }), reasons,
        el('p', { class: 'muted small', text: 'Frequent causes show where the RFC reader or object resolution should be improved next.' }))),
    el('div', { class: 'card' }, el('h2', { text: 'Latest run' }),
      el('div', { class: 'row' }, pill(s.status === 'PASS' ? 'NO' : (s.status === 'ATTENTION REQUIRED' ? 'YES' : 'REVIEW')),
        el('b', { text: s.status }), el('span', { class: 'muted', text: (L.label || L.id) + ' · by ' + L.created_by }),
        el('a', { class: 'btn pri sm', href: '#/run/' + L.id, text: 'Open review queue' })))]);
}

/* ---------- new audit / upload ---------- */
async function viewNew(rid) {
  let meta = rid ? await api('GET', 'runs/' + rid) : null;
  const label = el('input', { type: 'text', placeholder: 'e.g. Daily audit 08-Nov', value: meta ? meta.label : '' });
  const rdate = el('input', { type: 'date', value: meta && meta.report_date ? meta.report_date : '' });
  const err = el('div', { class: 'hidden' });
  async function ensureRun() {
    if (meta) return meta;
    meta = await api('POST', 'runs', { label: label.value });
    history.replaceState(null, '', '#/new/' + meta.id);
    return meta;
  }
  function zone(kind, title, hint, required, folder) {
    const list = el('ul', { class: 'flist' });
    const inp = el('input', { type: 'file', multiple: true, class: 'hidden', accept: '.xlsx,.xlsm,.csv' });
    const dinp = folder ? el('input', { type: 'file', class: 'hidden', webkitdirectory: true, multiple: true }) : null;
    const existing = (meta && meta.files && meta.files[kind]) || [];
    existing.forEach(f => list.appendChild(fileRow(kind, f.name, f.size, 'ok')));
    function fileRow(k, name, size, st) {
      const s = el('span', { class: 'st-' + st, text: st === 'ok' ? '✔' : (st === 'up' ? '…' : '✖') });
      const li = el('li', {}, s, el('span', { class: 'nm', text: name }), el('span', { class: 'muted', text: size ? fmtSize(size) : '' }),
        el('button', { class: 'btn ghost sm', text: '✕', title: 'Remove', onclick: async () => {
          try { await api('DELETE', 'runs/' + meta.id + '/file?kind=' + k + '&name=' + encodeURIComponent(name)); li.remove(); } catch (e) { toast(e.message, true); }
        } }));
      li._st = s; return li;
    }
    async function send(files) {
      const m = await ensureRun();
      for (const f of files) {
        const rel = f.webkitRelativePath || '';
        const parts = rel.split('/');
        const sub = parts.length > 2 ? parts[parts.length - 2] : '';
        const li = fileRow(kind, (sub ? sub + '/' : '') + f.name, f.size, 'up');
        list.appendChild(li);
        try {
          await api('POST', 'runs/' + m.id + '/upload?kind=' + kind + '&name=' + encodeURIComponent(f.name) + (sub ? '&folder=' + encodeURIComponent(sub) : ''), undefined, f);
          li._st.className = 'st-ok'; li._st.textContent = '✔';
        } catch (e) { li._st.className = 'st-err'; li._st.textContent = '✖'; li.title = e.message; li.appendChild(el('span', { class: 'st-err small', text: e.message })); }
      }
    }
    const filter = fs => Array.from(fs).filter(f => !f.name.startsWith('~$') && !f.name.startsWith('.'));
    inp.addEventListener('change', () => send(filter(inp.files)));
    if (dinp) dinp.addEventListener('change', () => send(filter(dinp.files)));
    const z = el('div', { class: 'drop' },
      el('h3', {}, title, required ? el('span', { class: 'req', text: '  REQUIRED' }) : null),
      el('div', { class: 'muted small', text: hint }),
      el('div', { class: 'row' }, el('button', { class: 'btn sm', text: 'Choose files', onclick: () => inp.click() }),
        dinp ? el('button', { class: 'btn sm', text: 'Choose folder', onclick: () => dinp.click() }) : null),
      inp, dinp, list);
    z.querySelector('.row').style.justifyContent = 'center'; z.querySelector('.row').style.marginTop = '10px';
    z.addEventListener('dragover', e => { e.preventDefault(); z.classList.add('over'); });
    z.addEventListener('dragleave', () => z.classList.remove('over'));
    z.addEventListener('drop', e => { e.preventDefault(); z.classList.remove('over'); send(filter(e.dataTransfer.files)); });
    return z;
  }
  const startBtn = el('button', { class: 'btn pri', text: '▶  Run audit', onclick: async () => {
    try {
      const m = await ensureRun();
      await api('POST', 'runs/' + m.id + '/start', { report_date: rdate.value });
      location.hash = '#/run/' + m.id;
    } catch (e) { err.className = 'err'; err.textContent = e.message; }
  } });
  shell(meta ? 'Audit inputs' : 'New audit', 'new', [
    el('div', { class: 'card' },
      el('div', { class: 'row' },
        el('div', {}, el('label', { class: 'f', text: 'Label (optional)' }), label),
        el('div', {}, el('label', { class: 'f', text: 'Report date (blank = from AlgoSec file names)' }), rdate))),
    el('div', { class: 'grid g3' },
      zone('algosec', 'AlgoSec change reports', 'Changes Summary .xlsx files, one per firewall', true, false),
      zone('rfc', 'RFC port sheets', 'RFC_<number>.xlsx; a folder of sub-folders per RFC also works', false, true),
      zone('smax', 'SMAX export', 'Optional .xlsx/.csv for Title, Owner, Expiry', false, false)),
    err,
    el('div', { class: 'row' }, startBtn, el('span', { class: 'muted small', text: 'Files are stored on this server only. Approved reviewer overrides are applied automatically.' }))]);
}

/* ---------- runs ---------- */
async function viewRuns() {
  const runs = await api('GET', 'runs');
  const rows = runs.map(r => {
    const s = r.summary || { counts: {}, overrides: {} };
    return el('tr', { class: 'click', onclick: () => location.hash = r.status === 'draft' ? '#/new/' + r.id : '#/run/' + r.id },
      el('td', { class: 'mono', text: r.id }), el('td', { text: r.label || '' }), el('td', { text: r.report_date || '' }),
      el('td', { text: r.created_by }), el('td', {}, el('span', { class: 'pill p-' + r.status, text: r.status })),
      el('td', { text: s.rules === undefined ? '' : s.rules }),
      el('td', {}, s.counts ? el('span', { class: 'pill p-YES', text: String(s.counts.YES || 0) }) : ''),
      el('td', { text: s.counts ? (s.counts.REVIEW || 0) : '' }), el('td', { text: s.counts ? (s.counts.NO || 0) : '' }),
      el('td', { text: (s.overrides && s.overrides.applied) || '' }), el('td', { text: 'v' + (r.versions || 0) }));
  });
  shell('Audit runs', 'runs', el('div', { class: 'tw' }, el('table', {},
    el('thead', {}, el('tr', {}, ['Run', 'Label', 'Report date', 'By', 'Status', 'Rules', 'PIR YES', 'Review', 'NO', 'Overrides', 'Version'].map(h => el('th', { text: h })))),
    el('tbody', {}, rows.length ? rows : el('tr', {}, el('td', { colspan: 11, class: 'muted', text: 'No runs yet.' }))))),
    can('analyst') ? el('a', { class: 'btn pri', href: '#/new', text: '+ New audit' }) : null);
}

/* ---------- run view ---------- */
async function viewRun(rid, tab) {
  const meta = await api('GET', 'runs/' + rid);
  if (meta.status === 'running' || meta.running) return runProgress(rid, meta);
  if (meta.status === 'draft') { location.hash = '#/new/' + rid; return; }
  if (meta.status === 'failed') {
    return shell('Run failed', 'runs', [el('div', { class: 'err', text: meta.error || 'Failed' }),
      el('div', { class: 'card' }, el('h2', { text: 'Log' }), el('div', { class: 'log', text: (meta.log || []).join('\n') })),
      can('analyst') ? el('a', { class: 'btn', href: '#/new/' + rid, text: 'Fix inputs and run again' }) : null]);
  }
  const res = await api('GET', 'runs/' + rid + '/results');
  S.cache[rid] = res;
  const ovs = (await api('GET', 'overrides')).overrides;
  pendingCount = ovs.filter(o => o.state === 'proposed').length;
  const fps = new Set(res.rules.map(r => r.fingerprint));
  const appliedIds = new Set(res.rules.filter(r => r.override).map(r => r.override.id));
  const newer = ovs.filter(o => o.state === 'approved' && fps.has(o.fingerprint) && !appliedIds.has(o.id));
  const revokedApplied = ovs.filter(o => appliedIds.has(o.id) && o.state !== 'approved');
  const qaSet = new Set(res.qa_sample.map(String));
  const queue = res.rules.filter(r => r.status === 'YES' || r.status === 'REVIEW' || r.tool_status !== r.status || r.confidence === 'Low' || r.override_history.some(o => o.state === 'proposed'));
  const tabs = [['queue', 'Review queue', queue.length], ['all', 'All rules', res.rules.length], ['qa', 'QA sample', res.qa_sample.length],
    ['rfc', 'RFC read check', res.rfc_sheets.length + res.sheet_problems.length], ['warn', 'Warnings', res.warnings.length], ['files', 'Reports & evidence', (res.outputs || []).length]];
  const actions = el('div', { class: 'row' },
    can('analyst') ? el('button', { class: 'btn', text: '↻ Re-run final report', title: 'Run again with the same inputs and the current approved overrides', onclick: async () => {
      try { await api('POST', 'runs/' + rid + '/start', {}); location.hash = '#/run/' + rid; route(); } catch (e) { toast(e.message, true); }
    } }) : null,
    el('a', { class: 'btn', href: '/api/runs/' + rid + '/evidence', text: '⬇ Evidence pack' }));
  const c = res.counts, tc = res.tool_counts;
  const head = el('div', { class: 'card' },
    el('div', { class: 'row' },
      el('b', { text: meta.label || rid }), el('span', { class: 'muted', text: 'Report ' + res.report_date + ' · v' + res.version + ' · ' + res.run_time + ' · by ' + res.operator }),
      el('span', { class: 'sp' })),
    el('div', { class: 'row' }, el('span', { class: 'muted', text: 'Final:' }), pill('YES'), el('b', { text: c.YES || 0 }), pill('REVIEW'), el('b', { text: c.REVIEW || 0 }), pill('NO'), el('b', { text: c.NO || 0 }),
      el('span', { class: 'muted', text: '  ·  Tool: YES ' + (tc.YES || 0) + ', REVIEW ' + (tc.REVIEW || 0) + ', NO ' + (tc.NO || 0) }),
      el('span', { class: 'muted', text: '  ·  Overrides applied ' + res.overrides.applied + ', pending ' + res.overrides.pending })),
    (newer.length || revokedApplied.length) ? el('div', { class: 'warnbox' }, (newer.length ? newer.length + ' override(s) were approved after this version. ' : '') +
      (revokedApplied.length ? revokedApplied.length + ' applied override(s) were revoked. ' : '') + 'Click "Re-run final report" to produce an up-to-date final report.') : null);
  const body = el('div');
  shell('Audit results', 'runs', [head,
    el('div', { class: 'tabs' }, tabs.map(t => el('a', { href: '#/run/' + rid + '/' + t[0], class: tab === t[0] ? 'on' : '' }, t[1], el('span', { class: 'cnt', text: t[2] })))),
    body], actions);
  if (tab === 'queue' || tab === 'all' || tab === 'qa') {
    const src = tab === 'queue' ? queue : (tab === 'qa' ? res.rules.filter(r => qaSet.has(String(r.uid))) : res.rules);
    if (tab === 'qa') body.appendChild(el('div', { class: 'note', text: 'Random ' + res.qa_sample.length + ' rule(s) the tool marked as implemented (NO). Open each one, check it against the RFC and mark it correct or wrong. This measures the tool\'s real accuracy, including missed issues.' }));
    ruleTable(body, rid, res, src, qaSet);
  } else if (tab === 'rfc') {
    body.appendChild(rfcCheck(res));
  } else if (tab === 'warn') {
    body.appendChild(el('div', { class: 'tw' }, el('table', {}, el('thead', {}, el('tr', {}, el('th', { text: 'Severity' }), el('th', { text: 'Message' }))),
      el('tbody', {}, res.warnings.map(w => el('tr', {}, el('td', {}, el('span', { class: 'pill ' + (w[0] === 'ERROR' ? 'p-YES' : (w[0] === 'WARN' ? 'p-REVIEW' : 'p-NA')), text: w[0] })), el('td', { class: 'wrap', text: w[1] })))))));
  } else if (tab === 'files') {
    body.appendChild(el('div', { class: 'card' }, el('h2', { text: 'Reports' }),
      el('ul', {}, (res.outputs || []).map(o => el('li', {}, el('a', { href: '/api/runs/' + rid + '/download?path=' + encodeURIComponent(o), text: o.split('/').pop() })))),
      el('h3', { text: 'Evidence pack' }),
      el('p', { class: 'muted', text: 'ZIP with the reports, every verdict with its explanation, run log, QA checks, overrides snapshot, this run\'s audit trail and SHA-256 checksums of every file.' }),
      el('a', { class: 'btn pri', href: '/api/runs/' + rid + '/evidence', text: 'Download evidence pack' }),
      el('h3', { text: 'Input chain of custody' }),
      el('div', { class: 'tw' }, el('table', {}, el('thead', {}, el('tr', {}, ['Role', 'File', 'SHA-256', 'Size'].map(h => el('th', { text: h })))),
        el('tbody', {}, (res.input_custody || []).map(cu => el('tr', {}, el('td', { text: cu.role }), el('td', { text: cu.name }), el('td', { class: 'mono', text: (cu.sha256 || '').slice(0, 20) + '…' }), el('td', { text: cu.size_bytes ? fmtSize(cu.size_bytes) : '' }))))))));
  }
}
function runProgress(rid, meta) {
  const log = el('div', { class: 'log', text: (meta.log || []).join('\n') || 'Starting...' });
  shell('Audit running', 'runs', el('div', { class: 'card' }, el('h2', { text: 'Running audit ' + (meta.label || rid) }), log));
  const tick = async () => {
    try {
      const m = await api('GET', 'runs/' + rid);
      log.textContent = (m.log || []).join('\n'); log.scrollTop = log.scrollHeight;
      if (m.status === 'running' || m.running) S.poll = setTimeout(tick, 1200); else route();
    } catch (e) { }
  };
  S.poll = setTimeout(tick, 800);
}
function ruleTable(body, rid, res, rules, qaSet) {
  const tabsSet = Array.from(new Set(res.rules.map(r => r.tab)));
  const q = el('input', { type: 'text', placeholder: 'Search rule, RFC, IP, port, detail...' });
  const fs = el('select', {}, ['', 'YES', 'REVIEW', 'NO', 'N/A'].map(v => el('option', { value: v, text: v ? 'Final: ' + v : 'Final: any' })));
  const ft = el('select', {}, ['', 'YES', 'REVIEW', 'NO', 'N/A'].map(v => el('option', { value: v, text: v ? 'Tool: ' + v : 'Tool: any' })));
  const fc = el('select', {}, ['', 'High', 'Medium', 'Low'].map(v => el('option', { value: v, text: v ? 'Confidence: ' + v : 'Confidence: any' })));
  const ftab = el('select', {}, [''].concat(tabsSet).map(v => el('option', { value: v, text: v || 'All firewalls' })));
  const fx = el('select', {}, [['', 'Any'], ['risky', 'Risky only'], ['ov', 'Overridden'], ['diff', 'Tool ≠ final'], ['pend', 'Pending approval']].map(v => el('option', { value: v[0], text: v[1] })));
  const cnt = el('span', { class: 'muted small' });
  const tbody = el('tbody');
  let limit = 300;
  const more = el('button', { class: 'btn sm hidden', text: 'Show more', onclick: () => { limit += 500; draw(); } });
  function draw() {
    const s = q.value.trim().toLowerCase();
    const rows = rules.filter(r =>
      (!fs.value || r.status === fs.value) && (!ft.value || r.tool_status === ft.value) && (!fc.value || r.confidence === fc.value) &&
      (!ftab.value || r.tab === ftab.value) &&
      (!fx.value || (fx.value === 'risky' && r.risky) || (fx.value === 'ov' && r.override) || (fx.value === 'diff' && r.tool_status !== r.status) ||
        (fx.value === 'pend' && r.override_history.some(o => o.state === 'proposed'))) &&
      (!s || [r.name, r.rfcs.join(' '), r.src, r.dst, r.ports, r.services, r.detail, r.tab, r.asset_owner].join(' ').toLowerCase().indexOf(s) >= 0));
    clear(tbody);
    rows.slice(0, limit).forEach(r => {
      const pend = r.override_history.some(o => o.state === 'proposed');
      const qa = res.qa[String(r.uid)];
      tbody.appendChild(el('tr', { class: 'click', onclick: () => openRule(rid, r.uid) },
        el('td', {}, pill(r.status), pend ? el('span', { class: 'pill p-proposed small', text: 'pending', title: 'Override waiting for approval' }) : null),
        el('td', {}, r.tool_status !== r.status ? pill(r.tool_status) : el('span', { class: 'muted', text: 'same' })),
        el('td', {}, conf(r.confidence)),
        el('td', { text: r.tab }), el('td', { class: 'mono', text: r.tab_row }),
        el('td', { class: 'trunc', text: r.name, title: r.name }),
        el('td', { class: 'mono', text: r.rfcs.join(', ') }),
        el('td', { class: 'trunc mono', text: r.src, title: r.src }), el('td', { class: 'trunc mono', text: r.dst, title: r.dst }),
        el('td', { class: 'trunc mono', text: r.ports || r.services }),
        el('td', {}, r.risky ? el('span', { class: 'pill p-YES', text: r.risky_ports.join(' ') }) : ''),
        el('td', { class: 'trunc', text: r.detail, title: r.detail }),
        qaSet.has(String(r.uid)) ? el('td', {}, qa ? el('span', { class: 'pill ' + (qa.verdict === 'correct' ? 'p-NO' : 'p-YES'), text: 'QA ' + qa.verdict }) : el('span', { class: 'pill p-proposed', text: 'QA' })) : el('td')));
    });
    cnt.textContent = 'Showing ' + Math.min(limit, rows.length) + ' of ' + rows.length + ' rule(s)';
    more.className = rows.length > limit ? 'btn sm' : 'btn sm hidden';
  }
  [q, fs, ft, fc, ftab, fx].forEach(x => x.addEventListener(x === q ? 'input' : 'change', draw));
  const csv = el('button', { class: 'btn sm', text: '⬇ CSV', onclick: () => {
    const head = ['Final', 'Tool', 'Confidence', 'Tab', 'Row', 'Rule', 'RFC', 'Source', 'Destination', 'Ports', 'Risky', 'Detail', 'Override reason'];
    const esc = v => { v = String(v === null || v === undefined ? '' : v); if (/^[=+\-@\t\r]/.test(v)) v = "'" + v; return '"' + v.replace(/"/g, '""') + '"'; };
    const lines = [head.map(esc).join(',')].concat(rules.map(r => [r.status, r.tool_status, r.confidence, r.tab, r.tab_row, r.name, r.rfcs.join(' '), r.src, r.dst, r.ports, r.risky_ports.join(' '), r.detail, r.override ? r.override.reason : ''].map(esc).join(',')));
    const a = el('a', { href: URL.createObjectURL(new Blob([lines.join('\r\n')], { type: 'text/csv' })), download: 'PolicyPulse_' + rid + '.csv' });
    document.body.appendChild(a); a.click(); a.remove();
  } });
  body.append(el('div', { class: 'filters' }, q, fs, ft, fc, ftab, fx, csv, cnt),
    el('div', { class: 'tw' }, el('table', {}, el('thead', {}, el('tr', {}, ['Final', 'Tool', 'Conf.', 'Firewall', 'Row', 'Rule', 'RFC', 'Source', 'Destination', 'Ports', 'Risky', 'Detail', ''].map(h => el('th', { text: h })))), tbody)), more);
  draw();
}
function rfcCheck(res) {
  const wrap = el('div');
  if (res.sheet_problems.length) wrap.appendChild(el('div', { class: 'card' }, el('h2', { text: 'RFC files that could not be read' }),
    el('p', { class: 'muted', text: 'Rules that cite these RFCs are REVIEW. If a layout is new, add an rfc.templates entry in the config or send a sample to the tool owner.' }),
    el('div', { class: 'tw' }, el('table', {}, el('thead', {}, el('tr', {}, el('th', { text: 'File' }), el('th', { text: 'Problem' }))),
      el('tbody', {}, res.sheet_problems.map(p => el('tr', {}, el('td', { text: p[0] }), el('td', { class: 'wrap', text: p[1] }))))))));
  wrap.appendChild(el('div', { class: 'card' }, el('h2', { text: 'What was read from each RFC' }),
    el('div', { class: 'tw' }, el('table', {}, el('thead', {}, el('tr', {}, ['RFC', 'File', 'Sheets read', 'Layout found', 'Lines', 'Warnings'].map(h => el('th', { text: h })))),
      el('tbody', {}, res.rfc_sheets.map(s => el('tr', {}, el('td', { class: 'mono', text: 'RFC' + s.rfc }), el('td', { text: s.file }), el('td', { text: (s.sheets || []).join(', ') }),
        el('td', { class: 'small', text: (s.layouts || []).map(l => l[1]).join(', ') }), el('td', { text: s.lines }),
        el('td', { class: 'wrap small' }, s.warnings.length ? s.warnings.map(w => el('div', { text: '• ' + w })) : el('span', { class: 'muted', text: 'none' })))))))));
  return wrap;
}

/* ---------- rule drawer ---------- */
let drawerEls = null;
function closeDrawer() { if (drawerEls) { drawerEls.forEach(e => e.remove()); drawerEls = null; } }
function openRule(rid, uid) {
  const res = S.cache[rid];
  const r = res.rules.find(x => String(x.uid) === String(uid));
  if (!r) return;
  closeDrawer();
  const bg = el('div', { class: 'drawer-bg', onclick: closeDrawer });
  const kv = (k, v, cls) => [el('div', { class: 'k', text: k }), el('div', { class: 'v ' + (cls || ''), text: v === undefined || v === null || v === '' ? '-' : String(v) })];
  const na = r.not_approved;
  const ev = r.evidence;
  const evTable = ev.length ? el('div', { class: 'tw' }, el('table', {},
    el('thead', {}, el('tr', {}, ['RFC / Sr', 'Sheet / row', 'Source (RFC)', 'Destination (RFC)', 'Port (RFC)', 'Direction / justification'].map(h => el('th', { text: h })))),
    el('tbody', {}, ev.map(l => el('tr', { class: l.used ? 'used' : '' },
      el('td', { class: 'mono', text: 'RFC' + l.rfc + ' Sr ' + l.sr }), el('td', { class: 'small', text: l.sheet + ' r' + l.row }),
      el('td', { class: 'wrap mono ' + (l.src_hit ? 'hit' : 'miss'), text: l.src }), el('td', { class: 'wrap mono ' + (l.dst_hit ? 'hit' : 'miss'), text: l.dst }),
      el('td', { class: 'wrap mono ' + (l.port_hit ? 'hit' : 'miss'), text: l.port + (l.ports && l.ports !== l.port ? ' (' + l.ports + ')' : '') }),
      el('td', { class: 'wrap small', text: [l.direction, l.justification].filter(Boolean).join(' · ') }))))))
    : el('div', { class: 'muted', text: r.rfcs.length ? 'No RFC port sheet lines available for this rule.' : 'No RFC number in the rule.' });
  const hist = r.override_history.length ? el('div', { class: 'tw' }, el('table', {}, el('thead', {}, el('tr', {}, ['State', 'Final', 'Reason / comment', 'By', 'Approved by', ''].map(h => el('th', { text: h })))),
    el('tbody', {}, r.override_history.map(o => el('tr', {},
      el('td', {}, el('span', { class: 'pill p-' + o.state, text: o.state })), el('td', {}, pill(o.final_status)),
      el('td', { class: 'wrap' }, el('b', { text: o.reason }), o.comment ? el('div', { class: 'small', text: o.comment }) : null, o.expires ? el('div', { class: 'small muted', text: 'expires ' + o.expires }) : null),
      el('td', { class: 'small', text: o.by + '\n' + o.at }), el('td', { class: 'small', text: o.approved_by || (o.closed_by ? o.state + ' by ' + o.closed_by : '') }),
      el('td', {}, ovActions(o, () => { route().then(() => openRule(rid, uid)); }))))))) : el('div', { class: 'muted', text: 'No overrides for this rule.' });
  const form = can('analyst') ? overrideForm(rid, r) : null;
  const qa = (res.qa_sample || []).map(String).indexOf(String(r.uid)) >= 0 && can('analyst') ? qaBox(rid, r, res) : null;
  const box = el('div', { class: 'drawer' },
    el('div', { class: 'dh' }, el('div', {}, el('div', { class: 'muted small', text: r.tab + ' · row ' + r.tab_row + ' · ' + r.firewall + ' · ' + r.change_type }), el('h2', { text: r.name })),
      el('div', { class: 'sp' }), el('button', { class: 'btn sm', text: 'Close ✕', onclick: closeDrawer })),
    el('div', { class: 'db' },
      el('div', { class: 'verdict' },
        el('div', { class: 'box' }, el('div', { class: 'l', text: 'Tool verdict' }), pill(r.tool_status)),
        el('span', { class: 'arrow', text: '→' }),
        el('div', { class: 'box' }, el('div', { class: 'l', text: 'Final verdict' }), pill(r.status)),
        el('div', { class: 'box' }, el('div', { class: 'l', text: 'Confidence' }), conf(r.confidence)),
        el('div', { class: 'muted small', text: r.confidence_why })),
      el('div', { class: 'card' }, el('h2', { text: 'Why - step by step' }),
        el('ul', { class: 'steps' }, r.explain.map(s => el('li', { class: s[1] }, el('span', { class: 'i', text: s[1] === 'PASS' ? '✔' : (s[1] === 'FAIL' ? '✖' : 'i') }), el('b', { text: s[0] }), el('span', { class: 'd mono', text: s[2] })))),
        el('h3', { text: 'Tool detail' }), el('div', { text: r.detail }),
        r.notes.length ? el('div', {}, el('h3', { text: 'Notes' }), r.notes.map(n => el('div', { class: 'small', text: '• ' + n }))) : null),
      el('div', { class: 'card' }, el('h2', { text: 'Evidence - firewall rule vs RFC' }),
        el('div', { class: 'kv' }, kv('Source', r.src), kv('Destination', r.dst), kv('Services', r.services), kv('Ports', r.ports), kv('Action', r.action),
          kv('RFC(s) cited', r.rfcs.map(x => 'RFC' + x).join(', ')), kv('RFC sheet used', r.rfc_used.map(x => 'RFC' + x).join(', ')),
          na.src ? kv('Source NOT approved', na.src, 'bad-txt') : null, na.dst ? kv('Dest. NOT approved', na.dst, 'bad-txt') : null,
          na.ports ? kv('Ports NOT approved', na.ports, 'bad-txt') : null, kv('Asset owner', r.asset_owner), kv('AlgoSec file', r.file + ' row ' + r.file_row)),
        el('h3', { text: 'RFC lines (green = overlaps the rule, red = no overlap, blue edge = line used for the verdict)' }), evTable),
      qa,
      el('div', { class: 'card' }, el('h2', { text: 'Reviewer overrides' }), hist, form)));
  document.body.append(bg, box);
  drawerEls = [bg, box];
}
function ovActions(o, after) {
  const out = [];
  const mine = S.me && o.by && o.by.toLowerCase() === S.me.user.toLowerCase();
  const act = async (a) => {
    const note = a === 'approve' ? '' : (prompt('Note (optional):') || '');
    try { await api('POST', 'overrides/' + o.id + '/' + a, { note }); toast('Override ' + a + 'd'); after && after(); } catch (e) { toast(e.message, true); }
  };
  if (o.state === 'proposed' && can('reviewer') && !mine) {
    out.push(el('button', { class: 'btn ok sm', text: 'Approve', onclick: () => act('approve') }));
    out.push(el('button', { class: 'btn bad sm', text: 'Reject', onclick: () => act('reject') }));
  }
  if ((o.state === 'approved' || o.state === 'proposed') && (mine || can('reviewer')))
    out.push(el('button', { class: 'btn sm', text: 'Revoke', onclick: () => act('revoke') }));
  if (o.state === 'proposed' && mine) out.push(el('span', { class: 'muted small', text: 'needs another reviewer' }));
  return el('div', { class: 'row' }, out);
}
function overrideForm(rid, r) {
  const st = el('select', {}, S.me.statuses.map(s => el('option', { value: s, text: s })));
  st.value = r.status === 'NO' ? 'YES' : 'NO';
  const rs = el('select', {}, S.me.reasons.map(s => el('option', { value: s, text: s })));
  const cm = el('textarea', { placeholder: 'Evidence: e.g. "Port 1521 approved in RFC255000111 Sr 4 (attached to change); confirmed with owner on 08-Nov."' });
  const ex = el('input', { type: 'date' });
  const err = el('div', { class: 'hidden' });
  return el('div', {}, el('h3', { text: 'Propose a correction' }),
    el('div', { class: 'row' }, el('div', {}, el('label', { class: 'f', text: 'Final PIR ISSUE' }), st),
      el('div', {}, el('label', { class: 'f', text: 'Reason' }), rs),
      el('div', {}, el('label', { class: 'f', text: 'Expires (optional)' }), ex)),
    el('label', { class: 'f', text: 'Comment / evidence (required)' }), cm, err,
    el('div', { class: 'row' }, el('button', { class: 'btn pri', text: S.me.require_approval ? 'Submit for approval' : 'Save override', onclick: async () => {
      try {
        await api('POST', 'overrides', { run: rid, uid: r.uid, final_status: st.value, reason: rs.value, comment: cm.value, expires: ex.value });
        toast(S.me.require_approval ? 'Submitted. Another reviewer must approve it.' : 'Saved. Re-run the final report to apply it.');
        await route(); openRule(rid, r.uid);
      } catch (e) { err.className = 'err'; err.textContent = e.message; }
    } }), el('span', { class: 'muted small', text: S.me.require_approval ? 'Maker-checker is on: a different reviewer approves it, then "Re-run final report".' : '' })));
}
function qaBox(rid, r, res) {
  const cur = res.qa[String(r.uid)];
  const cm = el('input', { type: 'text', placeholder: 'Comment (optional)', value: cur ? cur.comment : '' });
  cm.style.flex = '1';
  const mark = async (v) => { try { await api('POST', 'runs/' + rid + '/qa', { uid: r.uid, verdict: v, comment: cm.value }); toast('QA saved'); await route(); openRule(rid, r.uid); } catch (e) { toast(e.message, true); } };
  return el('div', { class: 'card' }, el('h2', { text: 'QA check (random sample)' }),
    el('p', { class: 'muted small', text: 'Check this rule against the RFC yourself. Is the tool verdict right?' }),
    cur ? el('div', { class: 'note', text: 'Marked ' + cur.verdict + ' by ' + cur.by + ' at ' + cur.at }) : null,
    el('div', { class: 'row' }, el('button', { class: 'btn ok', text: '✔ Verdict correct', onclick: () => mark('correct') }),
      el('button', { class: 'btn bad', text: '✖ Verdict wrong', onclick: () => mark('wrong') }), cm));
}

/* ---------- overrides page ---------- */
async function viewOverrides(state) {
  const d = await api('GET', 'overrides');
  const all = d.overrides.slice().reverse();
  pendingCount = all.filter(o => o.state === 'proposed').length;
  const list = state === 'all' ? all : all.filter(o => o.state === state);
  const tabs = [['proposed', 'Pending approval'], ['approved', 'Approved'], ['rejected', 'Rejected'], ['revoked', 'Revoked'], ['all', 'All']];
  shell('Reviewer overrides', 'overrides', [
    el('div', { class: 'note', text: 'An override corrects a tool verdict (false positive or missed issue). It is keyed to the exact rule content: if the rule changes later, the override stops applying and the rule is checked again.' }),
    el('div', { class: 'tabs' }, tabs.map(t => el('a', { href: '#/overrides/' + t[0], class: state === t[0] ? 'on' : '' }, t[1], el('span', { class: 'cnt', text: (t[0] === 'all' ? all : all.filter(o => o.state === t[0])).length })))),
    el('div', { class: 'tw' }, el('table', {}, el('thead', {}, el('tr', {}, ['State', 'Firewall', 'Rule', 'Tool → Final', 'Reason / comment', 'Proposed', 'Decision', 'Expires', ''].map(h => el('th', { text: h })))),
      el('tbody', {}, list.length ? list.map(o => el('tr', {},
        el('td', {}, el('span', { class: 'pill p-' + o.state, text: o.state })), el('td', { text: o.tab }),
        el('td', { class: 'wrap' }, o.run ? el('a', { href: '#/run/' + o.run, text: o.rule }) : o.rule),
        el('td', {}, o.tool_status ? pill(o.tool_status) : '', el('span', { class: 'arrow', text: '→' }), pill(o.final_status)),
        el('td', { class: 'wrap' }, el('b', { text: o.reason }), el('div', { class: 'small', text: o.comment || '' })),
        el('td', { class: 'small', text: o.by + ' · ' + o.at }),
        el('td', { class: 'small', text: o.approved_by ? 'approved by ' + o.approved_by + ' · ' + o.approved_at : (o.closed_by ? o.state + ' by ' + o.closed_by + (o.closed_note ? ': ' + o.closed_note : '') : '') }),
        el('td', { class: 'small', text: o.expires || '' }), el('td', {}, ovActions(o, route)))) : el('tr', {}, el('td', { colspan: 9, class: 'muted', text: 'Nothing here.' })))))]);
}

/* ---------- audit trail ---------- */
async function viewTrail() {
  const t = await api('GET', 'trail');
  const q = el('input', { type: 'text', placeholder: 'Filter by user, action, run...' });
  const tb = el('tbody');
  const draw = () => {
    const s = q.value.toLowerCase(); clear(tb);
    t.filter(x => !s || JSON.stringify(x).toLowerCase().indexOf(s) >= 0).slice(0, 1000).forEach(x => tb.appendChild(el('tr', {},
      el('td', { class: 'mono small', text: x.at }), el('td', { text: x.user }), el('td', { text: x.action }), el('td', { class: 'mono small', text: x.ip || '' }),
      el('td', { class: 'wrap mono small', text: JSON.stringify(x.details) }))));
  };
  q.addEventListener('input', draw);
  shell('Audit trail', 'trail', [el('div', { class: 'filters' }, q, el('span', { class: 'muted small', text: 'Every sign-in, upload, run, override and approval is recorded (append-only file).' })),
    el('div', { class: 'tw' }, el('table', {}, el('thead', {}, el('tr', {}, ['When', 'User', 'Action', 'IP', 'Details'].map(h => el('th', { text: h })))), tb))]);
  draw();
}

/* ---------- users ---------- */
async function viewUsers() {
  const us = await api('GET', 'users');
  const u = el('input', { type: 'text', placeholder: 'user name' });
  const p = el('input', { type: 'password', placeholder: 'password (min 10)' });
  const r = el('select', {}, ['viewer', 'analyst', 'reviewer', 'admin'].map(x => el('option', { value: x, text: x })));
  r.value = 'analyst';
  shell('Users', 'users', [
    el('div', { class: 'card' }, el('h2', { text: 'Add or update a user' }),
      el('div', { class: 'row' }, u, p, r, el('button', { class: 'btn pri', text: 'Save', onclick: async () => {
        try { await api('POST', 'users', { user: u.value, password: p.value, role: r.value }); toast('Saved'); route(); } catch (e) { toast(e.message, true); }
      } })),
      el('p', { class: 'muted small', text: 'viewer: read only · analyst: upload, run, propose overrides, QA · reviewer: approve/reject others\' overrides · admin: users' })),
    el('div', { class: 'tw' }, el('table', {}, el('thead', {}, el('tr', {}, ['User', 'Role', 'Created', 'Updated', ''].map(h => el('th', { text: h })))),
      el('tbody', {}, us.map(x => el('tr', {}, el('td', { text: x.user }), el('td', {}, el('span', { class: 'role', text: x.role })), el('td', { class: 'small', text: x.created }), el('td', { class: 'small', text: x.updated }),
        el('td', {}, x.user === S.me.user ? '' : el('button', { class: 'btn sm', text: 'Remove', onclick: async () => {
          if (!confirm('Remove ' + x.user + '?')) return;
          try { await api('DELETE', 'users/' + encodeURIComponent(x.user)); route(); } catch (e) { toast(e.message, true); }
        } }))))))) ]);
}

/* ---------- help ---------- */
function viewHelp() {
  const li = (t, d) => el('li', {}, el('b', { text: t + ' ' }), d);
  shell('How it works', 'help', el('div', { class: 'grid g2' },
    el('div', { class: 'card' }, el('h2', { text: 'Workflow' }), el('ol', {},
      li('1. New audit:', 'upload the AlgoSec change reports, the RFC port sheets and (optionally) the SMAX export, then Run.'),
      li('2. Review queue:', 'every rule with a PIR issue, a REVIEW, low confidence, or a pending override. Open a rule to see why.'),
      li('3. Evidence:', 'the rule\'s IPs and ports next to every RFC line; green overlaps, red does not; anything not approved is listed in red.'),
      li('4. Correct false positives:', 'propose an override with a reason and evidence. A second reviewer approves it (maker-checker).'),
      li('5. Final report:', 'Re-run final report. The workbook shows both the tool verdict and the final verdict, plus a Reviewer Overrides sheet.'),
      li('6. QA sample:', 'a random share of "implemented" rules for a human to re-check; the dashboard shows measured accuracy.'),
      li('7. Evidence pack:', 'one ZIP with reports, verdicts, explanations, audit trail and SHA-256 checksums for auditors.'))),
    el('div', { class: 'card' }, el('h2', { text: 'Reading the verdicts' }), el('ul', {},
      li('PIR ISSUE = YES', 'the rule opens something the RFC did not approve.'),
      li('NO', 'source, destination and ports are all inside the cited RFC.'),
      li('REVIEW', 'the tool could not verify fully (missing RFC sheet, object without IP, unknown service).'),
      li('Confidence', 'High: every value was read exactly. Medium: something was assumed (TCP when Port Type blank, port from a service name, rule wider than any one RFC line). Low: something could not be read.'),
      li('Override keyed to content', 'if the firewall rule changes, its old override stops applying and the rule is checked again.')))));
}

/* ---------- boot ---------- */
async function boot() {
  try { S.me = await api('GET', 'me'); } catch (e) { return renderLogin(); }
  await refreshPending();
  route();
}
boot();
})();
"""
