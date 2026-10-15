'use strict';

const $app = document.getElementById('app');
// URL prefix in front of /vpn/: empty normally, /api/hassio_ingress/<token> inside Home Assistant.
const BASE = location.pathname.replace(/\/vpn\/.*$/, '');

// --- tiny DOM + API helpers ---

function h(tag, props, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(props || {})) {
    if (v == null || v === false) continue;
    if (k === 'class') el.className = v;
    else if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
    else if (k === 'value') el.value = v;
    else el.setAttribute(k, v === true ? '' : v);
  }
  for (const kid of kids.flat(Infinity)) {
    if (kid == null || kid === false) continue;
    el.append(kid instanceof Node ? kid : String(kid));
  }
  return el;
}

// fill replaces el's children, skipping null/false like h() does.
function fill(el, ...kids) {
  el.replaceChildren();
  for (const kid of kids.flat(Infinity)) {
    if (kid == null || kid === false || kid === '') continue;
    el.append(kid instanceof Node ? kid : String(kid));
  }
}

function svg(markup) {
  const t = document.createElement('template');
  t.innerHTML = markup.trim();
  return t.content.firstChild;
}

const icons = {
  lock: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><rect x="4" y="11" width="16" height="10" rx="2"/><path d="M8 11V7a4 4 0 0 1 8 0v4"/></svg>`,
  check: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.6" stroke-linecap="round" stroke-linejoin="round"><path d="M5 12.5l4.5 4.5L19 7.5"/></svg>`,
  alert: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><path d="M12 8v5M12 16.5v.5"/><circle cx="12" cy="12" r="9.5"/></svg>`,
};

class AuthError extends Error {}

async function api(path, body) {
  const opts = body === undefined ? {} : {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  };
  const r = await fetch(BASE + '/vpn/api/' + path, opts);
  const data = await r.json().catch(() => ({}));
  if (r.status === 401) {
    if (session.authed) { session.authed = false; render(); }
    throw new AuthError('Please log in again');
  }
  if (!r.ok) throw new Error(data.error || r.statusText);
  return data;
}

function errLine() {
  const el = h('p', { class: 'error', role: 'alert' });
  return { el, show: (msg) => { el.textContent = msg; }, clear: () => { el.textContent = ''; } };
}

async function busy(btn, fn, err) {
  const label = btn.textContent;
  btn.disabled = true;
  btn.textContent = 'Working…';
  err && err.clear();
  try {
    await fn();
  } catch (e) {
    if (err && !(e instanceof AuthError)) err.show(e.message);
  } finally {
    btn.disabled = false;
    btn.textContent = label;
  }
}

function field(label, input, hint) {
  return h('label', { class: 'field' }, h('span', {}, label), input, hint && h('small', {}, hint));
}

function row(k, v) { return [h('dt', {}, k), h('dd', {}, v)]; }

function fmtBytes(n) {
  if (!n) return '0 B';
  const u = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.min(u.length - 1, Math.floor(Math.log(n) / Math.log(1024)));
  return (n / 1024 ** i).toFixed(i ? 1 : 0) + ' ' + u[i];
}

function fmtDuration(sec) {
  sec = Math.max(0, Math.round(sec));
  if (sec < 60) return sec + 's';
  const m = Math.floor(sec / 60);
  if (m < 60) return m + 'm';
  const hr = Math.floor(m / 60);
  if (hr < 48) return hr + 'h ' + (m % 60) + 'm';
  return Math.floor(hr / 24) + 'd ' + (hr % 24) + 'h';
}

const since = (iso) => (Date.now() - new Date(iso).getTime()) / 1000;
const fmtDate = (iso) => new Date(iso).toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' });
const providerName = (p) => ({ mullvad: 'Mullvad', wireguard: 'WireGuard', openvpn: 'OpenVPN' })[p] || '';

const brand = () => h('div', { class: 'brand' }, svg(icons.lock), 'sneakytorrents');

// --- app state & routing ---

let session = { account_set: false, authed: false, onboarded: false };
let wizardStep = null; // keeps the wizard on screen through its last step
let timers = [];

function every(ms, fn) { fn(); timers.push(setInterval(fn, ms)); }

async function refreshSession() { session = await api('session'); }

function render() {
  timers.forEach(clearInterval);
  timers = [];
  let view;
  if (session.ha && !session.authed && !session.account_set) view = haClosedView();
  else if (!session.account_set && !session.ingress) view = wizard(1);
  else if (!session.authed) view = loginView();
  else if (!session.onboarded || wizardStep) view = wizard(wizardStep || 2);
  else view = dashboard();
  $app.replaceChildren(view);
}

// --- onboarding ---

// Shown on the app's direct port in Home Assistant before a login exists.
function haClosedView() {
  return h('main', { class: 'narrow' }, brand(), h('section', { class: 'card', style: 'margin-top:20px' },
    h('h2', {}, 'Open sneakytorrents from Home Assistant'),
    h('p', { class: 'muted' }, 'This address needs its own login. Open sneakytorrents from the Home Assistant sidebar and create one under Direct access login.')));
}

function wizard(step) {
  // Inside Home Assistant, Home Assistant's login is used, so there is no login step.
  const steps = (session.ingress ? ['VPN', 'Connect'] : ['Login', 'VPN', 'Connect']);
  const offset = session.ingress ? 1 : 0;
  const body = step === 1 ? accountStep() : step === 2 ? vpnStep() : connectStep();
  return h('main', { class: 'narrow' },
    brand(),
    h('ol', { class: 'steps' }, steps.map((s, i) => {
      const n = i + 1 + offset;
      return h('li', { class: n < step ? 'done' : n === step ? 'current' : '' }, h('span', { class: 'n' }, i + 1), s);
    })),
    body);
}

function accountStep() {
  const user = h('input', { value: 'admin', autocomplete: 'username', required: true });
  const pass = h('input', { type: 'password', autocomplete: 'new-password', minlength: 8, required: true });
  const pass2 = h('input', { type: 'password', autocomplete: 'new-password', required: true });
  const err = errLine();
  const btn = h('button', { class: 'primary', type: 'submit' }, 'Create login');
  return h('form', {
    class: 'card',
    onsubmit: async (e) => {
      e.preventDefault();
      if (pass.value !== pass2.value) return err.show("The passwords don't match");
      await busy(btn, async () => {
        await api('setup/account', { username: user.value, password: pass.value });
        await refreshSession();
        wizardStep = 2;
        render();
      }, err);
    },
  },
  h('h2', {}, 'Create your login'),
  h('p', { class: 'muted' }, 'This login protects both the VPN settings and qBittorrent.'),
  field('Username', user),
  field('Password', pass, 'At least 8 characters'),
  field('Confirm password', pass2),
  err.el,
  h('div', { class: 'actions' }, btn));
}

function loginView() {
  const user = h('input', { autocomplete: 'username', required: true });
  const pass = h('input', { type: 'password', autocomplete: 'current-password', required: true });
  const err = errLine();
  const btn = h('button', { class: 'primary', type: 'submit' }, 'Log in');
  return h('main', { class: 'narrow' }, brand(), h('form', {
    class: 'card',
    style: 'margin-top:20px',
    onsubmit: async (e) => {
      e.preventDefault();
      await busy(btn, async () => {
        await api('login', { username: user.value, password: pass.value });
        await refreshSession();
        render();
      }, err);
    },
  },
  h('h2', {}, 'Log in'),
  field('Username', user),
  field('Password', pass),
  err.el,
  h('div', { class: 'actions' }, btn)));
}

function vpnStep() {
  return providerEditor({
    title: 'Choose your VPN',
    submitLabel: 'Connect',
    onSaved: () => { wizardStep = 3; render(); },
  });
}

function connectStep() {
  const card = h('section', { class: 'card center' }, h('div', { class: 'spinner' }));
  every(1500, async () => {
    let st;
    try { st = await api('status'); } catch { return; }
    const v = st.vpn;
    if (v.state === 'connected' && v.public_ip) {
      const where = [v.exit_city, v.exit_country].filter(Boolean).join(', ');
      fill(card,
        h('div', { class: 'hero-icon' }, svg(icons.check)),
        h('h2', {}, "You're connected"),
        h('p', {}, 'qBittorrent now sends all its traffic through ', h('strong', {}, v.server || 'the VPN'), '.'),
        h('dl', { class: 'kv', style: 'max-width:340px;margin:16px auto 0;text-align:left' },
          row('Exit IP', v.public_ip), where && row('Exit location', where)),
        h('div', { class: 'actions' },
          h('a', { class: 'button primary', href: BASE + '/' }, 'Open qBittorrent'),
          h('button', { onclick: () => { wizardStep = null; render(); } }, 'VPN dashboard')));
    } else if (v.error) {
      card.replaceChildren(
        h('div', { class: 'hero-icon bad' }, svg(icons.alert)),
        h('h2', {}, "Couldn't connect yet"),
        h('p', { class: 'error' }, v.error),
        h('p', { class: 'muted small' }, 'It keeps retrying in the background. qBittorrent stays offline until the tunnel is up.'),
        h('div', { class: 'actions' },
          h('button', { onclick: () => { wizardStep = 2; render(); } }, 'Change settings')));
    } else {
      card.replaceChildren(
        h('div', { class: 'spinner' }),
        h('h2', {}, v.state === 'connected' ? 'Checking your exit IP…' : 'Connecting…'),
        h('p', { class: 'muted' }, v.server ? `to ${v.server}${v.location ? ' (' + v.location + ')' : ''}` : ''));
    }
  });
  return card;
}

// --- provider settings (shared by onboarding and dashboard) ---

function providerEditor({ title, submitLabel, onSaved }) {
  const tabsEl = h('div', { class: 'tabs', role: 'tablist' });
  const note = h('div');
  const panel = h('div', {}, h('p', { class: 'muted' }, 'Loading…'));
  const card = h('section', { class: 'card' }, h('h2', {}, title), note, tabsEl, panel);
  let settings = null;
  let current = null;

  // Only offer what this host can run: Mullvad needs WireGuard (it no longer offers OpenVPN).
  function available() {
    const caps = settings.capabilities;
    const tabs = {};
    if (caps.wireguard !== 'none') Object.assign(tabs, { mullvad: 'Mullvad', wireguard: 'WireGuard' });
    if (caps.openvpn) tabs.openvpn = 'OpenVPN';
    return tabs;
  }

  function select(name) {
    const tabs = available();
    if (!Object.keys(tabs).length) {
      tabsEl.replaceChildren();
      panel.replaceChildren(h('p', { class: 'error' }, "This container can't create a VPN tunnel. Start it with --device /dev/net/tun and --cap-add NET_ADMIN."));
      return;
    }
    if (!tabs[name]) name = Object.keys(tabs)[0];
    fill(note, settings.capabilities.wireguard === 'none' && h('p', { class: 'muted small' },
      "WireGuard isn't available on this host, so only OpenVPN is offered. Mullvad no longer supports OpenVPN."));
    current = name;
    tabsEl.replaceChildren(...Object.entries(tabs).map(([k, label]) => h('button', {
      type: 'button', role: 'tab', 'aria-selected': String(k === name),
      class: k === name ? 'tab active' : 'tab', onclick: () => select(k),
    }, label)));
    const ctx = { settings, submitLabel, onSaved, reload };
    panel.replaceChildren(
      name === 'mullvad' ? mullvadPanel(ctx) : name === 'wireguard' ? wireguardPanel(ctx) : openvpnPanel(ctx));
  }
  async function reload() {
    settings = await api('settings');
    select(current);
  }
  api('settings')
    .then((s) => { settings = s; select(s.provider || 'mullvad'); })
    .catch((e) => panel.replaceChildren(h('p', { class: 'error' }, e.message)));
  return card;
}

async function saveVPN(ctx, body, btn, err) {
  await busy(btn, async () => {
    await api('vpn', body);
    ctx.onSaved();
  }, err);
}

function mullvadPanel(ctx) {
  const m = ctx.settings.mullvad;
  const err = errLine();

  if (!m.signed_in) {
    const acct = h('input', { inputmode: 'numeric', autocomplete: 'off', placeholder: '1234 5678 9012 3456', required: true });
    const btn = h('button', { class: 'primary', type: 'submit' }, 'Sign in');
    return h('form', {
      onsubmit: async (e) => {
        e.preventDefault();
        await busy(btn, async () => {
          await api('mullvad/login', { account: acct.value });
          await ctx.reload();
        }, err);
      },
    },
    h('p', { class: 'muted' }, 'Enter your Mullvad account number. A WireGuard key is generated for this container and added to your account as a device.'),
    field('Account number', acct),
    err.el,
    h('div', { class: 'actions' }, btn));
  }

  const country = h('select', { disabled: true }, h('option', {}, 'Loading servers…'));
  const city = h('select', { disabled: true });
  const server = h('select', { disabled: true });
  const btn = h('button', { class: 'primary', type: 'submit' }, ctx.submitLabel);
  const signout = h('button', {
    type: 'button', class: 'link',
    onclick: async () => {
      if (!confirm('Sign out of Mullvad? This removes the device from your account and stops the VPN.')) return;
      await busy(signout, async () => {
        await api('mullvad/logout', {});
        await ctx.reload();
      }, err);
    },
  }, 'Sign out');

  api('mullvad/relays').then((list) => {
    const opt = (value, label, selected) => h('option', { value, selected }, label);
    const fillCountry = () => {
      country.replaceChildren(opt('', 'Any country'), ...list.map((c) => opt(c.code, c.name, c.code === m.country)));
      country.disabled = false;
    };
    const fillCity = () => {
      const c = list.find((c) => c.code === country.value);
      city.replaceChildren(opt('', c ? 'Any city' : '-'), ...(c ? c.cities.map((ci) => opt(ci.code, ci.name, ci.code === m.city)) : []));
      city.disabled = !c;
    };
    const fillServer = () => {
      const c = list.find((c) => c.code === country.value);
      const ci = c && c.cities.find((x) => x.code === city.value);
      server.replaceChildren(opt('', ci ? 'Any server' : '-'), ...(ci ? ci.servers.map((s) =>
        opt(s.hostname, `${s.hostname} · ${s.owned ? 'Mullvad-owned' : s.provider}`, s.hostname === m.hostname)) : []));
      server.disabled = !ci;
    };
    fillCountry(); fillCity(); fillServer();
    country.onchange = () => { m.city = ''; m.hostname = ''; fillCity(); fillServer(); };
    city.onchange = () => { m.hostname = ''; fillServer(); };
  }).catch((e) => err.show(e.message));

  return h('div', {},
    h('div', { class: 'account' },
      h('div', {},
        h('strong', {}, m.device_name ? `Device “${m.device_name}”` : 'Signed in'),
        h('div', { class: 'muted small' }, `Account ${m.account}${m.expiry ? ' · paid until ' + fmtDate(m.expiry) : ''}`)),
      signout),
    h('form', {
      onsubmit: (e) => {
        e.preventDefault();
        saveVPN(ctx, { provider: 'mullvad', mullvad: { country: country.value, city: city.value, hostname: server.value } }, btn, err);
      },
    },
    h('div', { class: 'grid3' }, field('Country', country), field('City', city), field('Server', server)),
    h('p', { class: 'muted small' }, 'With "Any", a server is picked for you, and a different one is used if it stops responding.'),
    err.el,
    h('div', { class: 'actions' }, btn)));
}

function parseWireGuard(text) {
  const keys = { privatekey: 'private_key', address: 'address', dns: 'dns', mtu: 'mtu', publickey: 'public_key', presharedkey: 'preshared_key', endpoint: 'endpoint' };
  const out = {};
  for (const line of text.split('\n')) {
    const m = line.match(/^\s*([A-Za-z]+)\s*=\s*(.+?)\s*$/);
    const k = m && keys[m[1].toLowerCase()];
    if (k && !out[k]) out[k] = m[2];
  }
  return out;
}

function wireguardPanel(ctx) {
  const w = ctx.settings.wireguard;
  const keep = 'Saved; leave blank to keep';
  const f = {
    private_key: h('input', { type: 'password', autocomplete: 'off', placeholder: w.has_private_key ? keep : '', required: !w.has_private_key }),
    address: h('input', { value: w.address, placeholder: '10.2.0.2/32', required: true }),
    public_key: h('input', { value: w.public_key, required: true }),
    preshared_key: h('input', { type: 'password', autocomplete: 'off', placeholder: w.has_preshared_key ? keep : 'Optional' }),
    endpoint: h('input', { value: w.endpoint, placeholder: 'vpn.example.com:51820', required: true }),
    dns: h('input', { value: w.dns, placeholder: 'Optional (default 1.1.1.1)' }),
    mtu: h('input', { type: 'number', min: 1280, max: 1500, value: w.mtu || '', placeholder: '1380' }),
  };
  const paste = h('textarea', {
    rows: 8, spellcheck: 'false',
    placeholder: '[Interface]\nPrivateKey = …\nAddress = 10.2.0.2/32\nDNS = 10.2.0.1\n\n[Peer]\nPublicKey = …\nEndpoint = vpn.example.com:51820',
  });
  const fill = () => {
    for (const [k, v] of Object.entries(parseWireGuard(paste.value))) if (f[k]) f[k].value = v;
  };
  paste.addEventListener('input', fill);
  const file = h('input', {
    type: 'file', accept: '.conf,text/plain',
    onchange: async () => { if (file.files[0]) { paste.value = await file.files[0].text(); fill(); } },
  });
  const err = errLine();
  const btn = h('button', { class: 'primary', type: 'submit' }, ctx.submitLabel);

  return h('form', {
    onsubmit: (e) => {
      e.preventDefault();
      const body = Object.fromEntries(Object.entries(f).map(([k, el]) => [k, el.value]));
      body.mtu = Number(body.mtu) || 0;
      saveVPN(ctx, { provider: 'wireguard', wireguard: body }, btn, err);
    },
  },
  h('p', { class: 'muted' }, 'Any provider or server that gives you a WireGuard config (Proton, IVPN, AirVPN, your own server…).'),
  h('details', { class: 'paste', open: !w.has_private_key },
    h('summary', {}, 'Fill in from a config file'),
    field('Open a .conf file', file),
    field('…or paste it', paste, 'Only the fields below are kept; IPv6 entries are ignored.')),
  field('Private key', f.private_key),
  h('div', { class: 'grid2' }, field('Address', f.address), field('Endpoint', f.endpoint)),
  field('Server public key', f.public_key),
  h('div', { class: 'grid3' }, field('Preshared key', f.preshared_key), field('DNS', f.dns), field('MTU', f.mtu)),
  err.el,
  h('div', { class: 'actions' }, btn));
}

function openvpnPanel(ctx) {
  const o = ctx.settings.openvpn;
  const cfg = h('textarea', { rows: 10, spellcheck: 'false', value: o.config || '', placeholder: 'client\ndev tun\nproto udp\nremote vpn.example.com 1194\n<ca>\n…\n</ca>', required: true });
  const file = h('input', {
    type: 'file', accept: '.ovpn,.conf,text/plain',
    onchange: async () => { if (file.files[0]) cfg.value = await file.files[0].text(); },
  });
  const user = h('input', { value: o.username, autocomplete: 'off' });
  const pass = h('input', { type: 'password', autocomplete: 'off', placeholder: o.has_password ? 'Saved; leave blank to keep' : '' });
  const dns = h('input', { value: o.dns, placeholder: 'Optional; uses the DNS the server pushes' });
  const err = errLine();
  const btn = h('button', { class: 'primary', type: 'submit' }, ctx.submitLabel);

  return h('form', {
    onsubmit: (e) => {
      e.preventDefault();
      saveVPN(ctx, { provider: 'openvpn', openvpn: { config: cfg.value, username: user.value, password: pass.value, dns: dns.value } }, btn, err);
    },
  },
  h('p', { class: 'muted' }, "Any provider's .ovpn file. Certificates and keys must be inline in the file, not separate files."),
  field('Open an .ovpn file', file),
  field('Config', cfg),
  h('div', { class: 'grid3' }, field('Username', user), field('Password', pass), field('DNS', dns)),
  err.el,
  h('div', { class: 'actions' }, btn));
}

// --- dashboard ---

function dashboard() {
  const statusCard = h('section', { class: 'card' }, h('p', { class: 'muted' }, 'Loading…'));
  const killCard = h('section', { class: 'card' });
  const logout = h('button', {
    onclick: async () => {
      await api('logout', {}).catch(() => {});
      session.authed = false;
      render();
    },
  }, 'Log out');

  every(3000, async () => {
    let st;
    try { st = await api('status'); } catch { return; }
    renderStatus(statusCard, st);
    renderKillSwitch(killCard, st);
  });

  return h('main', {},
    h('div', { class: 'topbar' }, brand(),
      h('nav', {}, h('a', { class: 'button primary', href: BASE + '/' }, 'Open qBittorrent'), !session.ingress && logout)),
    h('div', { class: 'grid' }, statusCard, killCard),
    providerEditor({ title: 'VPN settings', submitLabel: 'Save and reconnect', onSaved: () => {} }),
    portCard(),
    session.ingress ? haLoginCard() : accountCard(),
    logsCard());
}

function accountCard() {
  const cur = h('input', { type: 'password', autocomplete: 'current-password', required: true });
  const next = h('input', { type: 'password', autocomplete: 'new-password', minlength: 8, required: true });
  const next2 = h('input', { type: 'password', autocomplete: 'new-password', required: true });
  const err = errLine();
  const done = h('p', { class: 'muted small', role: 'status' });
  const btn = h('button', { type: 'submit' }, 'Change password');
  return h('form', {
    class: 'card',
    onsubmit: async (e) => {
      e.preventDefault();
      done.textContent = '';
      if (next.value !== next2.value) return err.show("The new passwords don't match");
      await busy(btn, async () => {
        await api('password', { current: cur.value, new: next.value });
        cur.value = next.value = next2.value = '';
        done.textContent = 'Password changed. Other devices have been logged out.';
      }, err);
    },
  },
  h('h2', {}, 'Account'),
  h('p', { class: 'muted small' }, `Logged in as ${session.username || ''}.`),
  h('div', { class: 'grid3' }, field('Current password', cur), field('New password', next), field('Confirm new password', next2)),
  err.el,
  done,
  h('div', { class: 'actions' }, btn));
}

// Inside Home Assistant: an optional login for the app's direct network port.
function haLoginCard() {
  const user = h('input', { value: session.username || 'admin', autocomplete: 'username', required: true, disabled: session.account_set });
  const next = h('input', { type: 'password', autocomplete: 'new-password', minlength: 8, required: true });
  const next2 = h('input', { type: 'password', autocomplete: 'new-password', required: true });
  const err = errLine();
  const done = h('p', { class: 'muted small', role: 'status' });
  const btn = h('button', { type: 'submit' }, session.account_set ? 'Set new password' : 'Create login');
  return h('form', {
    class: 'card',
    onsubmit: async (e) => {
      e.preventDefault();
      done.textContent = '';
      if (next.value !== next2.value) return err.show("The passwords don't match");
      await busy(btn, async () => {
        if (session.account_set) {
          await api('password', { current: '', new: next.value });
          done.textContent = 'Password changed. Devices using the direct address have been logged out.';
        } else {
          await api('setup/account', { username: user.value, password: next.value });
          await refreshSession();
          done.textContent = 'Login created.';
        }
        next.value = next2.value = '';
      }, err);
    },
  },
  h('h2', {}, 'Direct access login'),
  h('p', { class: 'muted small' },
    "Only needed if you turn on this app's network port in Home Assistant, to reach it without Home Assistant. Inside Home Assistant your Home Assistant login is used.",
    session.account_set ? ` Current login: ${session.username}.` : ' No login has been created, so the direct port stays closed.'),
  h('div', { class: 'grid3' }, field('Username', user), field('Password', next), field('Confirm password', next2)),
  err.el,
  done,
  h('div', { class: 'actions' }, btn));
}

function renderStatus(card, st) {
  const v = st.vpn;
  const labels = { connected: 'Connected', connecting: 'Connecting…', error: 'Not connected', off: 'Disconnected' };
  const tone = { connected: 'ok', connecting: 'warn', error: 'bad', off: 'off' }[v.state] || 'off';
  const where = [v.exit_city, v.exit_country].filter(Boolean).join(', ');
  const sub = [providerName(st.provider), v.server, v.location].filter(Boolean).join(' · ');
  const act = (label, path, cls) => {
    const b = h('button', { class: cls, onclick: () => busy(b, () => api(path, {})) }, label);
    return b;
  };
  fill(card,
    h('div', { class: 'status-head' }, h('span', { class: `dot ${tone}` }),
      h('div', {}, h('h2', {}, labels[v.state] || v.state), sub && h('div', { class: 'muted' }, sub))),
    v.error && v.state !== 'connected' && h('p', { class: 'error' }, v.error),
    h('dl', { class: 'kv' },
      row('Exit IP', v.public_ip || '-'),
      row('Exit location', where || '-'),
      v.state === 'connected' && v.since && row('Connected for', fmtDuration(since(v.since))),
      v.handshake && row('Last handshake', fmtDuration(since(v.handshake)) + ' ago'),
      st.provider !== 'openvpn' && st.capabilities && row('WireGuard', st.capabilities.wireguard === 'kernel' ? 'kernel module' : 'wireguard-go (userspace)'),
      (v.rx_bytes > 0 || v.tx_bytes > 0) && row('Tunnel traffic', `↓ ${fmtBytes(v.rx_bytes)}   ↑ ${fmtBytes(v.tx_bytes)}`)),
    h('div', { class: 'actions' }, st.enabled
      ? [act('Reconnect', 'connect'), act('Disconnect', 'disconnect')]
      : act('Connect', 'connect', 'primary')));
}

function renderKillSwitch(card, st) {
  card.replaceChildren(
    h('h2', {}, 'Kill switch'),
    h('p', { class: 'muted small' }, 'qBittorrent can only reach the internet through the tunnel. When the VPN is down, its traffic is blocked rather than sent over your own connection.'),
    h('div', { class: 'big' }, Number(st.leaks_blocked).toLocaleString()),
    h('div', { class: 'muted small' }, 'packets blocked since the container started'),
    h('p', { class: 'muted small' }, st.qbittorrent ? 'qBittorrent is running.' : 'qBittorrent is starting…'));
}

function portCard() {
  const input = h('input', { type: 'number', min: 0, max: 65535, placeholder: 'None' });
  const err = errLine();
  const btn = h('button', { type: 'submit' }, 'Save');
  api('settings').then((s) => { input.value = s.forwarded_port || ''; }).catch(() => {});
  return h('form', {
    class: 'card',
    onsubmit: async (e) => {
      e.preventDefault();
      await busy(btn, () => api('port', { port: Number(input.value) || 0 }), err);
    },
  },
  h('h2', {}, 'Port forwarding'),
  h('p', { class: 'muted small' }, "If your VPN provider forwards a port to you, enter it here so peers can connect to you. qBittorrent listens on it and the firewall lets it in through the tunnel. Mullvad doesn't offer port forwarding."),
  h('div', { style: 'max-width:220px' }, field('Forwarded port', input)),
  err.el,
  h('div', { class: 'actions' }, btn));
}

function logsCard() {
  const pre = h('pre', { class: 'logs' });
  const load = async () => {
    try {
      const { lines } = await api('logs');
      pre.textContent = lines.join('\n');
      pre.scrollTop = pre.scrollHeight;
    } catch (e) { pre.textContent = e.message; }
  };
  const details = h('details', { class: 'card', ontoggle: () => details.open && load() },
    h('summary', {}, 'Logs'),
    h('div', { class: 'actions' }, h('button', { type: 'button', onclick: load }, 'Refresh')),
    pre);
  return details;
}

// --- boot ---

refreshSession()
  .then(render)
  .catch((e) => $app.replaceChildren(h('main', { class: 'narrow' }, brand(), h('p', { class: 'error' }, e.message))));
