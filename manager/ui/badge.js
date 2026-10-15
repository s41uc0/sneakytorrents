// Injected into qBittorrent's web UI: a small VPN status pill linking to /vpn/.
(() => {
  const el = document.createElement('a');
  el.href = '/vpn/';
  el.title = 'VPN settings';
  Object.assign(el.style, {
    position: 'fixed', right: '12px', bottom: '34px', zIndex: '100000', display: 'none',
    padding: '5px 12px', borderRadius: '999px', color: '#fff', textDecoration: 'none',
    font: '600 12px/1.4 system-ui, -apple-system, sans-serif', boxShadow: '0 2px 8px rgba(0,0,0,.3)',
  });
  const colors = { connected: '#1f8f5f', connecting: '#b07800', error: '#c23a52', off: '#6b7480' };

  async function tick() {
    try {
      const r = await fetch('/vpn/api/status', { credentials: 'same-origin' });
      if (!r.ok) { el.style.display = 'none'; return; }
      const v = (await r.json()).vpn;
      const where = [v.exit_city, v.exit_country].filter(Boolean).join(', ');
      el.textContent = v.state === 'connected'
        ? `🔒 VPN · ${where || v.server || 'connected'}${v.public_ip ? ' · ' + v.public_ip : ''}`
        : v.state === 'connecting' ? '⏳ VPN connecting… torrents paused' : '⛔ VPN down · torrents blocked';
      el.style.background = colors[v.state] || colors.off;
      el.style.display = 'block';
    } catch {
      el.style.display = 'none';
    }
  }

  document.body.append(el);
  tick();
  setInterval(tick, 10000);
})();
