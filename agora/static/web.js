/* Native, self-hosted controls. This shared script never opens a participant key. */
'use strict';

function initTheme() {
  let saved;
  try { saved = localStorage.getItem('sab-dark'); } catch (_) { /* Storage is optional for theme. */ }
  let dark = saved === 'true' || (saved === null && window.matchMedia('(prefers-color-scheme: dark)').matches);
  function render() {
    document.documentElement.classList.toggle('dark', dark);
    document.querySelectorAll('[data-theme-moon]').forEach(node => { node.toggleAttribute('hidden', dark); });
    document.querySelectorAll('[data-theme-sun]').forEach(node => { node.toggleAttribute('hidden', !dark); });
    document.querySelectorAll('[data-theme-toggle]').forEach(node => node.setAttribute('aria-pressed', String(dark)));
  }
  render();
  document.querySelectorAll('[data-theme-toggle]').forEach(button => button.addEventListener('click', () => {
    dark = !dark;
    try { localStorage.setItem('sab-dark', String(dark)); } catch (_) { /* Keep working without persistence. */ }
    render();
    document.querySelectorAll('[data-radar-init]').forEach(renderRadar);
  }));
}

function renderRadar(root) {
  let dimensions;
  try { dimensions = JSON.parse(root.dataset.dimensions); } catch (_) { return; }
  if (!Array.isArray(dimensions) || dimensions.length < 3) return;
  const ns = 'http://www.w3.org/2000/svg';
  const svg = document.createElementNS(ns, 'svg');
  svg.setAttribute('viewBox', '0 0 420 420');
  svg.setAttribute('aria-hidden', 'true');
  const point = (index, radius) => {
    const angle = index * Math.PI * 2 / dimensions.length - Math.PI / 2;
    return [210 + Math.cos(angle) * radius, 210 + Math.sin(angle) * radius];
  };
  function element(tag, attributes, text) {
    const node = document.createElementNS(ns, tag);
    Object.entries(attributes).forEach(([name, value]) => node.setAttribute(name, String(value)));
    if (text !== undefined) node.textContent = text;
    svg.append(node);
  }
  for (const scale of [.25, .5, .75, 1]) {
    element('polygon', {points: dimensions.map((_, i) => point(i, 145 * scale).join(',')).join(' '), fill:'none', stroke:'var(--color-border)'});
  }
  const values = dimensions.map((dim, i) => point(i, 145 * (Number.isFinite(dim.score) ? Math.max(0, Math.min(1, dim.score)) : 0)).join(','));
  element('polygon', {points:values.join(' '), fill:'var(--color-accent)', 'fill-opacity':'.12', stroke:'var(--color-accent)', 'stroke-width':2});
  dimensions.forEach((dim, i) => {
    const [x, y] = point(i, 173);
    element('text', {x,y,'text-anchor':'middle','dominant-baseline':'middle',fill:'var(--color-muted)','font-size':11}, dim.label);
    if (Number.isFinite(dim.score)) {
      const [cx, cy] = point(i, 145 * Math.max(0, Math.min(1, dim.score)));
      element('circle', {cx,cy,r:3,fill:'var(--color-accent)'});
    }
  });
  root.replaceChildren(svg);
}

function setChainStatus(root, className, text) {
  const status = root.querySelector('[data-chain-status]');
  if (!status) return;
  status.classList.remove('chain-verified', 'chain-broken', 'chain-pending');
  status.classList.add(className);
  status.textContent = text;
}

async function verifyChainFromEndpoint(root) {
  const endpoint = root.dataset.chainEndpoint;
  if (!endpoint || !/^\/api\/spark\/\d+\/chain$/.test(endpoint)) return;
  setChainStatus(root, 'chain-pending', 'checking with server');
  try {
    const response = await fetch(endpoint, {headers:{Accept:'application/json'}, credentials:'omit', redirect:'error'});
    if (!response.ok) throw new Error('unavailable');
    const data = await response.json();
    const entries = Array.isArray(data.entries) ? data.entries : [];
    setChainStatus(root, data.verified === true ? 'chain-verified' : 'chain-broken',
      data.verified === true ? `server checked ${entries.length} entries` : 'server reports a broken chain');
  } catch (_) { setChainStatus(root, 'chain-broken', 'server check unavailable'); }
}

document.addEventListener('DOMContentLoaded', () => {
  initTheme();
  document.querySelectorAll('[data-radar-init]').forEach(renderRadar);
  document.querySelectorAll('[data-chain-verifier]').forEach(root => {
    root.querySelector('[data-chain-trigger]')?.addEventListener('click', () => verifyChainFromEndpoint(root));
    verifyChainFromEndpoint(root);
  });
  document.querySelectorAll('[data-copy]').forEach(button => button.addEventListener('click', async () => {
    try { await navigator.clipboard.writeText(button.dataset.copy); button.textContent = 'Copied'; }
    catch (_) { button.textContent = 'Select text to copy'; }
  }));
});
