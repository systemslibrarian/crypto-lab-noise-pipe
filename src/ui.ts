/**
 * UI controller for crypto-lab-noise-pipe.
 * Manages six panels: Pattern, Handshake, Transport, Break it, Compare, WireGuard.
 */

import {
  PATTERNS, getPatternNames, getPatternInfo, formatPatternMessages,
  TOKEN_DESCRIPTIONS, GLOSSARY, PROPERTY_EXPLANATIONS, getPredictPrompt,
  PatternInfo, type HandshakePattern, type Token
} from './patterns';
import {
  runFullHandshake, type FullHandshakeResult, type StepLog, type MessageLog,
  type PartyStateSnapshot, CipherState,
  simulateBitFlip, simulateNonceReuse, simulateRSSwap, simulatePSKMismatch, simulateReplay
} from './noise';
import { toHex, EMPTY } from './crypto';

// ----- State -----

let currentPattern: string = 'XX';
let handshakeResult: FullHandshakeResult | null = null;
let currentStep: number = 0;
let activePanel: string = 'panel-pattern';

// Transport (bidirectional with rekey)
let cI2R: CipherState | null = null; // initiator's send / responder's recv (c1)
let cR2I: CipherState | null = null; // responder's send / initiator's recv (c2)
let nI2R = 0; // displayed counter for i→r direction
let nR2I = 0;

// Compare panel selection
let comparePatterns = new Set<string>(['NN', 'XX', 'IK', 'IKpsk2']);

const reducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

// ----- Initialization -----

export function initUI(): void {
  setupPatternSelector();
  setupPanelTabs();
  setupGlossaryTooltip();
  setupKeyboardShortcuts();
  setupBreakItPanel();
  setupComparePicker();
  setupTransportLanes();
  setupExportTranscript();
  selectPattern('XX');
}

// ----- Keyboard shortcuts -----

function setupKeyboardShortcuts(): void {
  document.addEventListener('keydown', (e) => {
    const tag = (e.target as HTMLElement | null)?.tagName;
    if (tag === 'INPUT' || tag === 'TEXTAREA' || (e.target as HTMLElement)?.isContentEditable) return;

    if (e.key >= '1' && e.key <= '6') {
      const tabs = document.querySelectorAll<HTMLButtonElement>('[role="tab"]');
      const idx = parseInt(e.key, 10) - 1;
      if (idx >= 0 && idx < tabs.length) {
        const target = tabs[idx].getAttribute('aria-controls');
        const panels = document.querySelectorAll<HTMLElement>('[role="tabpanel"]');
        if (target) activatePanel(target, tabs, panels);
        tabs[idx].focus();
      }
    } else if (activePanel === 'panel-walkthrough') {
      if (e.key === 'ArrowLeft') stepPrev();
      else if (e.key === 'ArrowRight') stepNext();
    }
  });
}

function stepPrev(): void {
  if (currentStep > 0) {
    currentStep--;
    renderCurrentStep();
  }
}

function stepNext(): void {
  if (!handshakeResult) return;
  if (currentStep < handshakeResult.messageLogs.length - 1) {
    currentStep++;
    renderCurrentStep();
  }
}

// ----- Panel Tabs -----

function setupPanelTabs(): void {
  const tabs = document.querySelectorAll<HTMLButtonElement>('[role="tab"]');
  const panels = document.querySelectorAll<HTMLElement>('[role="tabpanel"]');

  tabs.forEach(tab => {
    tab.addEventListener('click', () => {
      const target = tab.getAttribute('aria-controls');
      if (!target) return;
      activatePanel(target, tabs, panels);
    });

    tab.addEventListener('keydown', (e) => {
      const tabList = Array.from(tabs);
      const idx = tabList.indexOf(tab);
      let newIdx = idx;
      if (e.key === 'ArrowRight' || e.key === 'ArrowDown') {
        e.preventDefault();
        newIdx = (idx + 1) % tabList.length;
      } else if (e.key === 'ArrowLeft' || e.key === 'ArrowUp') {
        e.preventDefault();
        newIdx = (idx - 1 + tabList.length) % tabList.length;
      } else if (e.key === 'Home') {
        e.preventDefault();
        newIdx = 0;
      } else if (e.key === 'End') {
        e.preventDefault();
        newIdx = tabList.length - 1;
      }
      if (newIdx !== idx) {
        const newTab = tabList[newIdx];
        const target = newTab.getAttribute('aria-controls');
        if (target) activatePanel(target, tabs, panels);
        newTab.focus();
      }
    });
  });
}

function activatePanel(
  panelId: string,
  tabs: NodeListOf<HTMLButtonElement>,
  panels: NodeListOf<HTMLElement>
): void {
  activePanel = panelId;
  tabs.forEach(t => {
    const isSelected = t.getAttribute('aria-controls') === panelId;
    t.setAttribute('aria-selected', String(isSelected));
    t.setAttribute('tabindex', isSelected ? '0' : '-1');
  });
  panels.forEach(p => {
    p.hidden = p.id !== panelId;
  });
}

// ----- Glossary tooltip -----

function setupGlossaryTooltip(): void {
  const tip = document.getElementById('glossary-tip');
  if (!tip) return;

  const show = (target: HTMLElement) => {
    const term = target.dataset.term ?? target.textContent ?? '';
    const def = GLOSSARY[term];
    if (!def) return;
    tip.textContent = def;
    tip.hidden = false;
    const r = target.getBoundingClientRect();
    const tipR = tip.getBoundingClientRect();
    let left = r.left + window.scrollX + (r.width - tipR.width) / 2;
    left = Math.max(8, Math.min(left, window.innerWidth - tipR.width - 8));
    const top = r.bottom + window.scrollY + 6;
    tip.style.left = `${left}px`;
    tip.style.top = `${top}px`;
  };

  const hide = () => { tip.hidden = true; };

  document.addEventListener('mouseover', (e) => {
    const t = (e.target as HTMLElement).closest<HTMLElement>('.gl');
    if (t) show(t);
  });
  document.addEventListener('mouseout', (e) => {
    const t = (e.target as HTMLElement).closest<HTMLElement>('.gl');
    if (t) hide();
  });
  document.addEventListener('focusin', (e) => {
    const t = (e.target as HTMLElement).closest<HTMLElement>('.gl');
    if (t) show(t);
  });
  document.addEventListener('focusout', (e) => {
    const t = (e.target as HTMLElement).closest<HTMLElement>('.gl');
    if (t) hide();
  });
}

function gl(term: string, label?: string): string {
  return `<span class="gl" data-term="${escapeHtml(term)}" tabindex="0">${escapeHtml(label ?? term)}</span>`;
}

// ----- Pattern Selector -----

function setupPatternSelector(): void {
  const container = document.getElementById('pattern-chips');
  if (!container) return;

  getPatternNames().forEach(name => {
    const btn = document.createElement('button');
    btn.className = 'chip pattern-chip';
    btn.textContent = name;
    btn.setAttribute('aria-label', `Select ${name} pattern`);
    btn.setAttribute('role', 'radio');
    btn.setAttribute('aria-checked', 'false');
    btn.addEventListener('click', () => selectPattern(name));
    container.appendChild(btn);
  });
}

async function selectPattern(name: string): Promise<void> {
  currentPattern = name;
  currentStep = 0;

  document.querySelectorAll('.pattern-chip').forEach(chip => {
    const isSelected = chip.textContent === name;
    chip.classList.toggle('active', isSelected);
    chip.setAttribute('aria-checked', String(isSelected));
  });

  const info = getPatternInfo(name);
  renderPatternInfo(info);

  const statusEl = document.getElementById('handshake-status');
  if (statusEl) {
    statusEl.textContent = 'Running handshake…';
    statusEl.setAttribute('aria-live', 'polite');
  }

  try {
    handshakeResult = await runFullHandshake(info.pattern);
    if (statusEl) statusEl.textContent = 'Handshake complete';
    renderPreMessageCard(info.pattern);
    renderHandshakeWalkthrough();
    resetTransport();
  } catch (err) {
    if (statusEl) statusEl.textContent = `Error: ${(err as Error).message}`;
    console.error('Handshake error:', err);
  }
}

function renderPatternInfo(info: PatternInfo): void {
  const nameEl = document.getElementById('pattern-name');
  const descEl = document.getElementById('pattern-description');
  const messagesEl = document.getElementById('pattern-messages');
  const securityEl = document.getElementById('security-properties');
  const realWorldEl = document.getElementById('real-world-use');
  const tokenLegendEl = document.getElementById('token-legend');
  const vsTLSEl = document.getElementById('vs-tls-text');

  if (nameEl) nameEl.textContent = `Noise_${info.pattern.name}_25519_AESGCM_SHA256`;
  if (descEl) descEl.textContent = info.description;
  if (messagesEl) messagesEl.textContent = formatPatternMessages(info.pattern);
  if (realWorldEl) realWorldEl.textContent = info.realWorld;
  if (vsTLSEl) vsTLSEl.textContent = info.vsTLS;

  if (securityEl) {
    securityEl.innerHTML = '';
    const props = [
      { key: 'senderAuth', label: 'Authentication', value: info.security.senderAuth, icon: getAuthIcon(info.security.senderAuth) },
      { key: 'forwardSecrecy', label: gl('forward secrecy', 'Forward Secrecy'), value: info.security.forwardSecrecy, icon: getFSIcon(info.security.forwardSecrecy) },
      { key: 'identityHiding', label: gl('identity hiding', 'Identity Hiding'), value: info.security.identityHiding, icon: getIDHIcon(info.security.identityHiding) }
    ];
    props.forEach(p => {
      const row = document.createElement('div');
      row.className = 'security-row';
      row.innerHTML = `
        <span class="security-label">${p.label}</span>
        <span class="security-value security-${p.value}" aria-label="${typeof p.label === 'string' ? p.label : p.key}: ${p.value}">
          <span class="security-icon" aria-hidden="true">${p.icon}</span>
          ${p.value}
        </span>
      `;
      securityEl.appendChild(row);
    });
  }

  if (tokenLegendEl) {
    const allTokens = new Set<string>();
    info.pattern.messages.forEach(m => m.tokens.forEach(t => allTokens.add(t)));
    info.pattern.preMessages.forEach(m => m.tokens.forEach(t => allTokens.add(t)));

    tokenLegendEl.innerHTML = '';
    allTokens.forEach(token => {
      const desc = TOKEN_DESCRIPTIONS[token] || token;
      const div = document.createElement('div');
      div.className = 'token-item';
      div.innerHTML = `<code class="token-code gl" data-term="${escapeHtml(token)}" tabindex="0">${escapeHtml(token)}</code> <span class="token-desc">${escapeHtml(desc)}</span>`;
      tokenLegendEl.appendChild(div);
    });
  }
}

function getAuthIcon(level: string): string {
  switch (level) {
    case 'none': return '⊘';
    case 'one-way': return '→';
    case 'mutual': return '⇄';
    default: return '?';
  }
}

function getFSIcon(level: string): string {
  switch (level) {
    case 'none': return '⊘';
    case 'partial': return '◐';
    case 'full': return '●';
    default: return '?';
  }
}

function getIDHIcon(level: string): string {
  switch (level) {
    case 'none': return '⊘';
    case 'initiator': return '🅸';
    case 'responder': return '🆁';
    case 'both': return '●';
    default: return '?';
  }
}

// ----- Pre-message card (Step 0) -----

function renderPreMessageCard(pattern: HandshakePattern): void {
  const card = document.getElementById('premessage-card');
  const content = document.getElementById('premessage-content');
  if (!card || !content) return;

  if (pattern.preMessages.length === 0) {
    card.hidden = true;
    return;
  }
  card.hidden = false;

  const rows = pattern.preMessages.map(pm => {
    const dir = pm.direction === '->' ? 'Initiator publishes' : 'Responder publishes';
    const tokens = pm.tokens.map(t => `<code class="gl" data-term="${escapeHtml(t)}" tabindex="0">${escapeHtml(t)}</code>`).join(', ');
    return `<div class="premessage-row"><span class="premessage-dir">${dir}</span><span class="premessage-tokens">${tokens}</span></div>`;
  }).join('');

  content.innerHTML = rows + `
    <p class="premessage-note">After Initialize(): protocol name and pre-message public keys are folded into ${gl('h')}.
    Some patterns therefore start with non-zero ${gl('h')} but still-zero ${gl('ck')}.</p>
  `;
}

// ----- Handshake Walkthrough (Panel 2) -----

let _prevHandlersBound = false;

function renderHandshakeWalkthrough(): void {
  if (!handshakeResult) return;
  const prevBtn = document.getElementById('step-prev') as HTMLButtonElement;
  const nextBtn = document.getElementById('step-next') as HTMLButtonElement;
  if (!_prevHandlersBound) {
    prevBtn && (prevBtn.onclick = stepPrev);
    nextBtn && (nextBtn.onclick = stepNext);
    _prevHandlersBound = true;
  }
  currentStep = 0;
  renderCurrentStep();
}

function renderCurrentStep(): void {
  if (!handshakeResult) return;
  const stepInfo = document.getElementById('step-info');
  const counter = document.getElementById('step-counter');
  const prevBtn = document.getElementById('step-prev') as HTMLButtonElement;
  const nextBtn = document.getElementById('step-next') as HTMLButtonElement;
  const predictText = document.getElementById('predict-text');
  if (!stepInfo || !counter) return;

  const totalSteps = handshakeResult.messageLogs.length;
  const msg = handshakeResult.messageLogs[currentStep];
  const info = getPatternInfo(currentPattern);
  const direction = msg.direction === '->' ? 'Initiator → Responder' : 'Responder → Initiator';

  counter.textContent = `Message ${currentStep + 1} of ${totalSteps}`;

  // Predict prompt
  if (predictText) {
    predictText.innerHTML = escapeHtml(getPredictPrompt(info.pattern, currentStep));
  }

  // Message diagram (SVG lane)
  renderMessageDiagram(msg, info.pattern, currentStep);

  // Party state cards
  const iState = currentStep === 0 ? handshakeResult.initiatorInitialState : handshakeResult.messageLogs[currentStep - 1].initiatorStateAfter;
  const rState = currentStep === 0 ? handshakeResult.responderInitialState : handshakeResult.messageLogs[currentStep - 1].responderStateAfter;
  const iStateAfter = msg.initiatorStateAfter;
  const rStateAfter = msg.responderStateAfter;
  renderPartyState('initiator-state', iState, iStateAfter);
  renderPartyState('responder-state', rState, rStateAfter);

  // Step body
  let html = `
    <div class="step-header">
      <span class="step-direction" aria-label="Direction: ${direction}">${direction}</span>
      <span class="step-tokens">Tokens: ${
        msg.tokens.map(t => `<code class="gl" data-term="${escapeHtml(t)}" tabindex="0">${escapeHtml(t)}</code>`).join(' ')
      }</span>
    </div>
    <div class="step-logs" role="list" aria-label="Handshake operations for message ${currentStep + 1}">
  `;

  msg.logs.forEach(log => {
    html += `
      <div class="log-entry${reducedMotion ? '' : ' animate-in'}" role="listitem">
        <div class="log-operation">${escapeHtml(log.operation)}</div>
        <div class="log-description">${escapeHtml(log.description)}</div>
        <div class="log-details">
          ${Object.entries(log.details).map(([k, v]) =>
            `<div class="detail-row">
              <span class="detail-key">${escapeHtml(k)}:</span>
              <span class="detail-value hex-value" title="${escapeHtml(v)}">${escapeHtml(v)}</span>
              <button class="copy-btn" data-copy="${escapeHtml(v)}" aria-label="Copy hex" type="button">📋</button>
            </div>`
          ).join('')}
        </div>
      </div>
    `;
  });

  html += '</div>';

  html += `
    <div class="handshake-hash">
      <span class="hash-label">${gl('h', 'Handshake hash (h)')} — channel binding:</span>
      <span class="hex-value" title="Cumulative handshake hash">${toHex(handshakeResult.handshakeHash)}</span>
    </div>
  `;

  stepInfo.innerHTML = html;

  // Wire copy buttons
  stepInfo.querySelectorAll<HTMLButtonElement>('.copy-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      const v = btn.dataset.copy ?? '';
      navigator.clipboard?.writeText(v).then(() => {
        const orig = btn.textContent;
        btn.textContent = '✓';
        setTimeout(() => { btn.textContent = orig; }, 800);
      });
    });
  });

  if (prevBtn) prevBtn.disabled = currentStep === 0;
  if (nextBtn) nextBtn.disabled = currentStep >= totalSteps - 1;
}

function renderMessageDiagram(msg: MessageLog, pattern: HandshakePattern, idx: number): void {
  const container = document.getElementById('message-diagram');
  if (!container) return;
  const isI2R = msg.direction === '->';
  const fromLabel = isI2R ? '🅰 Initiator' : '🅱 Responder';
  const toLabel = isI2R ? '🅱 Responder' : '🅰 Initiator';
  const tokensHtml = msg.tokens.map(t =>
    `<tspan class="diagram-token">${escapeHtml(t)}</tspan>`
  ).join(' ');
  const arrow = isI2R
    ? '<line x1="120" y1="50" x2="380" y2="50" stroke="currentColor" stroke-width="2" marker-end="url(#arrowR)"/>'
    : '<line x1="380" y1="50" x2="120" y2="50" stroke="currentColor" stroke-width="2" marker-end="url(#arrowL)"/>';
  const animClass = reducedMotion ? '' : 'diagram-animate';
  const tokenLabel = msg.tokens.join(', ');
  const sizeLabel = `${msg.wireBytes.length} B`;

  container.innerHTML = `
    <svg viewBox="0 0 500 110" class="diagram-svg ${animClass}" role="img" aria-label="Message ${idx + 1}: ${fromLabel} sends ${tokenLabel} to ${toLabel}">
      <defs>
        <marker id="arrowR" markerWidth="10" markerHeight="10" refX="9" refY="3" orient="auto">
          <path d="M0,0 L0,6 L9,3 z" fill="currentColor"/>
        </marker>
        <marker id="arrowL" markerWidth="10" markerHeight="10" refX="9" refY="3" orient="auto-start-reverse">
          <path d="M0,0 L0,6 L9,3 z" fill="currentColor"/>
        </marker>
      </defs>
      <text x="60" y="20" text-anchor="middle" class="diagram-party">${fromLabel}</text>
      <text x="440" y="20" text-anchor="middle" class="diagram-party">${toLabel}</text>
      <line x1="60" y1="30" x2="60" y2="100" stroke="currentColor" stroke-opacity="0.3" stroke-dasharray="3,3"/>
      <line x1="440" y1="30" x2="440" y2="100" stroke="currentColor" stroke-opacity="0.3" stroke-dasharray="3,3"/>
      ${arrow}
      <text x="250" y="40" text-anchor="middle" class="diagram-tokens">${tokensHtml}</text>
      <text x="250" y="80" text-anchor="middle" class="diagram-size">${sizeLabel} on the wire</text>
    </svg>
  `;
}

function renderPartyState(elId: string, before: PartyStateSnapshot, after: PartyStateSnapshot): void {
  const el = document.getElementById(elId);
  if (!el) return;
  const fields: Array<[string, string, Uint8Array | null, Uint8Array | null]> = [
    ['s', 'local static', before.s, after.s],
    ['e', 'local ephemeral', before.e, after.e],
    ['rs', 'remote static', before.rs, after.rs],
    ['re', 'remote ephemeral', before.re, after.re],
    ['psk', 'pre-shared key', before.psk, after.psk]
  ];

  const items = fields.map(([key, _desc, beforeVal, afterVal]) => {
    const changed = (beforeVal === null) !== (afterVal === null) ||
      (beforeVal && afterVal && toHex(beforeVal) !== toHex(afterVal));
    const present = afterVal !== null;
    const stateClass = present ? 'state-present' : 'state-absent';
    const changeClass = changed ? 'state-changed' : '';
    const value = afterVal ? toHex(afterVal).slice(0, 16) + '…' : '<em>not held</em>';
    return `
      <div class="state-row ${stateClass} ${changeClass}">
        <span class="state-key ${gl(key) ? '' : ''}"><span class="gl" data-term="${escapeHtml(key)}" tabindex="0">${escapeHtml(key)}</span></span>
        <span class="state-val" title="${afterVal ? toHex(afterVal) : 'null'}">${value}</span>
      </div>
    `;
  }).join('');

  const hChanged = toHex(before.h) !== toHex(after.h);
  const ckChanged = toHex(before.ck) !== toHex(after.ck);

  el.innerHTML = items + `
    <div class="state-row state-h ${hChanged ? 'state-changed' : ''}">
      <span class="state-key"><span class="gl" data-term="h" tabindex="0">h</span></span>
      <span class="state-val" title="${toHex(after.h)}">${toHex(after.h).slice(0, 16)}…</span>
    </div>
    <div class="state-row state-ck ${ckChanged ? 'state-changed' : ''}">
      <span class="state-key"><span class="gl" data-term="ck" tabindex="0">ck</span></span>
      <span class="state-val" title="${toHex(after.ck)}">${toHex(after.ck).slice(0, 16)}…</span>
    </div>
    <div class="state-row state-k">
      <span class="state-key"><span class="gl" data-term="k" tabindex="0">k</span></span>
      <span class="state-val">${after.hasCipherKey ? '✓ installed' : '<em>empty</em>'}</span>
    </div>
  `;
}

// ----- Transport Phase (Panel 3) -----

function resetTransport(): void {
  if (!handshakeResult) return;
  // From initiator's perspective: c1 = send (i→r), c2 = recv (r→i).
  // Reset by deriving fresh cipher states from the same chaining key by re-running split.
  // Easier: just reset n and use the existing cipher states.
  cI2R = handshakeResult.initiatorCiphers[0];
  cR2I = handshakeResult.initiatorCiphers[1];
  // Recreate the responder's view too (we use one CipherState pair only — for demo we encrypt with c1 and decrypt with the *responder's* c1 which is the same key).
  // The responder's [0] is i→r recv key, responder's [1] is r→i send.
  // For simplicity we'll use initiator's pair for both directions:
  //   send i→r: initiator's c1.encrypt   /  decrypt with responder's c1 (== initiator's c1 key) — use responder's
  //   send r→i: responder's c2.encrypt   /  decrypt with initiator's c2
  cI2R.setNonce(0);
  cR2I.setNonce(0);
  handshakeResult.responderCiphers[0].setNonce(0);
  handshakeResult.responderCiphers[1].setNonce(0);
  nI2R = 0;
  nR2I = 0;

  const sendKey = handshakeResult.messageLogs[handshakeResult.messageLogs.length - 1]
    ?.logs.find(l => l.operation === 'Split')?.details.sendKey || '(derived)';
  const recvKey = handshakeResult.messageLogs[handshakeResult.messageLogs.length - 1]
    ?.logs.find(l => l.operation === 'Split')?.details.recvKey || '(derived)';

  const sendEl = document.getElementById('transport-send-key');
  const recvEl = document.getElementById('transport-recv-key');
  if (sendEl) sendEl.textContent = sendKey;
  if (recvEl) recvEl.textContent = recvKey;

  setText('i-to-r-nonce', '0');
  setText('r-to-i-nonce', '0');
  setText('ct-i-to-r', '');
  setText('pt-i-to-r', '');
  setText('ct-r-to-i', '');
  setText('pt-r-to-i', '');
  setText('transport-error', '');
}

function setupTransportLanes(): void {
  const sendI2R = document.getElementById('send-i-to-r');
  const sendR2I = document.getElementById('send-r-to-i');
  const rekeyI = document.getElementById('rekey-i-btn');
  const rekeyR = document.getElementById('rekey-r-btn');
  const resetBtn = document.getElementById('reset-transport-btn');
  const errEl = document.getElementById('transport-error');

  const reportErr = (msg: string) => { if (errEl) errEl.textContent = msg; };
  const clearErr = () => { if (errEl) errEl.textContent = ''; };

  sendI2R?.addEventListener('click', async () => {
    if (!handshakeResult || !cI2R) return;
    clearErr();
    const input = document.getElementById('msg-i-to-r') as HTMLInputElement;
    const msg = input?.value;
    if (!msg) { reportErr('Enter a plaintext to encrypt'); return; }
    try {
      const pt = new TextEncoder().encode(msg);
      const ct = await cI2R.encryptWithAd(EMPTY, pt);
      nI2R++;
      setText('i-to-r-nonce', String(nI2R));
      setText('ct-i-to-r', toHex(ct));
      const dec = await handshakeResult.responderCiphers[0].decryptWithAd(EMPTY, ct);
      setText('pt-i-to-r', new TextDecoder().decode(dec));
      if (nI2R > 100) reportErr(`Note: rekey before n reaches 2⁶⁴. Current i→r: ${nI2R}`);
    } catch (err) {
      reportErr(`i→r error: ${(err as Error).message}`);
    }
  });

  sendR2I?.addEventListener('click', async () => {
    if (!handshakeResult) return;
    clearErr();
    const input = document.getElementById('msg-r-to-i') as HTMLInputElement;
    const msg = input?.value;
    if (!msg) { reportErr('Enter a plaintext to encrypt'); return; }
    try {
      const pt = new TextEncoder().encode(msg);
      // Responder's send cipher is responderCiphers[1] (r→i)
      const ct = await handshakeResult.responderCiphers[1].encryptWithAd(EMPTY, pt);
      nR2I++;
      setText('r-to-i-nonce', String(nR2I));
      setText('ct-r-to-i', toHex(ct));
      // Initiator's recv cipher is cR2I
      const dec = await cR2I!.decryptWithAd(EMPTY, ct);
      setText('pt-r-to-i', new TextDecoder().decode(dec));
      if (nR2I > 100) reportErr(`Note: rekey before n reaches 2⁶⁴. Current r→i: ${nR2I}`);
    } catch (err) {
      reportErr(`r→i error: ${(err as Error).message}`);
    }
  });

  rekeyI?.addEventListener('click', async () => {
    if (!handshakeResult || !cI2R) return;
    clearErr();
    try {
      // Per spec §4.2 / §5.1: REKEY rotates k. The nonce counter is NOT reset.
      await cI2R.rekey();
      await handshakeResult.responderCiphers[0].rekey();
      const newKey = cI2R.k ? toHex(cI2R.k) : '(rotated)';
      const sendEl = document.getElementById('transport-send-key');
      if (sendEl) sendEl.textContent = newKey;
      reportErr('c₁ rekeyed (k rotated; n keeps incrementing per spec).');
    } catch (err) {
      reportErr(`Rekey failed: ${(err as Error).message}`);
    }
  });

  rekeyR?.addEventListener('click', async () => {
    if (!handshakeResult || !cR2I) return;
    clearErr();
    try {
      await cR2I.rekey();
      await handshakeResult.responderCiphers[1].rekey();
      const newKey = cR2I.k ? toHex(cR2I.k) : '(rotated)';
      const recvEl = document.getElementById('transport-recv-key');
      if (recvEl) recvEl.textContent = newKey;
      reportErr('c₂ rekeyed (k rotated; n keeps incrementing per spec).');
    } catch (err) {
      reportErr(`Rekey failed: ${(err as Error).message}`);
    }
  });

  resetBtn?.addEventListener('click', resetTransport);
}

function setText(id: string, text: string): void {
  const el = document.getElementById(id);
  if (el) el.textContent = text;
}

// ----- Break it panel (Panel 4) -----

function setupBreakItPanel(): void {
  document.querySelectorAll<HTMLButtonElement>('.breakit-btn').forEach(btn => {
    btn.addEventListener('click', async () => {
      const attack = btn.dataset.attack;
      const result = document.querySelector<HTMLElement>(`[data-result="${attack}"]`);
      if (!result || !handshakeResult) return;
      result.innerHTML = '<em>Running…</em>';
      const info = getPatternInfo(currentPattern);
      let r;
      try {
        switch (attack) {
          case 'bitflip': {
            // Use a fresh pair from the same handshake
            const tmpHandshake = await runFullHandshake(info.pattern);
            r = await simulateBitFlip(tmpHandshake.initiatorCiphers[0], tmpHandshake.responderCiphers[0], 'Hello, Noise!');
            break;
          }
          case 'rsswap': {
            r = await simulateRSSwap(info.pattern);
            break;
          }
          case 'noncereuse': {
            const tmpHandshake = await runFullHandshake(info.pattern);
            r = await simulateNonceReuse(tmpHandshake.initiatorCiphers[0], tmpHandshake.responderCiphers[0]);
            break;
          }
          case 'pskmismatch': {
            r = await simulatePSKMismatch(info.pattern);
            break;
          }
          case 'replay': {
            r = await simulateReplay(info.pattern);
            break;
          }
          default:
            r = { ok: false, summary: 'Unknown attack' };
        }
      } catch (err) {
        r = { ok: false, summary: 'Attack threw', error: (err as Error).message };
      }
      renderBreakItResult(result, r);
    });
  });
}

function renderBreakItResult(el: HTMLElement, r: any): void {
  const badge = r.ok
    ? '<span class="badge badge-ok">✅ Defense held</span>'
    : '<span class="badge badge-fail">⚠ Attack succeeded</span>';
  let detailsHtml = '';
  if (r.details) {
    detailsHtml = '<div class="breakit-details">' + Object.entries(r.details).map(([k, v]) =>
      `<div class="detail-row"><span class="detail-key">${escapeHtml(k)}:</span><span class="detail-value hex-value">${escapeHtml(String(v))}</span></div>`
    ).join('') + '</div>';
  }
  el.innerHTML = `
    ${badge}
    <p class="breakit-summary">${escapeHtml(r.summary)}</p>
    ${r.error ? `<p class="breakit-error">${escapeHtml(r.error)}</p>` : ''}
    ${detailsHtml}
  `;
}

// ----- Pattern Comparison (Panel 5) -----

function setupComparePicker(): void {
  const row = document.getElementById('compare-chip-row');
  if (!row) return;
  getPatternNames().forEach(name => {
    const btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'chip compare-chip';
    btn.textContent = name;
    btn.setAttribute('aria-pressed', String(comparePatterns.has(name)));
    if (comparePatterns.has(name)) btn.classList.add('active');
    btn.addEventListener('click', () => {
      if (comparePatterns.has(name)) {
        if (comparePatterns.size > 1) comparePatterns.delete(name);
      } else {
        comparePatterns.add(name);
      }
      btn.classList.toggle('active', comparePatterns.has(name));
      btn.setAttribute('aria-pressed', String(comparePatterns.has(name)));
      renderPatternComparison();
    });
    row.appendChild(btn);
  });
}

export function renderPatternComparison(): void {
  const container = document.getElementById('comparison-table');
  if (!container) return;

  const names = getPatternNames().filter(n => comparePatterns.has(n));
  const rows = names.map(name => {
    const info = getPatternInfo(name);
    return `
      <tr>
        <td><strong>${name}</strong></td>
        <td>
          <button class="compare-cell security-${info.security.senderAuth}" data-pattern="${name}" data-prop="senderAuth" aria-label="${info.security.senderAuth}">
            ${getAuthIcon(info.security.senderAuth)} ${info.security.senderAuth}
          </button>
        </td>
        <td>
          <button class="compare-cell security-${info.security.forwardSecrecy}" data-pattern="${name}" data-prop="forwardSecrecy" aria-label="${info.security.forwardSecrecy}">
            ${getFSIcon(info.security.forwardSecrecy)} ${info.security.forwardSecrecy}
          </button>
        </td>
        <td>
          <button class="compare-cell security-${info.security.identityHiding}" data-pattern="${name}" data-prop="identityHiding" aria-label="${info.security.identityHiding}">
            ${getIDHIcon(info.security.identityHiding)} ${info.security.identityHiding}
          </button>
        </td>
        <td>${info.pattern.messages.length} message${info.pattern.messages.length !== 1 ? 's' : ''}</td>
        <td>${escapeHtml(info.realWorld)}</td>
      </tr>
    `;
  });

  container.innerHTML = `
    <table class="comparison-table" role="table" aria-label="Pattern comparison">
      <thead>
        <tr>
          <th scope="col">Pattern</th>
          <th scope="col">Authentication</th>
          <th scope="col">Forward Secrecy</th>
          <th scope="col">Identity Hiding</th>
          <th scope="col">Messages</th>
          <th scope="col">Real-World Use</th>
        </tr>
      </thead>
      <tbody>
        ${rows.join('')}
      </tbody>
    </table>
  `;

  container.querySelectorAll<HTMLButtonElement>('.compare-cell').forEach(btn => {
    btn.addEventListener('click', () => {
      const pattern = btn.dataset.pattern!;
      const prop = btn.dataset.prop!;
      const info = getPatternInfo(pattern);
      const value = (info.security as any)[prop];
      const explainer = document.getElementById('comparison-explainer');
      if (!explainer) return;
      explainer.hidden = false;
      explainer.innerHTML = `
        <h4>${pattern} — ${propLabel(prop)}: <span class="security-${value}">${value}</span></h4>
        <p>${escapeHtml(PROPERTY_EXPLANATIONS[prop]?.[value] ?? 'No explanation available.')}</p>
        <p class="explainer-meta"><strong>Pattern context:</strong> ${escapeHtml(info.description)}</p>
      `;
      explainer.scrollIntoView({ behavior: reducedMotion ? 'auto' : 'smooth', block: 'nearest' });
    });
  });
}

function propLabel(prop: string): string {
  if (prop === 'senderAuth') return 'Authentication';
  if (prop === 'forwardSecrecy') return 'Forward Secrecy';
  if (prop === 'identityHiding') return 'Identity Hiding';
  return prop;
}

// ----- WireGuard Deep Dive (Panel 6) -----

export function renderWireGuardPanel(): void {
  const container = document.getElementById('wireguard-content');
  if (!container) return;

  const ikpsk2 = getPatternInfo('IKpsk2');

  container.innerHTML = `
    <div class="wg-section">
      <h3>IKpsk2 — WireGuard's Handshake Pattern</h3>
      <p>
        WireGuard uses the <strong>Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s</strong> protocol.
        This demo uses AES-256-GCM and SHA-256 for browser compatibility, but the handshake
        pattern and state machine are identical.
      </p>
      <p class="spec-ref">
        Reference: <a href="https://www.wireguard.com/papers/wireguard.pdf" target="_blank" rel="noopener noreferrer">
        WireGuard: Next Generation Kernel Network Tunnel</a> — Jason A. Donenfeld, 2017
      </p>
    </div>

    <div class="wg-section">
      <h3>Pattern Structure</h3>
      <pre class="pattern-display" aria-label="IKpsk2 handshake pattern"><code>${escapeHtml(formatPatternMessages(ikpsk2.pattern))}</code></pre>
    </div>

    <div class="wg-section">
      <h3>Actual WireGuard Packet Layout</h3>
      <p>Each colored block maps to the Noise token(s) that produced it. Hover a block to see its origin.</p>

      <h4 class="packet-title">Message 1 — Initiation (148 bytes)</h4>
      <div class="packet-diagram" aria-label="WireGuard initiation packet">
        ${packetBlock('type', '1', 4, 'Type byte (1) + 3 reserved bytes', 'wg-meta')}
        ${packetBlock('sender_index', '4', 4, 'Random 32-bit sender id', 'wg-meta')}
        ${packetBlock('unencrypted_ephemeral', '32', 32, 'From Noise token e — initiator ephemeral public key', 'wg-e')}
        ${packetBlock('encrypted_static', '48', 48, 'From Noise token s — initiator static pubkey encrypted under k derived from es. 32 bytes key + 16 bytes AEAD tag.', 'wg-s')}
        ${packetBlock('encrypted_timestamp', '28', 28, 'TAI64N timestamp encrypted under k after ss — WireGuard\'s replay protection on top of Noise.', 'wg-payload')}
        ${packetBlock('mac1', '16', 16, 'Keyed MAC over preceding bytes using H(label-mac1 ‖ responder static). DoS mitigation.', 'wg-mac')}
        ${packetBlock('mac2', '16', 16, 'Cookie MAC (zero unless under load). DoS mitigation.', 'wg-mac')}
      </div>

      <h4 class="packet-title">Message 2 — Response (92 bytes)</h4>
      <div class="packet-diagram" aria-label="WireGuard response packet">
        ${packetBlock('type', '1', 4, 'Type byte (2) + 3 reserved bytes', 'wg-meta')}
        ${packetBlock('sender_index', '4', 4, 'Random 32-bit responder id', 'wg-meta')}
        ${packetBlock('receiver_index', '4', 4, 'Echoes initiator\'s sender id', 'wg-meta')}
        ${packetBlock('unencrypted_ephemeral', '32', 32, 'From Noise token e — responder ephemeral public key', 'wg-e')}
        ${packetBlock('encrypted_nothing', '16', 16, 'Empty payload AEAD tag — encrypted under k mixed via ee, se, psk. Confirms PSK + DH chain.', 'wg-payload')}
        ${packetBlock('mac1', '16', 16, 'Keyed MAC over preceding bytes. DoS mitigation.', 'wg-mac')}
        ${packetBlock('mac2', '16', 16, 'Cookie MAC.', 'wg-mac')}
      </div>

      <div class="packet-legend">
        <span class="packet-legend-item"><span class="legend-swatch wg-meta"></span> Packet metadata (not part of Noise)</span>
        <span class="packet-legend-item"><span class="legend-swatch wg-e"></span> From Noise token <code class="gl" data-term="e" tabindex="0">e</code></span>
        <span class="packet-legend-item"><span class="legend-swatch wg-s"></span> From Noise token <code class="gl" data-term="s" tabindex="0">s</code></span>
        <span class="packet-legend-item"><span class="legend-swatch wg-payload"></span> Encrypted payload (uses ${gl('AEAD')})</span>
        <span class="packet-legend-item"><span class="legend-swatch wg-mac"></span> WireGuard MAC (outside Noise)</span>
      </div>
    </div>

    <div class="wg-section">
      <h3>Handshake Message Mapping</h3>
      <div class="wg-messages" role="list" aria-label="WireGuard handshake messages">
        <div class="wg-message" role="listitem">
          <h4>Message 1: Initiator → Responder</h4>
          <p><strong>Tokens:</strong> <code>e, es, s, ss</code></p>
          <p>Initiator generates ephemeral key, performs DH with responder's known static key (es),
          encrypts and sends its own static key, then performs static-static DH (ss).</p>
          <p><em>WireGuard:</em> This is the <code>Initiation</code> message containing the initiator's
          encrypted static key and a timestamp for replay protection.</p>
        </div>
        <div class="wg-message" role="listitem">
          <h4>Message 2: Responder → Initiator</h4>
          <p><strong>Tokens:</strong> <code>e, ee, se, psk</code></p>
          <p>Responder generates ephemeral key, performs ee and se DH operations,
          then mixes the pre-shared key (psk2 modifier — PSK mixed after second message).</p>
          <p><em>WireGuard:</em> This is the <code>Response</code> message. The PSK adds a
          post-quantum defensive layer — even if X25519 is broken, the PSK protects the session.</p>
        </div>
      </div>
    </div>

    <div class="wg-section">
      <h3>Why IKpsk2?</h3>
      <ul>
        <li><strong>I</strong> — Initiator sends static key immediately (fewest round trips)</li>
        <li><strong>K</strong> — Responder's static key is Known to initiator in advance</li>
        <li><strong>psk2</strong> — Pre-shared key mixed after the 2nd message for additional symmetric security</li>
      </ul>
      <p>This makes WireGuard a 1-RTT protocol: the initiator can start sending data immediately
      after the responder's single reply.</p>
    </div>

    <div class="wg-section cross-links">
      <h3>Related</h3>
      <p>See also the <a href="https://github.com/systemslibrarian/crypto-compare" target="_blank" rel="noopener noreferrer">crypto-compare</a>
      Protocols category for comparison with TLS 1.3, WireGuard, and Signal Protocol.</p>
    </div>
  `;
}

function packetBlock(name: string, _label: string, bytes: number, tooltip: string, kls: string): string {
  // Width proportional to byte count (with min width for readability)
  const width = Math.max(40, Math.min(180, bytes * 3.5));
  return `<div class="packet-block ${kls}" style="flex: 0 0 ${width}px" title="${escapeHtml(tooltip)}">
    <div class="packet-name">${escapeHtml(name)}</div>
    <div class="packet-bytes">${bytes} B</div>
  </div>`;
}

// ----- Export transcript (#11) -----

function setupExportTranscript(): void {
  const btn = document.getElementById('export-transcript-btn');
  btn?.addEventListener('click', () => {
    if (!handshakeResult) return;
    const info = getPatternInfo(currentPattern);
    const transcript = {
      protocol: `Noise_${info.pattern.name}_25519_AESGCM_SHA256`,
      pattern: {
        name: info.pattern.name,
        preMessages: info.pattern.preMessages,
        messages: info.pattern.messages
      },
      security: info.security,
      keys: {
        initiatorStatic: serializeKeyPair(handshakeResult.keys.initiatorStatic),
        responderStatic: serializeKeyPair(handshakeResult.keys.responderStatic),
        psk: handshakeResult.keys.psk ? toHex(handshakeResult.keys.psk) : null
      },
      initialState: {
        initiator: serializeState(handshakeResult.initiatorInitialState),
        responder: serializeState(handshakeResult.responderInitialState)
      },
      messages: handshakeResult.messageLogs.map((m, i) => ({
        index: i,
        direction: m.direction,
        tokens: m.tokens,
        wireBytes: toHex(m.wireBytes),
        wireSize: m.wireBytes.length,
        operations: m.logs,
        initiatorStateAfter: serializeState(m.initiatorStateAfter),
        responderStateAfter: serializeState(m.responderStateAfter)
      })),
      finalHandshakeHash: toHex(handshakeResult.handshakeHash),
      transportKeys: {
        c1_i_to_r: handshakeResult.messageLogs.at(-1)?.logs.find(l => l.operation === 'Split')?.details.sendKey,
        c2_r_to_i: handshakeResult.messageLogs.at(-1)?.logs.find(l => l.operation === 'Split')?.details.recvKey
      },
      exportedAt: new Date().toISOString()
    };
    const blob = new Blob([JSON.stringify(transcript, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `noise-${info.pattern.name}-transcript.json`;
    a.click();
    URL.revokeObjectURL(url);
  });
}

function serializeKeyPair(kp: { privateKey: Uint8Array; publicKey: Uint8Array } | null) {
  if (!kp) return null;
  return { privateKey: toHex(kp.privateKey), publicKey: toHex(kp.publicKey) };
}

function serializeState(s: PartyStateSnapshot) {
  return {
    role: s.role,
    s: s.s ? toHex(s.s) : null,
    e: s.e ? toHex(s.e) : null,
    rs: s.rs ? toHex(s.rs) : null,
    re: s.re ? toHex(s.re) : null,
    psk: s.psk ? toHex(s.psk) : null,
    h: toHex(s.h),
    ck: toHex(s.ck),
    hasCipherKey: s.hasCipherKey
  };
}

// ----- Helpers -----

function escapeHtml(text: string): string {
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}
