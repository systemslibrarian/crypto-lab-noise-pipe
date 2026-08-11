/**
 * UI controller for crypto-lab-noise-pipe.
 * Manages six panels: Pattern, Handshake, Transport, Break it, Compare, WireGuard.
 */

import {
  PATTERNS, getPatternNames, getPatternInfo, formatPatternMessages,
  TOKEN_DESCRIPTIONS, GLOSSARY, PROPERTY_EXPLANATIONS, getPredictPrompt,
  getPatternNamesByComplexity, GUIDED_PATH, WHATS_NEW, TOKEN_EFFECTS,
  PatternInfo, type HandshakePattern, type Token
} from './patterns';
import {
  runFullHandshake, type FullHandshakeResult, type StepLog, type MessageLog,
  type PartyStateSnapshot, CipherState,
  simulateBitFlip, simulateNonceReuse, simulateRSSwap, simulatePSKMismatch, simulateReplay,
  simulateForwardSecrecy
} from './noise';
import { toHex, EMPTY, DHLEN } from './crypto';

// ----- State -----

let currentPattern: string = 'NN';
let handshakeResult: FullHandshakeResult | null = null;
let currentStep: number = 0;
let activePanel: string = 'panel-pattern';

// Anatomy-of-a-token onboarding state
let anatomyToken: string = 'ee';
let anatomyRole: 'initiator' | 'responder' = 'initiator';

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
  setupGuidedPath();
  setupAnatomy();
  setupPredictReveal();
  setupPanelTabs();
  setupGlossaryTooltip();
  setupKeyboardShortcuts();
  setupBreakItPanel();
  setupComparePicker();
  setupTransportLanes();
  setupExportTranscript();
  selectPattern('NN');
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

// ----- Anatomy of a token (onboarding) -----

/**
 * For a token + viewer role, return the two operands as {kind, owner}.
 * kind: 'ephemeral' | 'static'; owner: 'mine' | 'theirs'.
 * This mirrors HandshakeState.processWriteToken's es/se role branching exactly.
 */
function anatomyOperands(token: string, role: 'initiator' | 'responder') {
  const isI = role === 'initiator';
  switch (token) {
    case 'ee':
      return [
        { kind: 'ephemeral', owner: 'mine' },
        { kind: 'ephemeral', owner: 'theirs' }
      ];
    case 'ss':
      return [
        { kind: 'static', owner: 'mine' },
        { kind: 'static', owner: 'theirs' }
      ];
    case 'es':
      // initiator: DH(local ephemeral, remote static); responder: DH(local static, remote ephemeral)
      return isI
        ? [{ kind: 'ephemeral', owner: 'mine' }, { kind: 'static', owner: 'theirs' }]
        : [{ kind: 'static', owner: 'mine' }, { kind: 'ephemeral', owner: 'theirs' }];
    case 'se':
      // initiator: DH(local static, remote ephemeral); responder: DH(local ephemeral, remote static)
      return isI
        ? [{ kind: 'static', owner: 'mine' }, { kind: 'ephemeral', owner: 'theirs' }]
        : [{ kind: 'ephemeral', owner: 'mine' }, { kind: 'static', owner: 'theirs' }];
    default:
      return [{ kind: 'ephemeral', owner: 'mine' }, { kind: 'ephemeral', owner: 'theirs' }];
  }
}

function operandLabel(op: { kind: string; owner: string }): string {
  const who = op.owner === 'mine' ? 'my' : 'their';
  return `${who} ${op.kind}`;
}

function setupAnatomy(): void {
  const tokenBtns = document.querySelectorAll<HTMLButtonElement>('.anatomy-token-btn');
  const roleBtns = document.querySelectorAll<HTMLButtonElement>('.role-btn');

  tokenBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      anatomyToken = btn.dataset.token || 'ee';
      tokenBtns.forEach(b => b.setAttribute('aria-pressed', String(b === btn)));
      renderAnatomy(true);
    });
  });

  roleBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      anatomyRole = (btn.dataset.role as 'initiator' | 'responder') || 'initiator';
      roleBtns.forEach(b => {
        const on = b === btn;
        b.classList.toggle('active', on);
        b.setAttribute('aria-checked', String(on));
      });
      renderAnatomy(true);
    });
  });

  renderAnatomy(false);
}

function renderAnatomy(animate: boolean): void {
  const keyA = document.getElementById('anatomy-key-a');
  const keyB = document.getElementById('anatomy-key-b');
  const explain = document.getElementById('anatomy-explain');
  const stage = document.getElementById('anatomy-mixer');
  if (!keyA || !keyB || !explain) return;

  const [a, b] = anatomyOperands(anatomyToken, anatomyRole);

  const paint = (el: HTMLElement, op: { kind: string; owner: string }) => {
    const nameEl = el.querySelector('.anatomy-key-name');
    if (nameEl) nameEl.textContent = operandLabel(op);
    el.classList.toggle('key-ephemeral', op.kind === 'ephemeral');
    el.classList.toggle('key-static', op.kind === 'static');
    el.classList.toggle('key-mine', op.owner === 'mine');
    el.classList.toggle('key-theirs', op.owner === 'theirs');
  };
  paint(keyA, a);
  paint(keyB, b);

  // Re-trigger the slide animation unless reduced motion.
  if (animate && !reducedMotion && stage) {
    keyA.classList.remove('slide-in');
    keyB.classList.remove('slide-in');
    // Force reflow so the animation restarts.
    void keyA.offsetWidth;
    keyA.classList.add('slide-in');
    keyB.classList.add('slide-in');
  }

  const fsNote = anatomyToken === 'ee'
    ? ' Because both keys are ephemeral, this DH is the source of forward secrecy — its private halves vanish when the session ends.'
    : anatomyToken === 'ss'
    ? ' Both keys are long-lived statics, so this DH authenticates but provides no forward secrecy on its own.'
    : ' One key is ephemeral and one is static, so this DH both authenticates a party and contributes fresh, forward-secret material.';

  explain.textContent =
    `Token “${anatomyToken}”, viewed as the ${anatomyRole}: multiply ${operandLabel(a)} × ${operandLabel(b)}. ` +
    `The X25519 result is folded into the chaining key (ck), growing the shared secret.` + fsNote;
}

// ----- Predict-before-step reveal (active retrieval) -----

function correctPredictChoice(): 'h' | 'hk' | 'none' {
  if (!handshakeResult) return 'h';
  const info = getPatternInfo(currentPattern);
  const mp = info.pattern.messages[currentStep];
  if (!mp) return 'h';
  const touchesSchedule = mp.tokens.some(t => t === 'ee' || t === 'es' || t === 'se' || t === 'ss' || t === 'psk');
  return touchesSchedule ? 'hk' : 'h';
}

let _predictBound = false;
function setupPredictReveal(): void {
  if (_predictBound) return;
  _predictBound = true;
  const answerEl = document.getElementById('predict-answer');
  document.querySelectorAll<HTMLButtonElement>('.predict-choice').forEach(btn => {
    btn.addEventListener('click', () => {
      const picked = btn.dataset.choice as 'h' | 'hk' | 'none';
      const correct = correctPredictChoice();
      const right = picked === correct;
      document.querySelectorAll<HTMLButtonElement>('.predict-choice').forEach(b => {
        b.classList.toggle('choice-correct', b.dataset.choice === correct);
        b.classList.toggle('choice-wrong', b === btn && !right);
      });
      if (answerEl) {
        answerEl.hidden = false;
        const explain = correct === 'hk'
          ? 'This message fires a DH (or PSK) token, so h binds the new bytes AND ck→k absorb fresh key material.'
          : 'This message only sends/receives public keys — h hashes them in, but no DH fires, so ck and k stay put.';
        answerEl.innerHTML = (right ? '✅ Correct. ' : '❌ Not quite. ') +
          `The answer is <strong>${escapeHtml(labelForChoice(correct))}</strong>. ` + escapeHtml(explain);
        answerEl.classList.toggle('answer-right', right);
        answerEl.classList.toggle('answer-wrong', !right);
      }
    });
  });
}

function labelForChoice(c: 'h' | 'hk' | 'none'): string {
  if (c === 'h') return 'only h (transcript)';
  if (c === 'hk') return 'h and ck / k';
  return 'nothing';
}

function resetPredictReveal(): void {
  const answerEl = document.getElementById('predict-answer');
  if (answerEl) { answerEl.hidden = true; answerEl.textContent = ''; }
  document.querySelectorAll<HTMLButtonElement>('.predict-choice').forEach(b => {
    b.classList.remove('choice-correct', 'choice-wrong');
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

  // Chips laid out simplest → most complex so the grid itself reads as a ramp.
  getPatternNamesByComplexity().forEach(name => {
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

// ----- Guided path (simplest → most complex milestones) -----

function setupGuidedPath(): void {
  const row = document.getElementById('guided-path-steps');
  if (!row) return;
  GUIDED_PATH.forEach((name, i) => {
    if (i > 0) {
      const sep = document.createElement('span');
      sep.className = 'guided-path-arrow';
      sep.setAttribute('aria-hidden', 'true');
      sep.textContent = '→';
      row.appendChild(sep);
    }
    const btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'guided-path-step';
    btn.dataset.pattern = name;
    btn.setAttribute('aria-label', `Guided step ${i + 1}: ${name} pattern`);
    btn.innerHTML = `<span class="guided-path-num" aria-hidden="true">${i + 1}</span>${escapeHtml(name)}`;
    btn.addEventListener('click', () => selectPattern(name));
    row.appendChild(btn);
  });
}

function updateGuidedPathHighlight(name: string): void {
  document.querySelectorAll<HTMLButtonElement>('.guided-path-step').forEach(b => {
    const active = b.dataset.pattern === name;
    b.classList.toggle('active', active);
    if (active) b.setAttribute('aria-current', 'step');
    else b.removeAttribute('aria-current');
  });
}

function updateWhatsNewBanner(name: string): void {
  const banner = document.getElementById('whats-new-banner');
  const text = document.getElementById('whats-new-text');
  if (!banner || !text) return;
  const entry = WHATS_NEW[name];
  if (entry) {
    text.textContent = entry.text;
    banner.hidden = false;
  } else {
    banner.hidden = true;
  }
}

/**
 * Monotonic id for "which pattern selection is the current one".
 *
 * `selectPattern()` sets `currentPattern` synchronously and then awaits an
 * async handshake. Two selections started in the same tick always settle in
 * start order when they cost the same, but a slower pattern started FIRST
 * settles LAST — measured at 300 of 300 for XX-then-NN, XK-then-NN and
 * IKpsk2-then-NN — and its result then overwrites the newer one. The page would
 * show the new pattern's name above the old pattern's handshake, transport keys
 * and walkthrough. (At a realistic 16 ms gap between clicks it was 0 of 200, so
 * this is latent rather than everyday — but the window widens with device speed,
 * and nothing in the code bounded it.)
 *
 * Every async continuation below re-checks its generation before touching
 * global state. Break-it attacks share the counter, so a verdict computed
 * against one pattern can never be painted under another.
 */
let selectionGeneration = 0;

async function selectPattern(name: string): Promise<void> {
  const myGeneration = ++selectionGeneration;
  currentPattern = name;
  currentStep = 0;

  document.querySelectorAll('.pattern-chip').forEach(chip => {
    const isSelected = chip.textContent === name;
    chip.classList.toggle('active', isSelected);
    chip.setAttribute('aria-checked', String(isSelected));
  });

  updateGuidedPathHighlight(name);
  updateWhatsNewBanner(name);
  clearBreakItResults();

  const info = getPatternInfo(name);
  renderPatternInfo(info);

  const statusEl = document.getElementById('handshake-status');
  if (statusEl) {
    statusEl.textContent = 'Running handshake…';
    statusEl.setAttribute('aria-live', 'polite');
  }

  try {
    const result = await runFullHandshake(info.pattern);
    // A newer selection has already been made — discard this one entirely
    // rather than repainting the page with a handshake nobody asked for.
    if (myGeneration !== selectionGeneration) return;
    handshakeResult = result;
    if (statusEl) statusEl.textContent = 'Handshake complete';
    renderPreMessageCard(info.pattern);
    renderHandshakeWalkthrough();
    bindTransportToNewSession();
  } catch (err) {
    if (myGeneration !== selectionGeneration) return;
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
  resetPredictReveal();

  // Message diagram (SVG lane)
  renderMessageDiagram(msg, info.pattern, currentStep);

  // Segmented on-the-wire byte blocks for this message
  renderWireBlocks(msg);

  // Party state cards
  const iState = currentStep === 0 ? handshakeResult.initiatorInitialState : handshakeResult.messageLogs[currentStep - 1].initiatorStateAfter;
  const rState = currentStep === 0 ? handshakeResult.responderInitialState : handshakeResult.messageLogs[currentStep - 1].responderStateAfter;
  const iStateAfter = msg.initiatorStateAfter;
  const rStateAfter = msg.responderStateAfter;
  renderPartyState('initiator-state', iState, iStateAfter);
  renderPartyState('responder-state', rState, rStateAfter);

  // Step body
  const tokenChips = msg.tokens.map(t => {
    const eff = TOKEN_EFFECTS[t];
    const badges = eff
      ? `${eff.transcript ? '<span class="tok-effect tok-effect-transcript">binds to transcript</span>' : ''}` +
        `${eff.keySchedule ? '<span class="tok-effect tok-effect-schedule">adds to key schedule</span>' : ''}`
      : '';
    return `<span class="token-effect-chip">` +
      `<code class="gl" data-term="${escapeHtml(t)}" tabindex="0">${escapeHtml(t)}</code>${badges}</span>`;
  }).join('');

  let html = `
    <div class="step-header">
      <span class="step-direction" aria-label="Direction: ${direction}">${direction}</span>
    </div>
    <div class="step-token-effects" aria-label="Tokens in this message and what each one touches">${tokenChips}</div>
    <div class="step-logs" role="list" aria-label="Handshake operations for message ${currentStep + 1}">
  `;

  msg.logs.forEach(log => {
    // If this log carries DH operands, render a "which two keys?" visual first.
    const opA = log.details.operandA;
    const opB = log.details.operandB;
    const dhVisual = (opA && opB)
      ? renderDHVisual(opA, opB, log.details.dhOutput)
      : '';

    const detailRows = Object.entries(log.details)
      .filter(([k]) => k !== 'operandA' && k !== 'operandB')
      .map(([k, v]) =>
        `<div class="detail-row">
          <span class="detail-key">${escapeHtml(k)}:</span>
          <span class="detail-value hex-value" title="${escapeHtml(v)}">${escapeHtml(v)}</span>
          <button class="copy-btn" data-copy="${escapeHtml(v)}" aria-label="Copy hex" type="button">📋</button>
        </div>`
      ).join('');

    html += `
      <div class="log-entry${reducedMotion ? '' : ' animate-in'}" role="listitem">
        <div class="log-operation">${escapeHtml(log.operation)}</div>
        <div class="log-description">${escapeHtml(log.description)}</div>
        ${dhVisual}
        <div class="log-details">
          ${detailRows}
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

/**
 * Render the "which two keys were multiplied" visual for a DH token log.
 * operandA/operandB arrive as "label|hex" strings from the handshake engine.
 */
function renderDHVisual(opA: string, opB: string, output?: string): string {
  const [labelA, hexA = ''] = opA.split('|');
  const [labelB, hexB = ''] = opB.split('|');
  const chip = (label: string, hex: string) => {
    const mine = label.startsWith('my');
    const isEph = label.includes('ephemeral');
    const kindClass = isEph ? 'dhk-ephemeral' : 'dhk-static';
    const ownerClass = mine ? 'dhk-mine' : 'dhk-theirs';
    return `<span class="dh-key-chip ${kindClass} ${ownerClass}">
      <span class="dh-key-icon" aria-hidden="true">🔑</span>
      <span class="dh-key-label">${escapeHtml(label)}</span>
      <span class="dh-key-hex" title="${escapeHtml(hex)}">${escapeHtml(hex.slice(0, 12))}…</span>
    </span>`;
  };
  const outStr = output ? `${output.slice(0, 12)}…` : '';
  return `
    <div class="dh-visual" aria-label="Diffie-Hellman: ${escapeHtml(labelA)} times ${escapeHtml(labelB)}">
      ${chip(labelA, hexA)}
      <span class="dh-op" aria-hidden="true">×</span>
      ${chip(labelB, hexB)}
      <span class="dh-arrow" aria-hidden="true">→</span>
      <span class="dh-out" title="${escapeHtml(output ?? '')}">shared secret ${escapeHtml(outStr)}</span>
    </div>
  `;
}

/**
 * Segmented byte-block view of one handshake message, mirroring the WireGuard
 * packet diagram but for any pattern. Each block maps to the token that
 * produced it, and the static block is labeled ENCRYPTED vs PLAINTEXT so the
 * identity-hiding behaviour of `s` is visible, not just asserted.
 */
function renderWireBlocks(msg: MessageLog): void {
  const container = document.getElementById('wire-blocks');
  if (!container) return;

  const total = msg.wireBytes.length;
  const eCount = msg.tokens.filter(t => t === 'e').length;
  const hasStatic = msg.tokens.includes('s');

  type Seg = { name: string; bytes: number; kind: string; note: string };
  const segs: Seg[] = [];

  // Each `e` token puts a 32-byte ephemeral public key on the wire, in the clear.
  for (const t of msg.tokens) {
    if (t === 'e') {
      segs.push({ name: 'ephemeral pubkey', bytes: DHLEN, kind: 'blk-e',
        note: 'From token e — sent unencrypted (public keys are not secret).' });
    }
  }

  // The static block, if present, is 32 bytes plaintext or 48 bytes (32 + 16-byte
  // AEAD tag) once a k exists. Solve for it from the actual wire length so the
  // ENCRYPTED/PLAINTEXT label reflects the real bytes, never a guess.
  //
  // remainder = static block + trailing (empty) payload block. A static is only
  // encrypted when a k already exists — and if a k exists the trailing payload
  // carries a 16-byte tag too. So the possible remainders are:
  //   DHLEN         → static plaintext (32), payload plaintext (0)  [no k]
  //   DHLEN+16      → static plaintext (32), payload tag (16)       [k appeared this msg, after s]
  //   DHLEN+16+16   → static encrypted (48), payload tag (16)       [k existed before s]
  let staticEncrypted = false;
  if (hasStatic) {
    const remainder = total - eCount * DHLEN;
    staticEncrypted = remainder >= DHLEN + 32;

    segs.push(staticEncrypted
      ? { name: 'static pubkey', bytes: DHLEN, kind: 'blk-s-enc',
          note: 'From token s — ENCRYPTED under the current k (identity hidden from observers).' }
      : { name: 'static pubkey', bytes: DHLEN, kind: 'blk-s-plain',
          note: 'From token s — sent PLAINTEXT (no k derived yet, so the identity is visible on the wire).' });
    if (staticEncrypted) {
      segs.push({ name: 'AEAD tag', bytes: 16, kind: 'blk-tag',
        note: '16-byte AES-GCM tag authenticating the encrypted static key.' });
    }
  }

  // Trailing payload block (empty payload here). If a k exists it is a bare
  // 16-byte AEAD tag; otherwise there are zero payload bytes.
  const usedByStatic = hasStatic ? (staticEncrypted ? DHLEN + 16 : DHLEN) : 0;
  const payloadBytes = total - eCount * DHLEN - usedByStatic;
  if (payloadBytes >= 16) {
    segs.push({ name: 'payload tag', bytes: 16, kind: 'blk-tag',
      note: 'Empty payload, but a 16-byte AEAD tag is present because a k now exists.' });
  }

  container.innerHTML = segs.map(s => {
    const width = Math.max(56, Math.min(180, s.bytes * 3.2));
    const enc = s.kind === 'blk-s-enc' ? '🔒 ' : (s.kind === 'blk-s-plain' ? '🔓 ' : '');
    return `<div class="wire-block ${s.kind}" style="flex:0 0 ${width}px" title="${escapeHtml(s.note)}">
      <span class="wire-block-name">${enc}${escapeHtml(s.name)}</span>
      <span class="wire-block-bytes">${s.bytes} B</span>
    </div>`;
  }).join('') + `<p class="wire-blocks-note">${total} bytes total. ${
    hasStatic
      ? (staticEncrypted
          ? 'The static identity key is <strong>encrypted</strong> here — a k already exists, so observers cannot see who is connecting.'
          : 'The static identity key rides <strong>in the clear</strong> here — no k has been derived yet, so an observer can read it.')
      : 'No static identity keys are sent in this message.'
  }</p>`;
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

  // Two clearly-captioned tracks: transcript binding (h) vs key derivation (ck→k).
  el.innerHTML = `
    <div class="state-track state-track-keys">
      <p class="state-track-caption">Keys this party holds</p>
      ${items}
    </div>
    <div class="state-track state-track-transcript">
      <p class="state-track-caption">
        <span class="track-dot track-dot-transcript" aria-hidden="true"></span>
        Transcript — binds every handshake byte into one fingerprint
      </p>
      <div class="state-row state-h ${hChanged ? 'state-changed' : ''}">
        <span class="state-key"><span class="gl" data-term="h" tabindex="0">h</span></span>
        <span class="state-val" title="${toHex(after.h)}">${toHex(after.h).slice(0, 16)}…</span>
      </div>
    </div>
    <div class="state-track state-track-schedule">
      <p class="state-track-caption">
        <span class="track-dot track-dot-schedule" aria-hidden="true"></span>
        Key schedule — grows with each DH, becomes the session keys
      </p>
      <div class="state-row state-ck ${ckChanged ? 'state-changed' : ''}">
        <span class="state-key"><span class="gl" data-term="ck" tabindex="0">ck</span></span>
        <span class="state-val" title="${toHex(after.ck)}">${toHex(after.ck).slice(0, 16)}…</span>
      </div>
      <div class="state-row state-k">
        <span class="state-key"><span class="gl" data-term="k" tabindex="0">k</span></span>
        <span class="state-val">${after.hasCipherKey ? '✓ installed' : '<em>empty</em>'}</span>
      </div>
    </div>
  `;
}

// ----- Transport Phase (Panel 3) -----

/**
 * Bind the transport panel to the cipher states of a session that has JUST been
 * established, and show its counters at zero.
 *
 * Only ever call this immediately after `runFullHandshake()`. Zeroing a counter
 * is safe here and ONLY here, because the keys are new — a fresh handshake
 * means fresh ephemerals, so (key, nonce) pairs cannot repeat.
 *
 * This function used to be wired to the "Reset" button as well, which was a
 * catastrophic bug in a lab that teaches exactly this failure. Pressing Reset
 * called `setNonce(0)` on the SAME CipherState objects — same key — so
 * send → Reset → send encrypted different plaintext under an identical
 * (key, nonce) pair. With AES-GCM that leaks the XOR of the two plaintexts and
 * destroys the authenticator; it is the precise condition the nonce-reuse panel
 * three sections up warns is fatal. Reset now starts a genuinely new session,
 * so the counter returns to zero because the KEYS changed, not in spite of them.
 */
function bindTransportToNewSession(): void {
  if (!handshakeResult) return;
  // From initiator's perspective: c1 = send (i→r), c2 = recv (r→i).
  cI2R = handshakeResult.initiatorCiphers[0];
  cR2I = handshakeResult.initiatorCiphers[1];
  // The responder's [0] is the i→r recv key; its [1] is the r→i send key.
  // These are freshly split states, so their counters are already zero; setting
  // them explicitly keeps the panel honest if a caller ever rebinds mid-session.
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

  // "Decrypted by 🅱" is a claim about one specific run: this ciphertext, under
  // this key, round-tripped to this plaintext. Leaving it on screen after the
  // learner edits the plaintext — or after a rekey changes the key it was
  // produced under — turns it into a claim about inputs that no longer exist.
  // Retire the readouts the moment either input changes.
  const clearLane = (dir: 'i-to-r' | 'r-to-i') => {
    setText(`ct-${dir}`, '');
    setText(`pt-${dir}`, '');
  };
  const bindStaleClear = (inputId: string, dir: 'i-to-r' | 'r-to-i') => {
    const input = document.getElementById(inputId) as HTMLInputElement | null;
    input?.addEventListener('input', () => clearLane(dir));
  };
  bindStaleClear('msg-i-to-r', 'i-to-r');
  bindStaleClear('msg-r-to-i', 'r-to-i');

  // A lane's controls are locked while that lane has an operation in flight.
  // With CipherState now serializing its own nonce reservation, a double-click
  // can no longer reuse a (key, nonce) pair — but leaving the button live would
  // still let a second send land before the first had painted its ciphertext,
  // showing the learner a counter and a record that came from different clicks.
  const laneBusy: Record<'i-to-r' | 'r-to-i', boolean> = { 'i-to-r': false, 'r-to-i': false };
  const setLaneEnabled = (dir: 'i-to-r' | 'r-to-i', enabled: boolean) => {
    laneBusy[dir] = !enabled;
    const send = document.getElementById(dir === 'i-to-r' ? 'send-i-to-r' : 'send-r-to-i') as HTMLButtonElement | null;
    const rekey = document.getElementById(dir === 'i-to-r' ? 'rekey-i-btn' : 'rekey-r-btn') as HTMLButtonElement | null;
    if (send) send.disabled = !enabled;
    if (rekey) rekey.disabled = !enabled;
  };

  sendI2R?.addEventListener('click', async () => {
    if (!handshakeResult || !cI2R || laneBusy['i-to-r']) return;
    clearErr();
    const input = document.getElementById('msg-i-to-r') as HTMLInputElement;
    const msg = input?.value;
    if (!msg) { reportErr('Enter a plaintext to encrypt'); return; }
    setLaneEnabled('i-to-r', false);
    try {
      const pt = new TextEncoder().encode(msg);
      const ct = await cI2R.encryptWithAd(EMPTY, pt);
      // The counter shown is the sender's REAL CipherState.n, not a tally kept
      // alongside it. A parallel variable is a second source of truth that can
      // disagree with the nonce the record was actually sealed under.
      nI2R = cI2R.n;
      setText('i-to-r-nonce', String(nI2R));
      setText('ct-i-to-r', toHex(ct));
      const dec = await handshakeResult.responderCiphers[0].decryptWithAd(EMPTY, ct);
      setText('pt-i-to-r', new TextDecoder().decode(dec));
      if (nI2R > 100) reportErr(`Note: rekey before n reaches 2⁶⁴. Current i→r: ${nI2R}`);
    } catch (err) {
      reportErr(`i→r error: ${(err as Error).message}`);
    } finally {
      setLaneEnabled('i-to-r', true);
    }
  });

  sendR2I?.addEventListener('click', async () => {
    if (!handshakeResult || laneBusy['r-to-i']) return;
    clearErr();
    const input = document.getElementById('msg-r-to-i') as HTMLInputElement;
    const msg = input?.value;
    if (!msg) { reportErr('Enter a plaintext to encrypt'); return; }
    setLaneEnabled('r-to-i', false);
    try {
      const pt = new TextEncoder().encode(msg);
      // Responder's send cipher is responderCiphers[1] (r→i)
      const sender = handshakeResult.responderCiphers[1];
      const ct = await sender.encryptWithAd(EMPTY, pt);
      nR2I = sender.n;
      setText('r-to-i-nonce', String(nR2I));
      setText('ct-r-to-i', toHex(ct));
      // Initiator's recv cipher is cR2I
      const dec = await cR2I!.decryptWithAd(EMPTY, ct);
      setText('pt-r-to-i', new TextDecoder().decode(dec));
      if (nR2I > 100) reportErr(`Note: rekey before n reaches 2⁶⁴. Current r→i: ${nR2I}`);
    } catch (err) {
      reportErr(`r→i error: ${(err as Error).message}`);
    } finally {
      setLaneEnabled('r-to-i', true);
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
      clearLane('i-to-r');
      reportErr('c₁ rekeyed (k rotated; n keeps incrementing per spec). The i→r readout was cleared — it was produced under the old k.');
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
      clearLane('r-to-i');
      reportErr('c₂ rekeyed (k rotated; n keeps incrementing per spec). The r→i readout was cleared — it was produced under the old k.');
    } catch (err) {
      reportErr(`Rekey failed: ${(err as Error).message}`);
    }
  });

  // A new session, NOT a rewind: re-running the handshake mints fresh ephemeral
  // keys, so the counters legitimately start again at zero. Rewinding the nonce
  // under the existing key would reuse a (key, nonce) pair - see
  // bindTransportToNewSession() for why that was fatal here.
  resetBtn?.addEventListener('click', () => { void selectPattern(currentPattern); });
}

function setText(id: string, text: string): void {
  const el = document.getElementById(id);
  if (el) el.textContent = text;
}

// ----- Break it panel (Panel 4) -----

/**
 * Every Break-it verdict is a verdict about ONE pattern — "IK accepted the
 * forged static key", "XX rejected it". Switching patterns leaves those badges
 * describing a run that was never made against the pattern now on screen, which
 * is the exact inversion the four-badge scheme exists to prevent. Retire them.
 */
function clearBreakItResults(): void {
  document.querySelectorAll<HTMLElement>('.breakit-result').forEach(el => {
    el.innerHTML = '';
  });
}

function setupBreakItPanel(): void {
  document.querySelectorAll<HTMLButtonElement>('.breakit-btn').forEach(btn => {
    btn.addEventListener('click', async () => {
      const attack = btn.dataset.attack;
      const result = document.querySelector<HTMLElement>(`[data-result="${attack}"]`);
      if (!result || !handshakeResult) return;
      // The verdict about to be computed belongs to THIS pattern. Switching
      // patterns calls clearBreakItResults(), but an attack already in flight
      // used to finish afterwards and repaint the cleared slot with a verdict
      // about a pattern no longer on screen. Measured window: 0–8.6 ms per
      // attack across the shipped patterns, so a human is unlikely to hit it —
      // but nothing prevented it, and "IK accepted the forged responder static
      // key" sitting under the XX heading is precisely the inversion this
      // panel's four-badge scheme exists to stop.
      const myGeneration = selectionGeneration;
      const myPattern = currentPattern;
      btn.disabled = true;
      result.innerHTML = '<em>Running…</em>';
      const info = getPatternInfo(myPattern);
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
          case 'forwardsecrecy': {
            r = await simulateForwardSecrecy(info.pattern);
            break;
          }
          default:
            r = { outcome: 'error' as const, ok: false, summary: `Unknown attack "${attack}" — nothing was run.` };
        }
      } catch (err) {
        r = {
          outcome: 'error' as const,
          ok: false,
          summary: 'The simulation threw before it could reach a verdict — this says nothing about the pattern’s security.',
          error: (err as Error).message,
        };
      } finally {
        btn.disabled = false;
      }
      if (myGeneration !== selectionGeneration || myPattern !== currentPattern) return;
      renderBreakItResult(result, r);
    });
  });
}

// Four distinct outcomes, four distinct badges. Collapsing "not applicable" or
// "the simulation broke" into "attack succeeded" would tell the learner that a
// pattern fell to an attack that was never even run against it — which inverts
// the whole point of a panel comparing which patterns resist what.
const OUTCOME_BADGE: Record<string, string> = {
  held: '<span class="badge badge-ok">✅ Attack failed — defense held</span>',
  succeeded: '<span class="badge badge-fail">⚠ Attack succeeded</span>',
  'n/a': '<span class="badge badge-na">— Not applicable to this pattern</span>',
  error: '<span class="badge badge-error">✗ Could not run — no verdict</span>',
};

function renderBreakItResult(el: HTMLElement, r: any): void {
  // Fall back to 'error', never to a security verdict, if outcome is missing.
  const badge = OUTCOME_BADGE[r?.outcome as string] ?? OUTCOME_BADGE.error;
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
      const specNote = (info.specNotes as Record<string, string | undefined> | undefined)?.[prop];
      explainer.innerHTML = `
        <h4>${pattern} — ${propLabel(prop)}: <span class="security-${value}">${value}</span></h4>
        <p>${escapeHtml(PROPERTY_EXPLANATIONS[prop]?.[value] ?? 'No explanation available.')}</p>
        ${specNote ? `<p class="explainer-meta"><strong>In ${escapeHtml(pattern)} specifically:</strong> ${escapeHtml(specNote)}</p>` : ''}
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
