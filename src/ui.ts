/**
 * UI controller for crypto-lab-noise-pipe.
 * Manages all five panels and user interactions.
 */

import {
  PATTERNS, getPatternNames, getPatternInfo, formatPatternMessages,
  TOKEN_DESCRIPTIONS, PatternInfo, type HandshakePattern, type Token
} from './patterns';
import { runFullHandshake, type FullHandshakeResult, type StepLog, CipherState } from './noise';
import { toHex, generateKeyPair, EMPTY } from './crypto';

// ----- State -----

let currentPattern: string = 'XX';
let handshakeResult: FullHandshakeResult | null = null;
let currentStep: number = 0;
let transportSendCipher: CipherState | null = null;
let transportRecvCipher: CipherState | null = null;
let transportNonce: number = 0;
let activePanel: string = 'panel-pattern';

const reducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

// ----- Initialization -----

export function initUI(): void {
  setupPatternSelector();
  setupPanelTabs();
  selectPattern('XX');
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

  // Update chip selection
  document.querySelectorAll('.pattern-chip').forEach(chip => {
    const isSelected = chip.textContent === name;
    chip.classList.toggle('active', isSelected);
    chip.setAttribute('aria-checked', String(isSelected));
  });

  // Update pattern info display
  const info = getPatternInfo(name);
  renderPatternInfo(info);

  // Run handshake
  const statusEl = document.getElementById('handshake-status');
  if (statusEl) {
    statusEl.textContent = 'Running handshake…';
    statusEl.setAttribute('aria-live', 'polite');
  }

  try {
    handshakeResult = await runFullHandshake(info.pattern);
    if (statusEl) statusEl.textContent = 'Handshake complete';
    renderHandshakeWalkthrough();
    renderTransportPhase();
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

  if (nameEl) nameEl.textContent = `Noise_${info.pattern.name}_25519_AESGCM_SHA256`;
  if (descEl) descEl.textContent = info.description;
  if (messagesEl) {
    messagesEl.textContent = formatPatternMessages(info.pattern);
  }
  if (realWorldEl) realWorldEl.textContent = info.realWorld;

  // Security properties
  if (securityEl) {
    securityEl.innerHTML = '';
    const props = [
      { label: 'Authentication', value: info.security.senderAuth, icon: getAuthIcon(info.security.senderAuth) },
      { label: 'Forward Secrecy', value: info.security.forwardSecrecy, icon: getFSIcon(info.security.forwardSecrecy) },
      { label: 'Identity Hiding', value: info.security.identityHiding, icon: getIDHIcon(info.security.identityHiding) }
    ];
    props.forEach(p => {
      const row = document.createElement('div');
      row.className = 'security-row';
      row.innerHTML = `
        <span class="security-label">${p.label}</span>
        <span class="security-value security-${p.value}" aria-label="${p.label}: ${p.value}">
          <span class="security-icon" aria-hidden="true">${p.icon}</span>
          ${p.value}
        </span>
      `;
      securityEl.appendChild(row);
    });
  }

  // Token legend
  if (tokenLegendEl) {
    const allTokens = new Set<string>();
    info.pattern.messages.forEach(m => m.tokens.forEach(t => allTokens.add(t)));
    info.pattern.preMessages.forEach(m => m.tokens.forEach(t => allTokens.add(t)));

    tokenLegendEl.innerHTML = '';
    allTokens.forEach(token => {
      const desc = TOKEN_DESCRIPTIONS[token] || token;
      const div = document.createElement('div');
      div.className = 'token-item';
      div.innerHTML = `<code class="token-code">${escapeHtml(token)}</code> <span class="token-desc">${escapeHtml(desc)}</span>`;
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

// ----- Handshake Walkthrough (Panel 2) -----

function renderHandshakeWalkthrough(): void {
  if (!handshakeResult) return;
  const container = document.getElementById('walkthrough-steps');
  const stepInfo = document.getElementById('step-info');
  const prevBtn = document.getElementById('step-prev') as HTMLButtonElement;
  const nextBtn = document.getElementById('step-next') as HTMLButtonElement;
  const counter = document.getElementById('step-counter');

  if (!container || !stepInfo) return;

  const totalSteps = handshakeResult.messageLogs.length;

  function renderCurrentStep(): void {
    if (!handshakeResult || !stepInfo || !counter) return;
    const msg = handshakeResult.messageLogs[currentStep];
    const direction = msg.direction === '->' ? 'Initiator → Responder' : 'Responder → Initiator';

    counter.textContent = `Message ${currentStep + 1} of ${totalSteps}`;

    let html = `
      <div class="step-header">
        <span class="step-direction" aria-label="Direction: ${direction}">${direction}</span>
        <span class="step-tokens">Tokens: <code>${msg.tokens.join(', ')}</code></span>
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
              </div>`
            ).join('')}
          </div>
        </div>
      `;
    });

    html += '</div>';

    // Show handshake hash at this point
    html += `
      <div class="handshake-hash">
        <span class="hash-label">Handshake hash (h):</span>
        <span class="hex-value" title="Cumulative handshake hash">${toHex(handshakeResult.handshakeHash)}</span>
      </div>
    `;

    stepInfo.innerHTML = html;

    if (prevBtn) prevBtn.disabled = currentStep === 0;
    if (nextBtn) nextBtn.disabled = currentStep >= totalSteps - 1;
  }

  if (prevBtn) {
    prevBtn.onclick = () => {
      if (currentStep > 0) { currentStep--; renderCurrentStep(); }
    };
  }
  if (nextBtn) {
    nextBtn.onclick = () => {
      if (currentStep < totalSteps - 1) { currentStep++; renderCurrentStep(); }
    };
  }

  renderCurrentStep();
}

// ----- Transport Phase (Panel 3) -----

function renderTransportPhase(): void {
  if (!handshakeResult) return;

  const sendKeyEl = document.getElementById('transport-send-key');
  const recvKeyEl = document.getElementById('transport-recv-key');

  // Initiator's cipher states: [send, recv]
  transportSendCipher = handshakeResult.initiatorCiphers[0];
  transportRecvCipher = handshakeResult.responderCiphers[0]; // responder's send = initiator's recv, but for demo we use initiator perspective
  transportNonce = 0;

  const sendKey = handshakeResult.messageLogs[handshakeResult.messageLogs.length - 1]
    ?.logs.find(l => l.operation === 'Split')?.details.sendKey || '(derived)';
  const recvKey = handshakeResult.messageLogs[handshakeResult.messageLogs.length - 1]
    ?.logs.find(l => l.operation === 'Split')?.details.recvKey || '(derived)';

  if (sendKeyEl) sendKeyEl.textContent = sendKey;
  if (recvKeyEl) recvKeyEl.textContent = recvKey;

  const nonceEl = document.getElementById('transport-nonce');
  if (nonceEl) nonceEl.textContent = '0';

  const encryptBtn = document.getElementById('encrypt-btn') as HTMLButtonElement;
  const messageInput = document.getElementById('transport-message') as HTMLInputElement;
  const ciphertextEl = document.getElementById('transport-ciphertext');
  const plaintextEl = document.getElementById('transport-plaintext');
  const errorEl = document.getElementById('transport-error');

  if (encryptBtn && messageInput) {
    encryptBtn.onclick = async () => {
      if (!transportSendCipher) return;
      const msg = messageInput.value;
      if (!msg) {
        if (errorEl) { errorEl.textContent = 'Enter a message to encrypt'; }
        return;
      }
      if (errorEl) errorEl.textContent = '';
      try {
        const plaintext = new TextEncoder().encode(msg);
        const ciphertext = await transportSendCipher.encryptWithAd(EMPTY, plaintext);
        transportNonce++;
        if (nonceEl) nonceEl.textContent = String(transportNonce);

        if (ciphertextEl) ciphertextEl.textContent = toHex(ciphertext);

        // Decrypt with responder's cipher[0] (initiator→responder direction)
        // After Split(), both parties get [initiator→responder, responder→initiator]
        const decrypted = await handshakeResult!.responderCiphers[0].decryptWithAd(EMPTY, ciphertext);
        if (plaintextEl) plaintextEl.textContent = new TextDecoder().decode(decrypted);

        // Nonce warning
        if (transportNonce > 100) {
          if (errorEl) {
            errorEl.textContent = `Note: In production, rekey before nonce reaches 2⁶⁴. Current: ${transportNonce}`;
            errorEl.setAttribute('role', 'alert');
          }
        }
      } catch (err) {
        if (errorEl) {
          errorEl.textContent = `Encryption error: ${(err as Error).message}`;
          errorEl.setAttribute('role', 'alert');
        }
      }
    };
  }
}

// ----- Pattern Comparison (Panel 4) -----

export function renderPatternComparison(): void {
  const container = document.getElementById('comparison-table');
  if (!container) return;

  const comparePatterns = ['NN', 'XX', 'IK', 'IKpsk2'];
  const rows = comparePatterns.map(name => {
    const info = getPatternInfo(name);
    return `
      <tr>
        <td><strong>${name}</strong></td>
        <td>
          <span class="security-${info.security.senderAuth}" aria-label="${info.security.senderAuth}">
            ${getAuthIcon(info.security.senderAuth)} ${info.security.senderAuth}
          </span>
        </td>
        <td>
          <span class="security-${info.security.forwardSecrecy}" aria-label="${info.security.forwardSecrecy}">
            ${getFSIcon(info.security.forwardSecrecy)} ${info.security.forwardSecrecy}
          </span>
        </td>
        <td>
          <span class="security-${info.security.identityHiding}" aria-label="${info.security.identityHiding}">
            ${getIDHIcon(info.security.identityHiding)} ${info.security.identityHiding}
          </span>
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
}

// ----- WireGuard Deep Dive (Panel 5) -----

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
      <h3>Security Properties</h3>
      <div id="wg-security-props">
        <div class="security-row">
          <span class="security-label">Initiator identity</span>
          <span class="security-value">Hidden from passive observers (encrypted under es)</span>
        </div>
        <div class="security-row">
          <span class="security-label">Responder identity</span>
          <span class="security-value">Hidden from active attackers (known only to authenticated initiators)</span>
        </div>
        <div class="security-row">
          <span class="security-label">Forward secrecy</span>
          <span class="security-value security-full">● Full — ephemeral keys ensure past sessions stay secure</span>
        </div>
        <div class="security-row">
          <span class="security-label">PSK binding</span>
          <span class="security-value">Post-quantum defensive layer via psk2 modifier</span>
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

// ----- Helpers -----

function escapeHtml(text: string): string {
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}
