/**
 * Noise Protocol Framework pattern definitions.
 * Reference: Noise Protocol Framework, Revision 34 — Section 7
 * https://noiseprotocol.org/noise.html
 *
 * Token legend:
 *   e  = generate ephemeral key pair, send public key
 *   s  = encrypt and send static public key
 *   ee = DH(e_local, e_remote)
 *   es = DH(e_local, s_remote) or DH(s_local, e_remote) depending on role
 *   se = DH(s_local, e_remote) or DH(e_local, s_remote) depending on role
 *   ss = DH(s_local, s_remote)
 *   psk = mix pre-shared key into handshake state
 */

export type Token = 'e' | 's' | 'ee' | 'es' | 'se' | 'ss' | 'psk';

export interface MessagePattern {
  direction: '->' | '<-';
  tokens: Token[];
}

export type PreMessagePattern = {
  direction: '->' | '<-';
  tokens: ('e' | 's')[];
};

export interface HandshakePattern {
  name: string;
  preMessages: PreMessagePattern[];
  messages: MessagePattern[];
}

export type AuthLevel = 'none' | 'one-way' | 'mutual';
export type ForwardSecrecy = 'none' | 'partial' | 'full';
export type IdentityHiding = 'none' | 'initiator' | 'responder' | 'both';

export interface SecurityProperties {
  senderAuth: AuthLevel;
  forwardSecrecy: ForwardSecrecy;
  identityHiding: IdentityHiding;
}

export interface PatternInfo {
  pattern: HandshakePattern;
  security: SecurityProperties;
  description: string;
  realWorld: string;
  /** How this pattern compares to TLS's negotiated equivalent */
  vsTLS: string;
}

// ----- Pattern Definitions (Noise spec Rev 34, Section 7.4 & 7.5) -----

const NN: HandshakePattern = {
  name: 'NN',
  preMessages: [],
  messages: [
    { direction: '->', tokens: ['e'] },
    { direction: '<-', tokens: ['e', 'ee'] }
  ]
};

const NK: HandshakePattern = {
  name: 'NK',
  preMessages: [
    { direction: '<-', tokens: ['s'] }
  ],
  messages: [
    { direction: '->', tokens: ['e', 'es'] },
    { direction: '<-', tokens: ['e', 'ee'] }
  ]
};

const NX: HandshakePattern = {
  name: 'NX',
  preMessages: [],
  messages: [
    { direction: '->', tokens: ['e'] },
    { direction: '<-', tokens: ['e', 'ee', 's', 'es'] }
  ]
};

const KN: HandshakePattern = {
  name: 'KN',
  preMessages: [
    { direction: '->', tokens: ['s'] }
  ],
  messages: [
    { direction: '->', tokens: ['e'] },
    { direction: '<-', tokens: ['e', 'ee', 'se'] }
  ]
};

const KK: HandshakePattern = {
  name: 'KK',
  preMessages: [
    { direction: '->', tokens: ['s'] },
    { direction: '<-', tokens: ['s'] }
  ],
  messages: [
    { direction: '->', tokens: ['e', 'es', 'ss'] },
    { direction: '<-', tokens: ['e', 'ee', 'se'] }
  ]
};

const KX: HandshakePattern = {
  name: 'KX',
  preMessages: [
    { direction: '->', tokens: ['s'] }
  ],
  messages: [
    { direction: '->', tokens: ['e'] },
    { direction: '<-', tokens: ['e', 'ee', 'se', 's', 'es'] }
  ]
};

const XN: HandshakePattern = {
  name: 'XN',
  preMessages: [],
  messages: [
    { direction: '->', tokens: ['e'] },
    { direction: '<-', tokens: ['e', 'ee'] },
    { direction: '->', tokens: ['s', 'se'] }
  ]
};

const XK: HandshakePattern = {
  name: 'XK',
  preMessages: [
    { direction: '<-', tokens: ['s'] }
  ],
  messages: [
    { direction: '->', tokens: ['e', 'es'] },
    { direction: '<-', tokens: ['e', 'ee'] },
    { direction: '->', tokens: ['s', 'se'] }
  ]
};

const XX: HandshakePattern = {
  name: 'XX',
  preMessages: [],
  messages: [
    { direction: '->', tokens: ['e'] },
    { direction: '<-', tokens: ['e', 'ee', 's', 'es'] },
    { direction: '->', tokens: ['s', 'se'] }
  ]
};

const IN: HandshakePattern = {
  name: 'IN',
  preMessages: [],
  messages: [
    { direction: '->', tokens: ['e', 's'] },
    { direction: '<-', tokens: ['e', 'ee', 'se'] }
  ]
};

const IK: HandshakePattern = {
  name: 'IK',
  preMessages: [
    { direction: '<-', tokens: ['s'] }
  ],
  messages: [
    { direction: '->', tokens: ['e', 'es', 's', 'ss'] },
    { direction: '<-', tokens: ['e', 'ee', 'se'] }
  ]
};

const IX: HandshakePattern = {
  name: 'IX',
  preMessages: [],
  messages: [
    { direction: '->', tokens: ['e', 's'] },
    { direction: '<-', tokens: ['e', 'ee', 'se', 's', 'es'] }
  ]
};

/**
 * IKpsk2 — the pattern used by WireGuard.
 * Reference: WireGuard whitepaper by Jason A. Donenfeld
 * https://www.wireguard.com/papers/wireguard.pdf
 *
 * psk2 modifier: PSK mixed into handshake after the second message pattern.
 * Per Noise spec Rev 34, Section 9: "psk" token inserted at position indicated by modifier number.
 */
const IKpsk2: HandshakePattern = {
  name: 'IKpsk2',
  preMessages: [
    { direction: '<-', tokens: ['s'] }
  ],
  messages: [
    { direction: '->', tokens: ['e', 'es', 's', 'ss'] },
    { direction: '<-', tokens: ['e', 'ee', 'se', 'psk'] }
  ]
};

// ----- Security Properties -----
// Based on Noise spec Rev 34, Section 7.7 and analysis tables

export const PATTERNS: Record<string, PatternInfo> = {
  NN: {
    pattern: NN,
    security: { senderAuth: 'none', forwardSecrecy: 'full', identityHiding: 'both' },
    description: 'No authentication. Anonymous ephemeral DH. Forward secret but no identity verification.',
    realWorld: 'Early QUIC drafts, anonymous tunneling',
    vsTLS: 'TLS has no equivalent — anonymous cipher suites were removed in TLS 1.3. Noise lets you pick anonymity by design.'
  },
  NK: {
    pattern: NK,
    security: { senderAuth: 'none', forwardSecrecy: 'full', identityHiding: 'initiator' },
    description: 'Initiator authenticates responder via known static key. Initiator remains anonymous.',
    realWorld: 'Connecting to known server without client auth',
    vsTLS: 'Like TLS 1.3 server-auth, but the responder key is pinned at compile time — no certificate chain, no CA, no SNI leak.'
  },
  NX: {
    pattern: NX,
    security: { senderAuth: 'none', forwardSecrecy: 'full', identityHiding: 'initiator' },
    description: 'Responder sends static key during handshake. Initiator authenticates responder but stays anonymous.',
    realWorld: 'TOFU-style server authentication',
    vsTLS: 'TLS 1.3 with server cert but no client auth — except identity is a raw key, trust is TOFU not PKI.'
  },
  KN: {
    pattern: KN,
    security: { senderAuth: 'one-way', forwardSecrecy: 'full', identityHiding: 'none' },
    description: 'Responder knows initiator static key. One-way authentication of initiator.',
    realWorld: 'Device-to-server with pre-enrolled device keys',
    vsTLS: 'TLS has no clean equivalent — TLS client auth requires a server cert too. Noise lets you auth only one side.'
  },
  KK: {
    pattern: KK,
    security: { senderAuth: 'mutual', forwardSecrecy: 'full', identityHiding: 'none' },
    description: 'Both parties know each other\'s static keys. Mutual authentication with full forward secrecy.',
    realWorld: 'Peer-to-peer with pre-shared identity keys',
    vsTLS: 'Like mutual-TLS with pinned certs, but zero bytes of identity flow over the wire — both keys are pre-shared.'
  },
  KX: {
    pattern: KX,
    security: { senderAuth: 'mutual', forwardSecrecy: 'full', identityHiding: 'responder' },
    description: 'Initiator static known, responder sends static during handshake. Responder identity hidden from passive observers.',
    realWorld: 'Authenticated sessions with responder privacy',
    vsTLS: 'TLS always reveals server identity in cleartext SNI/cert. Noise KX hides the responder behind the handshake key schedule.'
  },
  XN: {
    pattern: XN,
    security: { senderAuth: 'one-way', forwardSecrecy: 'full', identityHiding: 'initiator' },
    description: 'Initiator transmits static key in third message. No responder authentication.',
    realWorld: 'Client identifies itself to unauthenticated relay',
    vsTLS: 'No TLS analog — TLS clients can\'t authenticate to a server that itself has no identity.'
  },
  XK: {
    pattern: XK,
    security: { senderAuth: 'mutual', forwardSecrecy: 'full', identityHiding: 'initiator' },
    description: 'Responder key known in advance, initiator sends static encrypted. Initiator identity hidden from passive attackers.',
    realWorld: 'Signal X3DH-like flows, connecting to known server with client auth',
    vsTLS: 'TLS 1.3 with client cert — but the client cert is sent in cleartext to anyone holding the server key. XK encrypts it.'
  },
  XX: {
    pattern: XX,
    security: { senderAuth: 'mutual', forwardSecrecy: 'full', identityHiding: 'both' },
    description: 'Both parties transmit static keys encrypted. Mutual authentication with identity hiding for both parties.',
    realWorld: 'libp2p secure channel, general-purpose mutual auth',
    vsTLS: 'Closest TLS analog is mTLS — but XX takes 3 messages (not 2 RTT) and hides both identities from on-path observers.'
  },
  IN: {
    pattern: IN,
    security: { senderAuth: 'one-way', forwardSecrecy: 'full', identityHiding: 'none' },
    description: 'Initiator sends static key immediately (unencrypted). One-way auth, no identity hiding.',
    realWorld: 'Quick client identification without privacy',
    vsTLS: 'No TLS analog — TLS never sends client identity before the server is authenticated.'
  },
  IK: {
    pattern: IK,
    security: { senderAuth: 'mutual', forwardSecrecy: 'full', identityHiding: 'initiator' },
    description: 'Initiator knows responder key, sends own static encrypted in first message. Fewest round trips with mutual auth.',
    realWorld: 'Low-latency encrypted channels, basis for WireGuard\'s IKpsk2',
    vsTLS: 'Like TLS 1.3 0-RTT with mTLS — but Noise makes the responder-key requirement explicit; no fallback to weaker auth.'
  },
  IX: {
    pattern: IX,
    security: { senderAuth: 'mutual', forwardSecrecy: 'full', identityHiding: 'none' },
    description: 'Both send static keys: initiator in first msg, responder in second. No identity hiding.',
    realWorld: 'Fast mutual authentication without privacy',
    vsTLS: 'Mutual TLS without cert encryption — both identities flow plaintext, but no PKI overhead.'
  },
  IKpsk2: {
    pattern: IKpsk2,
    security: { senderAuth: 'mutual', forwardSecrecy: 'full', identityHiding: 'initiator' },
    description: 'IK with pre-shared key mixed after second message. WireGuard\'s handshake pattern. PSK adds post-quantum defensive layer.',
    realWorld: 'WireGuard VPN (Donenfeld, 2017)',
    vsTLS: 'TLS 1.3 has PSK mode but only for resumption. Noise IKpsk2 uses PSK as a primary post-quantum hedge alongside ECDH.'
  }
};

// ----- Property explanations (used by interactive Compare panel) -----

export const PROPERTY_EXPLANATIONS: Record<string, Record<string, string>> = {
  senderAuth: {
    'none': 'Neither party is authenticated — anyone can complete the handshake. Use only for anonymous tunneling.',
    'one-way': 'One party proves possession of a static key; the other remains anonymous.',
    'mutual': 'Both parties prove possession of their static keys before the handshake completes.'
  },
  forwardSecrecy: {
    'none': 'Past sessions can be decrypted if static keys are later compromised.',
    'partial': 'Some session keys depend only on static keys — compromise of statics breaks forward secrecy for those keys.',
    'full': 'Every transport key derives from ephemeral DH. Past sessions remain secure even if all static keys are later stolen.'
  },
  identityHiding: {
    'none': 'Both static public keys are observable on the wire.',
    'initiator': 'The initiator\'s static key is encrypted before transmission — passive observers cannot identify the client.',
    'responder': 'The responder\'s static key is encrypted before transmission — passive observers cannot identify the server.',
    'both': 'Both static keys are either pre-shared or encrypted — no identities are visible to a network adversary.'
  }
};

// ----- Predict-before-step prompts -----
// Keyed by pattern name → array indexed by message number.
// Falls back to a tokens-derived prompt for patterns without specific copy.

export function getPredictPrompt(pattern: HandshakePattern, messageIndex: number): string {
  const msg = pattern.messages[messageIndex];
  if (!msg) return '';
  const dir = msg.direction === '->' ? 'Initiator → Responder' : 'Responder → Initiator';
  const dhTokens = msg.tokens.filter(t => t === 'ee' || t === 'es' || t === 'se' || t === 'ss');
  const sendsEphemeral = msg.tokens.includes('e');
  const sendsStatic = msg.tokens.includes('s');
  const mixesPSK = msg.tokens.includes('psk');

  const parts: string[] = [`This message goes ${dir}.`];
  if (sendsEphemeral) parts.push('A fresh ephemeral key pair is generated and the public key is sent unencrypted.');
  if (sendsStatic) {
    // Static is encrypted only if cipher already has a key (i.e. some DH already happened earlier in this message or before).
    // The `s` token within a message comes after any preceding DH tokens in that same message — so encryption depends on
    // whether ANY DH token has fired by this point in the protocol.
    parts.push('The local static public key is sent — and it will be encrypted under any key derived so far (else passed through plaintext).');
  }
  if (dhTokens.length > 0) {
    parts.push(`These DH operations mix new key material: ${dhTokens.join(', ')}.`);
  }
  if (mixesPSK) {
    parts.push('The pre-shared key is mixed into the chaining key — this is the psk2 modifier in WireGuard.');
  }
  parts.push('Predict: which values will change after this message? (h always; ck and k only if a DH or PSK fires.)');
  return parts.join(' ');
}

export function getPatternNames(): string[] {
  return Object.keys(PATTERNS);
}

export function getPatternInfo(name: string): PatternInfo {
  const info = PATTERNS[name];
  if (!info) throw new Error(`Unknown pattern: ${name}`);
  return info;
}

/** Format a pattern's message sequence for display */
export function formatPatternMessages(pattern: HandshakePattern): string {
  const lines: string[] = [];
  for (const pm of pattern.preMessages) {
    lines.push(`  ${pm.direction} ${pm.tokens.join(', ')}  (pre-message)`);
  }
  if (pattern.preMessages.length > 0) {
    lines.push('  ...');
  }
  pattern.messages.forEach((m, i) => {
    lines.push(`  ${m.direction} ${m.tokens.join(', ')}`);
  });
  return lines.join('\n');
}

/** Token descriptions per Noise spec */
export const TOKEN_DESCRIPTIONS: Record<string, string> = {
  'e': 'Generate ephemeral key pair and send public key',
  's': 'Encrypt and send static public key (or send unencrypted if no key yet)',
  'ee': 'DH(initiator ephemeral, responder ephemeral)',
  'es': 'DH(initiator ephemeral, responder static) — or reverse for responder',
  'se': 'DH(initiator static, responder ephemeral) — or reverse for responder',
  'ss': 'DH(initiator static, responder static)',
  'psk': 'Mix pre-shared symmetric key into handshake state'
};

/**
 * Glossary — used by hover tooltips throughout the UI.
 * Map a short term to its definition.
 */
export const GLOSSARY: Record<string, string> = {
  'e': 'Ephemeral key pair — generated fresh per session. Public key is sent unencrypted.',
  's': 'Static key pair — long-lived identity. Public key is encrypted before being sent (if a key is already derived).',
  'ee': 'DH between both parties\' ephemeral keys — provides forward secrecy.',
  'es': 'DH between initiator ephemeral and responder static — authenticates the responder.',
  'se': 'DH between initiator static and responder ephemeral — authenticates the initiator.',
  'ss': 'DH between both static keys — provides authentication independent of ephemerals (no forward secrecy on its own).',
  'psk': 'Mix in a pre-shared symmetric secret — adds a post-quantum hedge.',
  'h': 'Handshake hash — a running SHA-256 of every byte sent or received in the handshake, used as AEAD associated data and as the channel binding.',
  'ck': 'Chaining key — the running HKDF salt that absorbs every DH output. Split() derives transport keys from ck at the end of the handshake.',
  'k': 'Symmetric cipher key — derived alongside ck by HKDF when new DH output is mixed in. Used by EncryptAndHash/DecryptAndHash during the handshake.',
  'n': 'Nonce counter — 64-bit, starts at 0 after key install, increments per AEAD encryption. Must never repeat under the same key.',
  'rs': 'Remote static public key — the other party\'s long-lived identity (32 bytes for X25519).',
  're': 'Remote ephemeral public key — the other party\'s per-session DH key.',
  'DHLEN': 'Length of a DH public key. 32 bytes for X25519.',
  'HASHLEN': 'Length of the hash output. 32 bytes for SHA-256.',
  'AEAD': 'Authenticated Encryption with Associated Data. AES-256-GCM here; ChaCha20-Poly1305 in WireGuard.',
  'AD': 'Associated Data — extra bytes the AEAD authenticates but does not encrypt. In Noise it\'s the running handshake hash h.',
  'HKDF': 'HMAC-based Key Derivation Function (RFC 5869). Noise uses it to derive (ck, k) from each DH output.',
  'Split': 'Final HKDF call that derives the two transport CipherStates (c1=initiator→responder, c2=responder→initiator) from ck.',
  'psk2': 'PSK modifier — the "2" means "mix the PSK after message pattern #2". Used by IKpsk2 / WireGuard.',
  'MixKey': 'Update ck and install a new cipher key k from HKDF(ck, input).',
  'MixHash': 'Append data to h: h ← SHA256(h ‖ data). Binds every byte into the channel.',
  'MixKeyAndHash': 'PSK variant of MixKey that also updates h. Used by psk tokens.',
  'EncryptAndHash': 'Encrypt with k+n using h as AD, then MixHash the ciphertext.',
  'DecryptAndHash': 'Decrypt with k+n using h as AD, then MixHash the ciphertext.',
  'Rekey': 'Replace k with ENCRYPT(k, maxnonce, zeros). Forward-secret rotation without a fresh DH.',
  'channel binding': 'A value (here, the final h) both parties can compare out-of-band to detect MitM session confusion.',
  'forward secrecy': 'A property: compromise of long-term keys does not let an attacker decrypt past sessions.',
  'identity hiding': 'A property: a party\'s static public key is not visible to a passive (and sometimes active) network observer.'
};
