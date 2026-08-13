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
  /**
   * Per-pattern nuance behind the coarse security labels, keyed by property.
   * Cites the Noise spec Rev 34 grades (§7.7 payload security, §7.8 identity
   * hiding) that the four-value labels necessarily flatten.
   */
  specNotes?: Partial<Record<keyof SecurityProperties, string>>;
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
// Based on Noise spec Rev 34, Section 7.7 (payload security) and Section 7.8
// (identity hiding). The spec grades every payload and every static key on a
// numeric scale; the four-value labels below are a deliberate simplification,
// so the rule behind each one is stated here and applied uniformly to all 13
// patterns. Per-pattern `specNotes` carry the nuance the labels flatten.
//
// forwardSecrecy — graded on the WHOLE session, handshake payloads included:
//   'full'    the pattern encrypts nothing before the ephemeral-ephemeral DH
//             (`ee`) has been mixed in, so everything it does protect stays
//             protected under a later static-key compromise. Patterns opening
//             with a bare `e` have no key yet for a first-message payload, so
//             such a payload travels in cleartext (spec destination 0) — visible
//             from the start, but not a forward-secrecy failure.
//   'partial' the pattern pre-shares the responder's static key and therefore
//             encrypts its FIRST message payload before `ee` fires, using only
//             `es` (and `ss`). The spec grades that payload destination 2 —
//             "encryption to a known recipient, forward secrecy for sender
//             compromise only". Transport keys are still forward secret (with
//             the spec's §7.7 responder caveat for K*/I* patterns, noted in the
//             explanations below); the first-message payload is not. This is
//             exactly the 0-RTT-style trade-off, and it applies to NK, KK, XK,
//             IK and IKpsk2.
//   'none'    no ephemeral DH at all. No pattern here is in this class.
//
// identityHiding — the rule is: a party's static public key counts as HIDDEN
//   when it never appears in cleartext on the wire, whether because it is
//   pre-shared out of band, encrypted before transmission, or absent from the
//   pattern entirely. A party counts as EXPOSED only when the pattern sends its
//   static key in the clear (spec §7.8 property 0). Applied consistently this
//   leaves only IN and IX exposing anyone, which is itself the point: Noise
//   encrypts identities by default where TLS does not. "Hidden from the wire"
//   is not the same as unlinkable, so the §7.8 grade for each party — including
//   the ones a passive attacker can still confirm by guessing a candidate key —
//   is recorded in `specNotes`.

export const PATTERNS: Record<string, PatternInfo> = {
  NN: {
    pattern: NN,
    security: { senderAuth: 'none', forwardSecrecy: 'full', identityHiding: 'both' },
    description: 'No authentication. Anonymous ephemeral DH. Forward secret but no identity verification.',
    realWorld: 'Anonymous tunneling, opportunistic encryption',
    vsTLS: 'TLS has no equivalent — anonymous cipher suites were removed in TLS 1.3. Noise lets you pick anonymity by design.',
    specNotes: {
      identityHiding: 'Neither party has a static key in this pattern, so there is no identity to leak — hidden by absence, not by protection. Spec §7.8 marks both parties "-".'
    }
  },
  NK: {
    pattern: NK,
    security: { senderAuth: 'none', forwardSecrecy: 'partial', identityHiding: 'both' },
    description: 'Initiator authenticates responder via known static key. Initiator remains anonymous.',
    realWorld: 'Connecting to known server without client auth',
    vsTLS: 'Like TLS 1.3 server-auth, but the responder key is pinned at compile time — no certificate chain, no CA, no SNI leak.',
    specNotes: {
      forwardSecrecy: 'Message 1 is `e, es`: its payload is encrypted before `ee` runs, so it is graded destination 2 — forward secret against initiator compromise only. Stealing the responder\'s static key later decrypts any recorded first-message payload. Everything from message 2 onward, transport keys included, is fully forward secret.',
      identityHiding: 'The initiator has no static key; the responder\'s is pre-shared and never transmitted. But spec §7.8 grades the responder 3 — a passive attacker who guesses a candidate responder private key can confirm the guess against a recorded handshake. Absent from the wire is not the same as unlinkable.'
    }
  },
  NX: {
    pattern: NX,
    security: { senderAuth: 'none', forwardSecrecy: 'full', identityHiding: 'both' },
    description: 'Responder sends static key during handshake. Initiator authenticates responder but stays anonymous.',
    realWorld: 'TOFU-style server authentication',
    vsTLS: 'TLS 1.3 with server cert but no client auth — except identity is a raw key, trust is TOFU not PKI.',
    specNotes: {
      identityHiding: 'The one static key this pattern transmits is the RESPONDER\'s, sent encrypted in message 2 after `ee`. The initiator has no static key at all. Spec §7.8 grades the responder 1: encrypted with forward secrecy, but any anonymous initiator can open a handshake and read it, so the responder is identifiable to anyone willing to connect.'
    }
  },
  KN: {
    pattern: KN,
    security: { senderAuth: 'one-way', forwardSecrecy: 'full', identityHiding: 'both' },
    description: 'Responder knows initiator static key. One-way authentication of initiator.',
    realWorld: 'Device-to-server with pre-enrolled device keys',
    vsTLS: 'TLS has no clean equivalent — TLS client auth requires a server cert too. Noise lets you auth only one side.',
    specNotes: {
      identityHiding: 'The initiator\'s static key is pre-shared, never sent; the responder has none. Spec §7.8 grades the initiator 7 — an active attacker who impersonates the responder can afterwards test candidate initiator public keys against the recorded run.'
    }
  },
  KK: {
    pattern: KK,
    security: { senderAuth: 'mutual', forwardSecrecy: 'partial', identityHiding: 'both' },
    description: 'Both parties know each other\'s static keys. Mutual authentication, but the first message payload predates the ephemeral-ephemeral DH.',
    realWorld: 'Peer-to-peer with pre-shared identity keys',
    vsTLS: 'Like mutual-TLS with pinned certs, but zero bytes of identity flow over the wire — both keys are pre-shared.',
    specNotes: {
      forwardSecrecy: 'Message 1 is `e, es, ss`: its payload is encrypted using the two parties\' static keys before `ee` runs, so it is graded destination 2. Compromising either static key later decrypts a recorded first-message payload. Transport keys are forward secret, with the spec §7.7 caveat for patterns starting with K: the responder is guaranteed only weak forward secrecy for the transport messages it sends until it receives a transport message from the initiator.',
      identityHiding: 'Both static keys are pre-shared and neither is transmitted. Spec §7.8 grades both parties 5 — a passive attacker can still test a candidate (responder private key, initiator public key) pair against a recorded run.'
    }
  },
  KX: {
    pattern: KX,
    security: { senderAuth: 'mutual', forwardSecrecy: 'full', identityHiding: 'both' },
    description: 'Initiator static known, responder sends static during handshake. Neither identity appears in cleartext.',
    realWorld: 'Authenticated sessions with responder privacy',
    vsTLS: 'TLS always reveals server identity in cleartext SNI/cert. Noise KX hides the responder behind the handshake key schedule.',
    specNotes: {
      identityHiding: 'The initiator\'s static key is pre-shared; the responder\'s is sent encrypted in message 2. Spec §7.8 grades the initiator 7 and the responder 6 — the responder\'s key has only weak forward secrecy, so an active attacker who later learns the initiator\'s private key can decrypt it from a recorded run.'
    }
  },
  XN: {
    pattern: XN,
    security: { senderAuth: 'one-way', forwardSecrecy: 'full', identityHiding: 'both' },
    description: 'Initiator transmits static key in third message. No responder authentication.',
    realWorld: 'Client identifies itself to unauthenticated relay',
    vsTLS: 'No TLS analog — TLS clients can\'t authenticate to a server that itself has no identity.',
    specNotes: {
      identityHiding: 'The initiator\'s static key is sent encrypted in message 3; the responder has none. Spec §7.8 grades the initiator 2 — encrypted with forward secrecy, but the responder is unauthenticated, so it is being handed to whoever answered the connection.'
    }
  },
  XK: {
    pattern: XK,
    security: { senderAuth: 'mutual', forwardSecrecy: 'partial', identityHiding: 'both' },
    description: 'Responder key known in advance, initiator sends static encrypted in message 3. Best identity hiding of the pre-shared-responder patterns.',
    realWorld: 'Signal X3DH-like flows, connecting to known server with client auth',
    vsTLS: 'TLS 1.3 with client cert — but the client cert is sent in cleartext to anyone holding the server key. XK encrypts it.',
    specNotes: {
      forwardSecrecy: 'Message 1 is `e, es`: its payload is encrypted before `ee` runs and is graded destination 2, so a later compromise of the responder\'s static key decrypts any recorded first-message payload. Messages 2 and 3 and all transport keys are fully forward secret.',
      identityHiding: 'The initiator\'s static key goes out encrypted in message 3, after the responder is authenticated — spec §7.8 grade 8, the strongest in the table. The responder\'s is pre-shared, graded 3 (a passive attacker can confirm a guessed responder private key). This is why Lightning BOLT #8 picked XK.'
    }
  },
  XX: {
    pattern: XX,
    security: { senderAuth: 'mutual', forwardSecrecy: 'full', identityHiding: 'both' },
    description: 'Both parties transmit static keys encrypted. Mutual authentication with identity hiding for both parties.',
    realWorld: 'libp2p secure channel, general-purpose mutual auth',
    vsTLS: 'Closest TLS analog is mTLS — but XX takes 3 messages (not 2 RTT) and hides both identities from on-path observers.',
    specNotes: {
      identityHiding: 'Both static keys are transmitted encrypted after `ee`. Spec §7.8 grades the initiator 8 (encrypted with forward secrecy to an authenticated party) and the responder 1 (any anonymous initiator can connect and learn it). XX needs no pre-shared knowledge to get there, which is why it is the general-purpose default.'
    }
  },
  IN: {
    pattern: IN,
    security: { senderAuth: 'one-way', forwardSecrecy: 'full', identityHiding: 'responder' },
    description: 'Initiator sends static key immediately, in cleartext. One-way auth, no privacy for the client.',
    realWorld: 'Quick client identification without privacy',
    vsTLS: 'No TLS analog — TLS never sends client identity before the server is authenticated.',
    specNotes: {
      identityHiding: 'Message 1 is `e, s` with the static key unencrypted — spec §7.8 grade 0, transmitted in clear. The responder has no static key to expose, so it is hidden by absence. IN and IX are the only patterns here that put any identity on the wire in the clear.'
    }
  },
  IK: {
    pattern: IK,
    security: { senderAuth: 'mutual', forwardSecrecy: 'partial', identityHiding: 'both' },
    description: 'Initiator knows responder key, sends own static encrypted in first message. Fewest round trips with mutual auth — paid for with the first message\'s forward secrecy.',
    realWorld: 'Low-latency encrypted channels, basis for WireGuard\'s IKpsk2',
    vsTLS: 'Like TLS 1.3 0-RTT with mTLS — but Noise makes the responder-key requirement explicit; no fallback to weaker auth.',
    specNotes: {
      forwardSecrecy: 'Message 1 is `e, es, s, ss`: the initiator\'s static key AND the payload are encrypted before `ee` runs, graded destination 2. Anyone who later steals the responder\'s static key can decrypt a recorded first message — payload and initiator identity both. This is the same 0-RTT trade TLS 1.3 early data makes. Transport keys are forward secret, with the spec §7.7 caveat for patterns starting with I: the responder is guaranteed only weak forward secrecy for the transport messages it sends until it receives a transport message from the initiator.',
      identityHiding: 'The initiator\'s static key is encrypted, but only to the responder\'s static key — spec §7.8 grade 4, encrypted WITHOUT forward secrecy. The responder\'s is pre-shared, graded 3. So "hidden" here means hidden from a passive attacker today, not from one who compromises the responder tomorrow.'
    }
  },
  IX: {
    pattern: IX,
    security: { senderAuth: 'mutual', forwardSecrecy: 'full', identityHiding: 'responder' },
    description: 'Both send static keys: initiator in message 1 in cleartext, responder encrypted in message 2.',
    realWorld: 'Fast mutual authentication without privacy',
    vsTLS: 'Mutual TLS without cert encryption — the initiator\'s identity flows in plaintext, but no PKI overhead.',
    specNotes: {
      identityHiding: 'Message 1 is `e, s` with the initiator\'s static key unencrypted — spec §7.8 grade 0. The responder\'s is encrypted in message 2 but graded 6, weak forward secrecy: an active attacker who later learns the initiator\'s private key can recover it from a recording.'
    }
  },
  IKpsk2: {
    pattern: IKpsk2,
    security: { senderAuth: 'mutual', forwardSecrecy: 'partial', identityHiding: 'both' },
    description: 'IK with a pre-shared key mixed in during message 2. WireGuard\'s handshake pattern. The PSK adds a post-quantum defensive layer, but arrives too late to protect message 1.',
    realWorld: 'WireGuard VPN (Donenfeld, 2017)',
    vsTLS: 'TLS 1.3 also has a PSK mode, and RFC 8446 §2.2 supports both externally provisioned PSKs and PSKs established by a previous connection (resumption) — the difference is emphasis, not capability: Noise IKpsk2 treats the PSK as a primary post-quantum hedge alongside ECDH, where TLS deployments overwhelmingly use it for resumption.',
    specNotes: {
      forwardSecrecy: 'Inherits IK\'s message-1 exposure: `e, es, s, ss` encrypts the initiator\'s static key and payload before `ee`, graded destination 2. The `psk` token lands in message 2 (that is what the "2" in IKpsk2 means), so it does not protect message 1 either. Transport keys are forward secret (with the same §7.7 caveat as IK: the responder gets only weak forward secrecy for its transport messages until an initiator transport message arrives), and the PSK does make them resistant to an attacker who breaks X25519.',
      identityHiding: 'Same as IK — spec §7.8 grade 4 for the initiator (encrypted to the responder\'s static key, no forward secrecy) and 3 for the responder. WireGuard layers its own cookie and load-hiding mechanisms on top; the pattern alone does not hide the initiator from a future responder-key compromise.'
    }
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
    'none': 'No ephemeral DH at all — every recorded session is decryptable once a static key leaks.',
    'partial': 'Transport keys are forward secret, but this pattern pre-shares the responder\'s static key and so encrypts its FIRST message payload before the ephemeral-ephemeral DH runs, using only `es` (and `ss`). The Noise spec grades that payload destination 2 — "forward secrecy for sender compromise only". Steal the responder\'s static key later and any recorded first message opens. That is the price of the round trip these patterns save, and it is the same trade as TLS 1.3 0-RTT early data. One directional caveat survives into transport (spec §7.7): in patterns starting with K or I, the responder is guaranteed only weak forward secrecy for the transport messages it sends until it receives a transport message from the initiator.',
    'full': 'This pattern encrypts nothing before the ephemeral-ephemeral DH is mixed in, so everything it protects — handshake payloads and transport messages alike — stays protected even if every static key is stolen later. A pattern opening with a bare `e` has no key yet for a first-message payload, so such a payload goes out in cleartext: visible from the start, but not a forward-secrecy failure. Even here the spec adds one directional caveat (§7.7): in patterns starting with K or I, the responder is guaranteed only weak forward secrecy for the transport messages it sends until it receives a transport message from the initiator.'
  },
  identityHiding: {
    'none': 'Both parties send their static public key in cleartext. No pattern in this catalog does.',
    'initiator': 'The initiator\'s static key never appears in cleartext — pre-shared, absent, or sent encrypted — while the responder\'s does.',
    'responder': 'The responder\'s static key never appears in cleartext — pre-shared, absent, or sent encrypted — while the initiator\'s is sent in the clear.',
    'both': 'Neither static key appears in cleartext on the wire. Careful: this rule counts only what a passive observer reads off the wire. It does not mean unlinkable. A pre-shared key is invisible but often still confirmable by an attacker who guesses a candidate, and an encrypted key is not always forward secret. Click a pattern for its per-party Noise §7.8 grade.'
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

/**
 * Complexity ordering, simplest → most complex, for the guided newcomer ramp.
 * A newcomer should meet a *complete* handshake with the fewest moving parts
 * (NN: two messages, no statics, no PSK) before tokens like es/ss/psk appear.
 * The four **milestone** patterns form the guided path: NN → NK → XX → IKpsk2.
 */
export const COMPLEXITY_ORDER: string[] = [
  'NN', 'NK', 'NX', 'KN', 'IN', 'KX', 'XN', 'XK', 'KK', 'IX', 'IK', 'XX', 'IKpsk2'
];

/** The short guided path a newcomer is nudged along. */
export const GUIDED_PATH: string[] = ['NN', 'NK', 'XX', 'IKpsk2'];

/** Pattern names ordered simplest → most complex (for chip layout / stepping). */
export function getPatternNamesByComplexity(): string[] {
  const known = new Set(COMPLEXITY_ORDER);
  const rest = getPatternNames().filter(n => !known.has(n));
  return [...COMPLEXITY_ORDER.filter(n => PATTERNS[n]), ...rest];
}

/**
 * One-line "what's new in this pattern vs the previous milestone" for the
 * guided banner. Keyed by the target pattern; describes what capability the
 * newly-introduced tokens buy you, so the delta — not the whole pattern — is
 * what the learner focuses on.
 */
export const WHATS_NEW: Record<string, { from: string; text: string }> = {
  NN: {
    from: '',
    text: 'Start here. The simplest complete Noise handshake: just two ephemeral keys (e) and one DH between them (ee). No identities, no long-term keys — anonymous but already forward-secret.'
  },
  NK: {
    from: 'NN',
    text: 'New vs NN: the es token. The initiator now DHs its ephemeral against the responder\'s pre-known static key, so the initiator can be sure it is talking to the real server — the responder is now authenticated.'
  },
  XX: {
    from: 'NK',
    text: 'New vs NK: the s and ss/se tokens, plus a 3rd message. Both sides now transmit their static keys — encrypted, once a k exists — so authentication becomes mutual and both identities stay hidden from on-path observers.'
  },
  IKpsk2: {
    from: 'XX',
    text: 'New vs XX: the responder key is pre-known (so the initiator sends its static in message 1 — 1-RTT), and a psk token mixes a pre-shared secret into the key schedule as a post-quantum hedge. This is WireGuard.'
  }
};

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

/**
 * What each token does to the two running secrets, for the split state-card
 * captions. `transcript` = mixes bytes into h (MixHash); `keySchedule` = feeds
 * the DH/PSK output into ck and derives a fresh k (MixKey / MixKeyAndHash).
 */
export interface TokenEffect {
  transcript: boolean;   // touches h
  keySchedule: boolean;  // touches ck → k
  label: string;         // short human phrase for the firing token
}

export const TOKEN_EFFECTS: Record<string, TokenEffect> = {
  // `e`/`s` send a public key, whose bytes are hashed into h. In PSK patterns an
  // `e` additionally MixKeys its own public key, but the dominant teaching point
  // is transcript binding, so we label the ordinary case.
  'e':  { transcript: true,  keySchedule: false, label: 'ephemeral pubkey hashed into the transcript' },
  's':  { transcript: true,  keySchedule: false, label: 'static pubkey (encrypted if a k exists) hashed into the transcript' },
  'ee': { transcript: false, keySchedule: true,  label: 'DH output folded into the key schedule' },
  'es': { transcript: false, keySchedule: true,  label: 'DH output folded into the key schedule' },
  'se': { transcript: false, keySchedule: true,  label: 'DH output folded into the key schedule' },
  'ss': { transcript: false, keySchedule: true,  label: 'DH output folded into the key schedule' },
  'psk':{ transcript: true,  keySchedule: true,  label: 'pre-shared key mixed into BOTH the transcript and the key schedule' }
};

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
