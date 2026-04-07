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
    realWorld: 'Early QUIC drafts, anonymous tunneling'
  },
  NK: {
    pattern: NK,
    security: { senderAuth: 'none', forwardSecrecy: 'full', identityHiding: 'initiator' },
    description: 'Initiator authenticates responder via known static key. Initiator remains anonymous.',
    realWorld: 'Connecting to known server without client auth'
  },
  NX: {
    pattern: NX,
    security: { senderAuth: 'none', forwardSecrecy: 'full', identityHiding: 'initiator' },
    description: 'Responder sends static key during handshake. Initiator authenticates responder but stays anonymous.',
    realWorld: 'TOFU-style server authentication'
  },
  KN: {
    pattern: KN,
    security: { senderAuth: 'one-way', forwardSecrecy: 'full', identityHiding: 'none' },
    description: 'Responder knows initiator static key. One-way authentication of initiator.',
    realWorld: 'Device-to-server with pre-enrolled device keys'
  },
  KK: {
    pattern: KK,
    security: { senderAuth: 'mutual', forwardSecrecy: 'full', identityHiding: 'none' },
    description: 'Both parties know each other\'s static keys. Mutual authentication with full forward secrecy.',
    realWorld: 'Peer-to-peer with pre-shared identity keys'
  },
  KX: {
    pattern: KX,
    security: { senderAuth: 'mutual', forwardSecrecy: 'full', identityHiding: 'responder' },
    description: 'Initiator static known, responder sends static during handshake. Responder identity hidden from passive observers.',
    realWorld: 'Authenticated sessions with responder privacy'
  },
  XN: {
    pattern: XN,
    security: { senderAuth: 'one-way', forwardSecrecy: 'full', identityHiding: 'initiator' },
    description: 'Initiator transmits static key in third message. No responder authentication.',
    realWorld: 'Client identifies itself to unauthenticated relay'
  },
  XK: {
    pattern: XK,
    security: { senderAuth: 'mutual', forwardSecrecy: 'full', identityHiding: 'initiator' },
    description: 'Responder key known in advance, initiator sends static encrypted. Initiator identity hidden from passive attackers.',
    realWorld: 'Signal X3DH-like flows, connecting to known server with client auth'
  },
  XX: {
    pattern: XX,
    security: { senderAuth: 'mutual', forwardSecrecy: 'full', identityHiding: 'both' },
    description: 'Both parties transmit static keys encrypted. Mutual authentication with identity hiding for both parties.',
    realWorld: 'libp2p secure channel, general-purpose mutual auth'
  },
  IN: {
    pattern: IN,
    security: { senderAuth: 'one-way', forwardSecrecy: 'full', identityHiding: 'none' },
    description: 'Initiator sends static key immediately (unencrypted). One-way auth, no identity hiding.',
    realWorld: 'Quick client identification without privacy'
  },
  IK: {
    pattern: IK,
    security: { senderAuth: 'mutual', forwardSecrecy: 'full', identityHiding: 'initiator' },
    description: 'Initiator knows responder key, sends own static encrypted in first message. Fewest round trips with mutual auth.',
    realWorld: 'Low-latency encrypted channels, basis for WireGuard\'s IKpsk2'
  },
  IX: {
    pattern: IX,
    security: { senderAuth: 'mutual', forwardSecrecy: 'full', identityHiding: 'none' },
    description: 'Both send static keys: initiator in first msg, responder in second. No identity hiding.',
    realWorld: 'Fast mutual authentication without privacy'
  },
  IKpsk2: {
    pattern: IKpsk2,
    security: { senderAuth: 'mutual', forwardSecrecy: 'full', identityHiding: 'initiator' },
    description: 'IK with pre-shared key mixed after second message. WireGuard\'s handshake pattern. PSK adds post-quantum defensive layer.',
    realWorld: 'WireGuard VPN (Donenfeld, 2017)'
  }
};

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
