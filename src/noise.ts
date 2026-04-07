/**
 * Noise Protocol Framework — CipherState, SymmetricState, HandshakeState
 * Reference: Noise Protocol Framework, Revision 34 — Sections 5, 5.1, 5.2, 5.3
 * https://noiseprotocol.org/noise.html
 *
 * Cipher: AESGCM (AES-256-GCM)
 * Hash: SHA256
 * DH: 25519 (X25519)
 * Protocol name: Noise_{pattern}_25519_AESGCM_SHA256
 */

import {
  KeyPair, generateKeyPair, dh, DHLEN,
  hkdf, sha256, aesGcmEncrypt, aesGcmDecrypt,
  nonceFromCounter, concat, toHex, EMPTY
} from './crypto';
import { HandshakePattern, Token } from './patterns';

const HASHLEN = 32; // SHA-256 output length
const MAX_NONCE = Number.MAX_SAFE_INTEGER; // JS safe integer limit, spec says 2^64-1

// ----- Logging -----

export interface StepLog {
  /** Which token or operation produced this log entry */
  operation: string;
  /** Human-readable description */
  description: string;
  /** Hex values of relevant state */
  details: Record<string, string>;
}

// ----- CipherState (Noise spec Section 5.1) -----

export class CipherState {
  k: Uint8Array | null = null; // 32-byte key or null (empty)
  n: number = 0; // nonce counter

  /** InitializeKey(key) */
  initializeKey(key: Uint8Array | null): void {
    this.k = key;
    this.n = 0;
  }

  hasKey(): boolean {
    return this.k !== null;
  }

  /** SetNonce(nonce) */
  setNonce(nonce: number): void {
    this.n = nonce;
  }

  /**
   * EncryptWithAd(ad, plaintext)
   * If k is non-empty, encrypt with AES-256-GCM using k, n, ad.
   * If k is empty, return plaintext.
   */
  async encryptWithAd(ad: Uint8Array, plaintext: Uint8Array): Promise<Uint8Array> {
    if (!this.k) return plaintext;
    if (this.n >= MAX_NONCE) throw new Error('Nonce exhaustion — must rekey');
    const nonce = nonceFromCounter(this.n);
    const ct = await aesGcmEncrypt(this.k, nonce, plaintext, ad);
    this.n++;
    return ct;
  }

  /**
   * DecryptWithAd(ad, ciphertext)
   * If k is non-empty, decrypt. If k is empty, return ciphertext.
   */
  async decryptWithAd(ad: Uint8Array, ciphertext: Uint8Array): Promise<Uint8Array> {
    if (!this.k) return ciphertext;
    if (this.n >= MAX_NONCE) throw new Error('Nonce exhaustion — must rekey');
    const nonce = nonceFromCounter(this.n);
    const pt = await aesGcmDecrypt(this.k, nonce, ciphertext, ad);
    this.n++;
    return pt;
  }

  /**
   * Rekey() — per spec Section 5.1
   * Sets k = REKEY(k) where REKEY generates a new key from the old one.
   * Using ENCRYPT(k, maxnonce, zerolen, zeros) as specified.
   */
  async rekey(): Promise<void> {
    if (!this.k) throw new Error('Cannot rekey without a key');
    // Noise spec: REKEY uses nonce = 2^64-1 (maxnonce)
    // For AESGCM: 4 bytes zeros || 8 bytes 0xFF = all-ones 64-bit counter
    const maxNonce = new Uint8Array([0,0,0,0, 0xff,0xff,0xff,0xff, 0xff,0xff,0xff,0xff]);
    const zeros = new Uint8Array(32);
    const newKeyFull = await aesGcmEncrypt(this.k, maxNonce, zeros, EMPTY);
    // Take first 32 bytes (discard 16-byte AEAD tag)
    this.k = newKeyFull.slice(0, 32);
  }
}

// ----- SymmetricState (Noise spec Section 5.2) -----

export class SymmetricState {
  ck: Uint8Array; // chaining key
  h: Uint8Array;  // handshake hash
  cipher: CipherState;
  logs: StepLog[] = [];

  constructor() {
    this.ck = new Uint8Array(HASHLEN);
    this.h = new Uint8Array(HASHLEN);
    this.cipher = new CipherState();
  }

  /**
   * InitializeSymmetric(protocol_name)
   * If protocol_name <= HASHLEN bytes, pad to HASHLEN. Otherwise hash it.
   */
  async initializeSymmetric(protocolName: string): Promise<void> {
    const nameBytes = new TextEncoder().encode(protocolName);
    if (nameBytes.length <= HASHLEN) {
      this.h = new Uint8Array(HASHLEN);
      this.h.set(nameBytes);
    } else {
      this.h = await sha256(nameBytes);
    }
    this.ck = new Uint8Array(this.h);
    this.cipher.initializeKey(null);
    this.log('InitializeSymmetric', `Protocol: ${protocolName}`, {
      h: toHex(this.h),
      ck: toHex(this.ck)
    });
  }

  /** MixKey(input_key_material) — spec Section 5.2 */
  async mixKey(inputKeyMaterial: Uint8Array): Promise<void> {
    const [ck, tempK] = await hkdf(this.ck, inputKeyMaterial, 2);
    this.ck = ck;
    // Truncate tempK to 32 bytes (already 32 for SHA-256 HKDF)
    this.cipher.initializeKey(tempK.slice(0, 32));
    this.log('MixKey', 'HKDF(ck, input) → new ck + cipher key', {
      ck: toHex(this.ck),
      k: toHex(tempK.slice(0, 32))
    });
  }

  /** MixHash(data) — spec Section 5.2 */
  async mixHash(data: Uint8Array): Promise<void> {
    this.h = await sha256(concat(this.h, data));
    this.log('MixHash', 'h = SHA256(h || data)', {
      h: toHex(this.h)
    });
  }

  /**
   * MixKeyAndHash(input_key_material) — for PSK modifier, spec Section 5.2
   * HKDF with 3 outputs. First output replaces ck, second is mixed into h,
   * third becomes the cipher key.
   */
  async mixKeyAndHash(inputKeyMaterial: Uint8Array): Promise<void> {
    const [ck, tempH, tempK] = await hkdf(this.ck, inputKeyMaterial, 3);
    this.ck = ck;
    await this.mixHash(tempH);
    this.cipher.initializeKey(tempK.slice(0, 32));
    this.log('MixKeyAndHash', 'PSK mixed into ck, h, and cipher key', {
      ck: toHex(this.ck),
      h: toHex(this.h),
      k: toHex(tempK.slice(0, 32))
    });
  }

  /** GetHandshakeHash() — returns h */
  getHandshakeHash(): Uint8Array {
    return new Uint8Array(this.h);
  }

  /**
   * EncryptAndHash(plaintext) — spec Section 5.2
   * Encrypt plaintext with current cipher using h as AD. Then mix ciphertext into h.
   */
  async encryptAndHash(plaintext: Uint8Array): Promise<Uint8Array> {
    const ciphertext = await this.cipher.encryptWithAd(this.h, plaintext);
    await this.mixHash(ciphertext);
    this.log('EncryptAndHash', this.cipher.hasKey() ? 'Encrypted with AEAD' : 'No key yet — plaintext passed through', {
      ciphertext: toHex(ciphertext),
      h: toHex(this.h)
    });
    return ciphertext;
  }

  /**
   * DecryptAndHash(ciphertext) — spec Section 5.2
   * Decrypt using h as AD, then mix ciphertext into h.
   */
  async decryptAndHash(ciphertext: Uint8Array): Promise<Uint8Array> {
    const plaintext = await this.cipher.decryptWithAd(this.h, ciphertext);
    await this.mixHash(ciphertext);
    this.log('DecryptAndHash', this.cipher.hasKey() ? 'Decrypted with AEAD' : 'No key — plaintext passed through', {
      plaintext: toHex(plaintext),
      h: toHex(this.h)
    });
    return plaintext;
  }

  /**
   * Split() — spec Section 5.2
   * Returns two CipherState objects for transport.
   */
  async split(): Promise<[CipherState, CipherState]> {
    const [tempK1, tempK2] = await hkdf(this.ck, EMPTY, 2);
    const c1 = new CipherState();
    c1.initializeKey(tempK1.slice(0, 32));
    const c2 = new CipherState();
    c2.initializeKey(tempK2.slice(0, 32));
    this.log('Split', 'Derived transport keys from chaining key', {
      sendKey: toHex(tempK1.slice(0, 32)),
      recvKey: toHex(tempK2.slice(0, 32))
    });
    return [c1, c2];
  }

  private log(operation: string, description: string, details: Record<string, string>): void {
    this.logs.push({ operation, description, details });
  }
}

// ----- HandshakeState (Noise spec Section 5.3) -----

export type Role = 'initiator' | 'responder';

export interface HandshakeResult {
  /** Completed? */
  done: boolean;
  /** Message payload to send (if writing) */
  messageBuffer?: Uint8Array;
  /** Decrypted payload (if reading) */
  payload?: Uint8Array;
  /** Transport cipher states (when done) */
  cipherStates?: [CipherState, CipherState];
  /** Step logs for UI display */
  stepLogs: StepLog[];
}

export class HandshakeState {
  private symmetricState: SymmetricState;
  private s: KeyPair | null = null;  // local static key pair
  private e: KeyPair | null = null;  // local ephemeral key pair
  private rs: Uint8Array | null = null; // remote static public key
  private re: Uint8Array | null = null; // remote ephemeral public key
  private role: Role;
  private pattern: HandshakePattern;
  private messageIndex: number = 0;
  private psk: Uint8Array | null = null; // pre-shared key (for pskN modifiers)
  private initiator: boolean;

  constructor() {
    this.symmetricState = new SymmetricState();
    this.role = 'initiator';
    this.pattern = { name: '', preMessages: [], messages: [] };
    this.initiator = true;
  }

  /**
   * Initialize(handshake_pattern, initiator, prologue, s, e, rs, re, psk)
   * Per spec Section 5.3
   */
  async initialize(
    pattern: HandshakePattern,
    initiator: boolean,
    prologue: Uint8Array = EMPTY,
    s: KeyPair | null = null,
    e: KeyPair | null = null,
    rs: Uint8Array | null = null,
    re: Uint8Array | null = null,
    psk: Uint8Array | null = null
  ): Promise<void> {
    this.pattern = pattern;
    this.initiator = initiator;
    this.role = initiator ? 'initiator' : 'responder';
    this.s = s;
    this.e = e;
    this.rs = rs;
    this.re = re;
    this.psk = psk;
    this.messageIndex = 0;

    // Protocol name: Noise_{pattern}_25519_AESGCM_SHA256
    const protocolName = `Noise_${pattern.name}_25519_AESGCM_SHA256`;
    await this.symmetricState.initializeSymmetric(protocolName);
    await this.symmetricState.mixHash(prologue);

    // Process pre-messages
    for (const pm of pattern.preMessages) {
      const isSender = (pm.direction === '->') === initiator;
      for (const token of pm.tokens) {
        if (token === 'e') {
          if (isSender) {
            if (!this.e) throw new Error('Pre-message requires local ephemeral key');
            await this.symmetricState.mixHash(this.e.publicKey);
          } else {
            if (!this.re) throw new Error('Pre-message requires remote ephemeral key');
            await this.symmetricState.mixHash(this.re);
          }
        } else if (token === 's') {
          if (isSender) {
            if (!this.s) throw new Error('Pre-message requires local static key');
            await this.symmetricState.mixHash(this.s.publicKey);
          } else {
            if (!this.rs) throw new Error('Pre-message requires remote static key');
            await this.symmetricState.mixHash(this.rs);
          }
        }
      }
    }
  }

  /** Get the current accumulated logs */
  getLogs(): StepLog[] {
    return [...this.symmetricState.logs];
  }

  /** Clear logs (call after retrieving) */
  clearLogs(): void {
    this.symmetricState.logs = [];
  }

  /** Get current handshake hash */
  getHandshakeHash(): Uint8Array {
    return this.symmetricState.getHandshakeHash();
  }

  /** Get current chaining key (for display) */
  getChainingKey(): Uint8Array {
    return new Uint8Array(this.symmetricState.ck);
  }

  /** Get local ephemeral public key */
  getLocalEphemeral(): Uint8Array | null {
    return this.e?.publicKey ? new Uint8Array(this.e.publicKey) : null;
  }

  /** Get remote ephemeral public key */
  getRemoteEphemeral(): Uint8Array | null {
    return this.re ? new Uint8Array(this.re) : null;
  }

  /** Check if handshake is complete */
  isComplete(): boolean {
    return this.messageIndex >= this.pattern.messages.length;
  }

  /** Get the current message pattern (direction + tokens) */
  getCurrentMessagePattern() {
    if (this.isComplete()) return null;
    return this.pattern.messages[this.messageIndex];
  }

  /** Is the current message one we send? */
  isMyTurn(): boolean {
    const mp = this.getCurrentMessagePattern();
    if (!mp) return false;
    return (mp.direction === '->') === this.initiator;
  }

  /**
   * WriteMessage(payload) — spec Section 5.3
   * Process the next message pattern as sender.
   */
  async writeMessage(payload: Uint8Array = EMPTY): Promise<HandshakeResult> {
    if (this.isComplete()) throw new Error('Handshake already complete');
    const mp = this.pattern.messages[this.messageIndex];
    if (!((mp.direction === '->') === this.initiator)) {
      throw new Error('Not our turn to write');
    }

    this.clearLogs();
    const messageBuffer: Uint8Array[] = [];

    for (const token of mp.tokens) {
      await this.processWriteToken(token, messageBuffer);
    }

    // Encrypt and append payload
    const encPayload = await this.symmetricState.encryptAndHash(payload);
    messageBuffer.push(encPayload);

    this.messageIndex++;
    const message = concat(...messageBuffer);

    const result: HandshakeResult = {
      done: this.isComplete(),
      messageBuffer: message,
      stepLogs: this.getLogs()
    };

    if (this.isComplete()) {
      result.cipherStates = await this.symmetricState.split();
    }

    return result;
  }

  /**
   * ReadMessage(message) — spec Section 5.3
   * Process the next message pattern as receiver.
   */
  async readMessage(message: Uint8Array): Promise<HandshakeResult> {
    if (this.isComplete()) throw new Error('Handshake already complete');
    const mp = this.pattern.messages[this.messageIndex];
    if ((mp.direction === '->') === this.initiator) {
      throw new Error('Not our turn to read');
    }

    this.clearLogs();
    let offset = 0;

    for (const token of mp.tokens) {
      offset = await this.processReadToken(token, message, offset);
    }

    // Decrypt payload
    const encPayload = message.slice(offset);
    const payload = await this.symmetricState.decryptAndHash(encPayload);

    this.messageIndex++;

    const result: HandshakeResult = {
      done: this.isComplete(),
      payload,
      stepLogs: this.getLogs()
    };

    if (this.isComplete()) {
      result.cipherStates = await this.symmetricState.split();
    }

    return result;
  }

  private async processWriteToken(token: Token, messageBuffer: Uint8Array[]): Promise<void> {
    const log = (op: string, desc: string, details: Record<string, string>) => {
      this.symmetricState.logs.push({ operation: op, description: desc, details });
    };

    switch (token) {
      case 'e': {
        this.e = generateKeyPair();
        messageBuffer.push(this.e.publicKey);
        await this.symmetricState.mixHash(this.e.publicKey);
        // PSK mode: MixKey(e.public_key) per spec Section 9
        if (this.psk !== null) {
          await this.symmetricState.mixKey(this.e.publicKey);
        }
        log(`Token: e (write)`, 'Generated ephemeral key pair, sent public key', {
          ephemeralPub: toHex(this.e.publicKey)
        });
        break;
      }
      case 's': {
        if (!this.s) throw new Error('No local static key for "s" token');
        const ct = await this.symmetricState.encryptAndHash(this.s.publicKey);
        messageBuffer.push(ct);
        log(`Token: s (write)`, 'Encrypted and sent static public key', {
          staticPub: toHex(this.s.publicKey)
        });
        break;
      }
      case 'ee': {
        if (!this.e || !this.re) throw new Error('Missing keys for ee');
        const dhResult = dh(this.e, this.re);
        await this.symmetricState.mixKey(dhResult);
        log('Token: ee', 'DH(ephemeral, remote ephemeral)', {
          dhOutput: toHex(dhResult)
        });
        break;
      }
      case 'es': {
        if (this.initiator) {
          if (!this.e || !this.rs) throw new Error('Missing keys for es (initiator)');
          const dhResult = dh(this.e, this.rs);
          await this.symmetricState.mixKey(dhResult);
          log('Token: es', 'DH(local ephemeral, remote static)', {
            dhOutput: toHex(dhResult)
          });
        } else {
          if (!this.s || !this.re) throw new Error('Missing keys for es (responder)');
          const dhResult = dh(this.s, this.re);
          await this.symmetricState.mixKey(dhResult);
          log('Token: es', 'DH(local static, remote ephemeral)', {
            dhOutput: toHex(dhResult)
          });
        }
        break;
      }
      case 'se': {
        if (this.initiator) {
          if (!this.s || !this.re) throw new Error('Missing keys for se (initiator)');
          const dhResult = dh(this.s, this.re);
          await this.symmetricState.mixKey(dhResult);
          log('Token: se', 'DH(local static, remote ephemeral)', {
            dhOutput: toHex(dhResult)
          });
        } else {
          if (!this.e || !this.rs) throw new Error('Missing keys for se (responder)');
          const dhResult = dh(this.e, this.rs);
          await this.symmetricState.mixKey(dhResult);
          log('Token: se', 'DH(local ephemeral, remote static)', {
            dhOutput: toHex(dhResult)
          });
        }
        break;
      }
      case 'ss': {
        if (!this.s || !this.rs) throw new Error('Missing keys for ss');
        const dhResult = dh(this.s, this.rs);
        await this.symmetricState.mixKey(dhResult);
        log('Token: ss', 'DH(local static, remote static)', {
          dhOutput: toHex(dhResult)
        });
        break;
      }
      case 'psk': {
        if (!this.psk) throw new Error('No PSK available for psk token');
        await this.symmetricState.mixKeyAndHash(this.psk);
        log('Token: psk', 'Mixed pre-shared key into handshake state', {});
        break;
      }
    }
  }

  private async processReadToken(token: Token, message: Uint8Array, offset: number): Promise<number> {
    const log = (op: string, desc: string, details: Record<string, string>) => {
      this.symmetricState.logs.push({ operation: op, description: desc, details });
    };

    switch (token) {
      case 'e': {
        if (message.length < offset + DHLEN) throw new Error('Message too short for ephemeral key');
        this.re = message.slice(offset, offset + DHLEN);
        offset += DHLEN;
        await this.symmetricState.mixHash(this.re);
        // PSK mode: MixKey(re.public_key) per spec Section 9
        if (this.psk !== null) {
          await this.symmetricState.mixKey(this.re);
        }
        log('Token: e (read)', 'Received remote ephemeral public key', {
          remoteEphemeral: toHex(this.re)
        });
        break;
      }
      case 's': {
        const hasKey = this.symmetricState.cipher.hasKey();
        const len = hasKey ? DHLEN + 16 : DHLEN; // 16 byte AEAD tag
        if (message.length < offset + len) throw new Error('Message too short for static key');
        const temp = message.slice(offset, offset + len);
        offset += len;
        this.rs = await this.symmetricState.decryptAndHash(temp);
        log('Token: s (read)', 'Received and decrypted remote static public key', {
          remoteStatic: toHex(this.rs)
        });
        break;
      }
      case 'ee': {
        if (!this.e || !this.re) throw new Error('Missing keys for ee');
        const dhResult = dh(this.e, this.re);
        await this.symmetricState.mixKey(dhResult);
        log('Token: ee', 'DH(ephemeral, remote ephemeral)', {
          dhOutput: toHex(dhResult)
        });
        break;
      }
      case 'es': {
        if (this.initiator) {
          if (!this.e || !this.rs) throw new Error('Missing keys for es (initiator)');
          const dhResult = dh(this.e, this.rs);
          await this.symmetricState.mixKey(dhResult);
          log('Token: es', 'DH(local ephemeral, remote static)', {
            dhOutput: toHex(dhResult)
          });
        } else {
          if (!this.s || !this.re) throw new Error('Missing keys for es (responder)');
          const dhResult = dh(this.s, this.re);
          await this.symmetricState.mixKey(dhResult);
          log('Token: es', 'DH(local static, remote ephemeral)', {
            dhOutput: toHex(dhResult)
          });
        }
        break;
      }
      case 'se': {
        if (this.initiator) {
          if (!this.s || !this.re) throw new Error('Missing keys for se (initiator)');
          const dhResult = dh(this.s, this.re);
          await this.symmetricState.mixKey(dhResult);
          log('Token: se', 'DH(local static, remote ephemeral)', {
            dhOutput: toHex(dhResult)
          });
        } else {
          if (!this.e || !this.rs) throw new Error('Missing keys for se (responder)');
          const dhResult = dh(this.e, this.rs);
          await this.symmetricState.mixKey(dhResult);
          log('Token: se', 'DH(local ephemeral, remote static)', {
            dhOutput: toHex(dhResult)
          });
        }
        break;
      }
      case 'ss': {
        if (!this.s || !this.rs) throw new Error('Missing keys for ss');
        const dhResult = dh(this.s, this.rs);
        await this.symmetricState.mixKey(dhResult);
        log('Token: ss', 'DH(local static, remote static)', {
          dhOutput: toHex(dhResult)
        });
        break;
      }
      case 'psk': {
        if (!this.psk) throw new Error('No PSK available for psk token');
        await this.symmetricState.mixKeyAndHash(this.psk);
        log('Token: psk', 'Mixed pre-shared key into handshake state', {});
        break;
      }
    }
    return offset;
  }
}

/**
 * Run a full handshake between two parties.
 * Returns step-by-step logs, transport cipher states, and the handshake hash.
 */
export interface FullHandshakeResult {
  /** Logs per message (alternating initiator/responder) */
  messageLogs: { direction: string; tokens: Token[]; logs: StepLog[] }[];
  /** Initiator's transport cipher states [send, recv] */
  initiatorCiphers: [CipherState, CipherState];
  /** Responder's transport cipher states [send, recv] */
  responderCiphers: [CipherState, CipherState];
  /** Final handshake hash */
  handshakeHash: Uint8Array;
  /** Key pairs used */
  keys: {
    initiatorStatic: KeyPair | null;
    responderStatic: KeyPair | null;
    psk: Uint8Array | null;
  };
}

export async function runFullHandshake(
  pattern: HandshakePattern,
  options?: {
    initiatorStatic?: KeyPair | null;
    responderStatic?: KeyPair | null;
    psk?: Uint8Array | null;
  }
): Promise<FullHandshakeResult> {
  const opts = options ?? {};
  const patternName = pattern.name;

  // Determine which keys are needed
  const needsInitiatorStatic = hasStaticKeyRequirement(pattern, true);
  const needsResponderStatic = hasStaticKeyRequirement(pattern, false);

  const iStatic = needsInitiatorStatic ? (opts.initiatorStatic ?? generateKeyPair()) : null;
  const rStatic = needsResponderStatic ? (opts.responderStatic ?? generateKeyPair()) : null;
  const psk = opts.psk ?? (patternName.includes('psk') ? crypto.getRandomValues(new Uint8Array(32)) : null);

  // Determine which remote static keys are known in advance (pre-messages)
  let initiatorKnowsRS: Uint8Array | null = null;
  let responderKnowsRS: Uint8Array | null = null;

  for (const pm of pattern.preMessages) {
    if (pm.direction === '<-' && pm.tokens.includes('s') && rStatic) {
      initiatorKnowsRS = rStatic.publicKey;
    }
    if (pm.direction === '->' && pm.tokens.includes('s') && iStatic) {
      responderKnowsRS = iStatic.publicKey;
    }
  }

  const initiator = new HandshakeState();
  await initiator.initialize(pattern, true, EMPTY, iStatic, null, initiatorKnowsRS, null, psk);

  const responder = new HandshakeState();
  await responder.initialize(pattern, false, EMPTY, rStatic, null, responderKnowsRS, null, psk);

  const messageLogs: FullHandshakeResult['messageLogs'] = [];
  let iCiphers: [CipherState, CipherState] | null = null;
  let rCiphers: [CipherState, CipherState] | null = null;

  for (let i = 0; i < pattern.messages.length; i++) {
    const mp = pattern.messages[i];
    const isInitiatorSending = mp.direction === '->';

    if (isInitiatorSending) {
      const writeResult = await initiator.writeMessage(EMPTY);
      const readResult = await responder.readMessage(writeResult.messageBuffer!);
      messageLogs.push({
        direction: mp.direction,
        tokens: mp.tokens,
        logs: [...writeResult.stepLogs, ...readResult.stepLogs]
      });
      if (writeResult.done) iCiphers = writeResult.cipherStates!;
      if (readResult.done) rCiphers = readResult.cipherStates!;
    } else {
      const writeResult = await responder.writeMessage(EMPTY);
      const readResult = await initiator.readMessage(writeResult.messageBuffer!);
      messageLogs.push({
        direction: mp.direction,
        tokens: mp.tokens,
        logs: [...writeResult.stepLogs, ...readResult.stepLogs]
      });
      if (writeResult.done) rCiphers = writeResult.cipherStates!;
      if (readResult.done) iCiphers = readResult.cipherStates!;
    }
  }

  return {
    messageLogs,
    initiatorCiphers: iCiphers!,
    responderCiphers: rCiphers!,
    handshakeHash: initiator.getHandshakeHash(),
    keys: {
      initiatorStatic: iStatic,
      responderStatic: rStatic,
      psk
    }
  };
}

function hasStaticKeyRequirement(pattern: HandshakePattern, isInitiator: boolean): boolean {
  // Check pre-messages
  for (const pm of pattern.preMessages) {
    const isSender = (pm.direction === '->') === isInitiator;
    if (isSender && pm.tokens.includes('s')) return true;
  }
  // Check message tokens
  for (const mp of pattern.messages) {
    const isSender = (mp.direction === '->') === isInitiator;
    if (isSender && mp.tokens.includes('s')) return true;
    // Check DH tokens that need our static key
    if (isSender) {
      if (mp.tokens.includes('se') && isInitiator) return true;
      if (mp.tokens.includes('es') && !isInitiator) return true;
      if (mp.tokens.includes('ss')) return true;
    } else {
      if (mp.tokens.includes('se') && !isInitiator) return true;
      if (mp.tokens.includes('es') && isInitiator) return true;
      if (mp.tokens.includes('ss')) return true;
    }
  }
  // Fallback: check pattern name convention
  // First letter = initiator role (K=known, I=immediate, X=transmitted, N=none)
  // Second letter = responder role
  const first = pattern.name[0];
  const second = pattern.name.length > 1 ? pattern.name[1] : '';
  if (isInitiator && (first === 'K' || first === 'I' || first === 'X')) return true;
  if (!isInitiator && (second === 'K' || second === 'X')) return true;
  return false;
}
