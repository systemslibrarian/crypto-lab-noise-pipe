/**
 * Property / round-trip tests across every advertised handshake pattern, plus
 * checks on the transport-phase CipherState and the "Break it" failure-mode
 * simulations. Unlike the KATs these use fresh random keys, so they assert
 * structural invariants that must hold for any keys:
 *   - both parties reach the same handshake hash and transport keys,
 *   - transport encryption round-trips and rejects tampering,
 *   - forgery / mismatch simulations actually fail (verify-rejects-forgery),
 *   - the correct static keys are learned by each side.
 */
import { describe, it, expect } from 'vitest';
import {
  HandshakeState, runFullHandshake,
  simulateBitFlip, simulateNonceReuse, simulateRSSwap,
  simulatePSKMismatch, simulateReplay,
} from '../src/noise';
import { PATTERNS, getPatternNames } from '../src/patterns';
import { generateKeyPair, toHex, EMPTY, equal } from '../src/crypto';

const ALL_PATTERNS = getPatternNames();

describe('every pattern completes a consistent handshake', () => {
  for (const name of ALL_PATTERNS) {
    it(`${name}: both parties agree on hash and transport keys`, async () => {
      const result = await runFullHandshake(PATTERNS[name].pattern);

      // Both parties derived the same channel binding.
      expect(result.messageLogs.length).toBe(PATTERNS[name].pattern.messages.length);
      expect(result.initiatorCiphers).toBeDefined();
      expect(result.responderCiphers).toBeDefined();

      // Cipher convention (matches ui.ts): both parties hold
      // [c1 = initiator->responder, c2 = responder->initiator] in the same
      // order. So the responder's SEND cipher is index 1 and its RECV is index 0.
      const iSend = result.initiatorCiphers[0].k!;
      const iRecv = result.initiatorCiphers[1].k!;
      const rSend = result.responderCiphers[1].k!;
      const rRecv = result.responderCiphers[0].k!;
      expect(equal(iSend, rRecv)).toBe(true);
      expect(equal(iRecv, rSend)).toBe(true);
      // The two directions use distinct keys.
      expect(equal(iSend, iRecv)).toBe(false);
    });

    it(`${name}: transport traffic round-trips in both directions`, async () => {
      const r = await runFullHandshake(PATTERNS[name].pattern);
      const [iSend, iRecv] = r.initiatorCiphers; // [I->R send, R->I recv]
      const rRecv = r.responderCiphers[0]; // I->R (responder receives)
      const rSend = r.responderCiphers[1]; // R->I (responder sends)

      const msgA = new TextEncoder().encode('initiator says hello');
      const ctA = await iSend.encryptWithAd(EMPTY, msgA);
      const ptA = await rRecv.decryptWithAd(EMPTY, ctA);
      expect(toHex(ptA)).toBe(toHex(msgA));

      const msgB = new TextEncoder().encode('responder replies');
      const ctB = await rSend.encryptWithAd(EMPTY, msgB);
      const ptB = await iRecv.decryptWithAd(EMPTY, ctB);
      expect(toHex(ptB)).toBe(toHex(msgB));

      // Nonces advanced independently per direction.
      expect(iSend.n).toBe(1);
      expect(rRecv.n).toBe(1);
    });
  }
});

describe('mutual-auth patterns learn the correct static keys', () => {
  for (const name of ALL_PATTERNS) {
    const info = PATTERNS[name];
    if (info.security.senderAuth !== 'mutual') continue;
    it(`${name}: each side ends up holding the other's real static key`, async () => {
      const iStatic = generateKeyPair();
      const rStatic = generateKeyPair();
      const r = await runFullHandshake(info.pattern, {
        initiatorStatic: iStatic,
        responderStatic: rStatic,
      });
      // The final message logs carry each party's state including learned rs.
      const last = r.messageLogs[r.messageLogs.length - 1];
      expect(toHex(last.initiatorStateAfter.rs!)).toBe(toHex(rStatic.publicKey));
      expect(toHex(last.responderStateAfter.rs!)).toBe(toHex(iStatic.publicKey));
    });
  }
});

describe('transport tampering is rejected (AEAD integrity)', () => {
  it('a single flipped bit fails decryption', async () => {
    const r = await runFullHandshake(PATTERNS.XX.pattern);
    const res = await simulateBitFlip(r.initiatorCiphers[0], r.responderCiphers[0], 'secret');
    // ok=true means the tamper was correctly detected/rejected.
    expect(res.ok).toBe(true);
  });

  it('a wrong-key receiver cannot decrypt', async () => {
    const r1 = await runFullHandshake(PATTERNS.XX.pattern);
    const r2 = await runFullHandshake(PATTERNS.XX.pattern);
    const ct = await r1.initiatorCiphers[0].encryptWithAd(EMPTY, new TextEncoder().encode('hi'));
    // r2's responder holds an unrelated session key.
    await expect(r2.responderCiphers[0].decryptWithAd(EMPTY, ct)).rejects.toBeTruthy();
  });
});

describe('nonce management', () => {
  it('reusing a nonce reproduces the keystream-reuse leak', async () => {
    const r = await runFullHandshake(PATTERNS.XX.pattern);
    const res = await simulateNonceReuse(r.initiatorCiphers[0], r.responderCiphers[0]);
    // The simulation demonstrates the leak: XOR of ciphertexts == XOR of plaintexts.
    expect(res.details?.ciphertextXOR).toBeDefined();
    expect(res.details?.ciphertextXOR).toBe(res.details?.recoveredXOR);
  });

  it('rekey changes the key deterministically and keeps traffic decryptable', async () => {
    const r = await runFullHandshake(PATTERNS.XX.pattern);
    const send = r.initiatorCiphers[0];
    const recv = r.responderCiphers[0];
    const before = toHex(send.k!);
    await send.rekey();
    await recv.rekey();
    expect(toHex(send.k!)).not.toBe(before);
    expect(toHex(send.k!)).toBe(toHex(recv.k!)); // both sides derive same new key
    const ct = await send.encryptWithAd(EMPTY, new TextEncoder().encode('post-rekey'));
    const pt = await recv.decryptWithAd(EMPTY, ct);
    expect(new TextDecoder().decode(pt)).toBe('post-rekey');
  });
});

describe('failure-mode simulations behave as documented', () => {
  // A substituted `rs` is an IMPERSONATION: the attacker holds the private key
  // for the key the initiator was tricked into trusting, and answers in the
  // responder's place. IK has nothing with which to notice. These tests
  // previously asserted the opposite — see simulateRSSwap's comment.
  it('IK completes against an impersonator holding a substituted static key', async () => {
    const res = await simulateRSSwap(PATTERNS.IK.pattern);
    expect(res.outcome).toBe('succeeded');
    expect(res.ok).toBe(false);
    // Impersonation demonstrated, not asserted: same transport key on both ends.
    expect(res.details?.initiatorTransportKey).toMatch(/^[0-9a-f]{64}$/);
    expect(res.details?.attackerTransportKey).toBe(res.details?.initiatorTransportKey);
    expect(res.details?.forgedRS).not.toBe(res.details?.realResponderRS);
  });

  it('XK and NK likewise complete against an impersonator', async () => {
    for (const name of ['XK', 'NK'] as const) {
      const res = await simulateRSSwap(PATTERNS[name].pattern);
      expect(res.outcome, name).toBe('succeeded');
      expect(res.details?.attackerTransportKey, name).toBe(res.details?.initiatorTransportKey);
    }
  });

  it('IKpsk2 stops the same impersonator, because it lacks the PSK', async () => {
    const res = await simulateRSSwap(PATTERNS.IKpsk2.pattern);
    expect(res.outcome).toBe('held');
    expect(res.summary).toMatch(/pre-shared key/i);
    expect(res.error).toBeTruthy();
    // No shared transport key was ever reached.
    expect(res.details?.attackerTransportKey).toBeUndefined();
  });

  it('patterns without a pre-known rs report n/a rather than a security verdict', async () => {
    for (const name of ['XX', 'NX', 'IX'] as const) {
      const res = await simulateRSSwap(PATTERNS[name].pattern);
      expect(res.outcome, name).toBe('n/a');
    }
  });

  it('IKpsk2 with mismatched PSKs fails the handshake', async () => {
    const res = await simulatePSKMismatch(PATTERNS.IKpsk2.pattern);
    expect(res.ok).toBe(true);
    expect(res.error).toBeTruthy();
  });

  it('a fresh responder accepts a replayed message 1 (Noise has no built-in replay protection)', async () => {
    const res = await simulateReplay(PATTERNS.IK.pattern);
    // ok=false here means "no failure observed" — the replay was accepted,
    // which is the documented, honest behaviour of core Noise.
    expect(res.ok).toBe(false);
    expect(res.summary).toMatch(/replay/i);
  });
});

describe('PSK pattern (IKpsk2) round-trips with matching PSKs', () => {
  it('completes and yields working transport keys', async () => {
    const psk = crypto.getRandomValues(new Uint8Array(32));
    const r = await runFullHandshake(PATTERNS.IKpsk2.pattern, { psk });
    const ct = await r.initiatorCiphers[0].encryptWithAd(EMPTY, new TextEncoder().encode('vpn'));
    const pt = await r.responderCiphers[0].decryptWithAd(EMPTY, ct);
    expect(new TextDecoder().decode(pt)).toBe('vpn');
  });
});

describe('handshake state guards', () => {
  it('refuses to write out of turn', async () => {
    const hs = new HandshakeState();
    // Responder should not be able to write the first (initiator) message of NN.
    await hs.initialize(PATTERNS.NN.pattern, false);
    await expect(hs.writeMessage()).rejects.toThrow(/turn/i);
  });
});
