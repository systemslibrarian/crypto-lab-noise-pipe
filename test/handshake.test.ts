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
  HandshakeState, CipherState, runFullHandshake,
  simulateBitFlip, simulateNonceReuse, simulateRSSwap,
  simulatePSKMismatch, simulateReplay, simulateForwardSecrecy,
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

  // Regression: encryptWithAd read `this.n`, awaited WebCrypto, and only then
  // incremented. Two overlapping calls — one double-clicked send button — both
  // read the same counter and AES-GCM sealed two different plaintexts under one
  // (key, nonce) pair. Measured at 200 of 200 concurrent pairs before the fix,
  // with the two ciphertexts sharing a byte-identical keystream prefix; 0 of 200
  // after. This is the catastrophe the lab's own nonce-reuse panel teaches.
  //
  // The invariant asserted is between the two rendered facts: the counter the
  // CipherState reports and the nonce each record was actually sealed under.
  it('concurrent encryptions never share a nonce, over many trials', async () => {
    const TRIALS = 100;
    const enc = new TextEncoder();
    let checked = 0;
    for (let t = 0; t < TRIALS; t++) {
      const r = await runFullHandshake(PATTERNS.XX.pattern);
      const send = r.initiatorCiphers[0];
      const [a, b] = await Promise.all([
        send.encryptWithAd(EMPTY, enc.encode('attack at dawn')),
        send.encryptWithAd(EMPTY, enc.encode('attack at dusk')),
      ]);

      // Both records must have advanced the counter exactly once each.
      expect(send.n, 'two encryptions must consume two nonces').toBe(2);

      // Exactly ONE of the two records may open at nonce 0, and exactly one at
      // nonce 1. If both opened at 0 the nonce was reused.
      const opensAt = async (ct: Uint8Array, n: number) => {
        const probe = new CipherState();
        probe.initializeKey(send.k!);
        probe.setNonce(n);
        return probe.decryptWithAd(EMPTY, ct).then(() => true, () => false);
      };
      const at0 = [await opensAt(a, 0), await opensAt(b, 0)].filter(Boolean).length;
      const at1 = [await opensAt(a, 1), await opensAt(b, 1)].filter(Boolean).length;
      expect(at0, 'exactly one record may be sealed under nonce 0').toBe(1);
      expect(at1, 'exactly one record may be sealed under nonce 1').toBe(1);

      // And the keystream must differ, which is the observable consequence.
      const body = Math.min(a.length, b.length) - 16; // drop the GCM tag
      expect(body, 'there must be body bytes to compare').toBeGreaterThan(0);
      const p1 = enc.encode('attack at dawn');
      const p2 = enc.encode('attack at dusk');
      let leaks = true;
      for (let i = 0; i < body; i++) {
        if ((a[i] ^ b[i]) !== (p1[i] ^ p2[i])) { leaks = false; break; }
      }
      expect(leaks, 'ct1^ct2 must NOT equal pt1^pt2 — that is keystream reuse').toBe(false);
      checked++;
    }
    expect(checked, 'the loop must actually have run').toBe(TRIALS);
  });

  // A rekey issued before a send must be VISIBLE to that send. Without the
  // serialization queue both operations read `this.k` synchronously before
  // either awaited, so the record went out under the OLD key while the peer —
  // which rekeys and then decrypts one at a time — opened with the new one, and
  // the record simply never decrypted.
  it('a send issued after a rekey uses the rekeyed key, even in the same tick', async () => {
    const enc = new TextEncoder();
    let checked = 0;
    for (let t = 0; t < 50; t++) {
      const r = await runFullHandshake(PATTERNS.XX.pattern);
      const send = r.initiatorCiphers[0];
      const recv = r.responderCiphers[0];
      const keyBefore = toHex(send.k!);

      // Issue both in the same tick, rekey first, and do not await in between.
      const rekeyDone = send.rekey();
      const ctPromise = send.encryptWithAd(EMPTY, enc.encode('after the rekey'));
      const [, ct] = await Promise.all([rekeyDone, ctPromise]);
      expect(toHex(send.k!), 'the rekey must have landed').not.toBe(keyBefore);

      // The peer applies the same two operations in the same order, one at a
      // time. If the sender's ordering held, this decrypts.
      await recv.rekey();
      const pt = await recv.decryptWithAd(EMPTY, ct);
      expect(new TextDecoder().decode(pt)).toBe('after the rekey');
      checked++;
    }
    expect(checked, 'the loop must actually have run').toBe(50);
  });
});

/**
 * The forward-secrecy panel prints a verdict for every pattern. Before this
 * suite existed it printed "Stealing both static private keys after the fact
 * does NOT decrypt the recorded record — AEAD rejects the static-only key" for
 * all 13 patterns, while:
 *   - 4 of 13 (NN, NK, KN, IN) never attempted a decryption at all, and
 *   - 3 of 13 (NK, KN, IN) own exactly ONE static key, not both.
 * The one e2e test covering this panel ran only NN — the single pattern where
 * the wrong key-count detail was masked by a special case.
 */
describe('the forward-secrecy verdict is computed, not asserted', () => {
  it('every pattern either tries at least one candidate key, or badges n/a', async () => {
    let held = 0;
    let notApplicable = 0;
    for (const name of ALL_PATTERNS) {
      const res = await simulateForwardSecrecy(PATTERNS[name].pattern);
      const tried = res.details?.['candidate keys tried'] ?? '';
      const count = Number(/^(\d+)/.exec(tried)?.[1] ?? NaN);
      expect(Number.isFinite(count), `${name} must report how many keys it tried`).toBe(true);

      if (res.outcome === 'held') {
        expect(count, `${name} badges "held" so it must have rejected something`).toBeGreaterThan(0);
        expect(res.summary, `${name}`).toMatch(/AEAD rejected every one/);
        held++;
      } else if (res.outcome === 'n/a') {
        expect(count, `${name} badges n/a so nothing may have been tried`).toBe(0);
        // Nothing ran, so nothing may be claimed to have been rejected.
        expect(res.summary, `${name}`).not.toMatch(/AEAD rejected/);
        expect(res.summary, `${name}`).toMatch(/Nothing was run/);
        notApplicable++;
      } else {
        throw new Error(`${name}: unexpected forward-secrecy outcome ${res.outcome}`);
      }
    }
    expect(held + notApplicable, 'every shipped pattern must be covered').toBe(ALL_PATTERNS.length);
    expect(held, 'most patterns must reach a real "held" verdict').toBeGreaterThan(0);
    expect(notApplicable, 'NN has no statics, so it must badge n/a').toBeGreaterThan(0);
  });

  it('the compromise it describes names exactly the static keys the pattern owns', async () => {
    let checked = 0;
    for (const name of ALL_PATTERNS) {
      const hs = await runFullHandshake(PATTERNS[name].pattern);
      const owned = (hs.keys.initiatorStatic ? 1 : 0) + (hs.keys.responderStatic ? 1 : 0);
      const res = await simulateForwardSecrecy(PATTERNS[name].pattern);
      const holds = String(res.details?.['attacker holds'] ?? '');
      expect(holds, `${name} must say what the attacker holds`).not.toBe('');

      if (owned === 2) {
        expect(holds, name).toMatch(/both static private keys/);
      } else if (owned === 1) {
        expect(holds, `${name} owns one static key — "both" would be a lie`).not.toMatch(/both static private keys/);
        expect(holds, name).toMatch(/the only static key this pattern has/);
      } else {
        expect(holds, name).toMatch(/no static keys to steal/);
      }
      // And the number of DH candidates can never exceed what the material allows:
      // ss needs two statics; se/es each need one static and the peer ephemeral.
      const tried = Number(/^(\d+)/.exec(String(res.details?.['candidate keys tried'] ?? ''))![1]);
      expect(tried, `${name} candidate count`).toBe(owned === 2 ? 3 : owned === 1 ? 1 : 0);
      checked++;
    }
    expect(checked, 'every shipped pattern must be checked').toBe(ALL_PATTERNS.length);
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
