/**
 * Known-answer tests for the full Noise handshake against published reference
 * vectors from the noise-c test suite (github.com/rweather/noise-c,
 * tests/vector/noise-c-basic.txt). These vectors are also reproduced verbatim
 * by the Rust `snow` and Haskell `cacophony` implementations, so matching them
 * byte-for-byte is strong cross-implementation evidence of correctness.
 *
 * The vectors fix both parties' static and ephemeral keys, so we inject the
 * ephemerals via HandshakeState.setFixedEphemerals (a test-only hook) to make
 * the handshake fully deterministic. We assert on:
 *   - every handshake message's exact wire bytes,
 *   - the final handshake hash (channel binding), and
 *   - the post-Split transport ciphertexts.
 *
 * These KATs are what caught the AES-GCM nonce being encoded little-endian
 * instead of big-endian: with the wrong endianness, message 0 (no key yet) and
 * the first keyed message (n=0) still match, but everything from n=1 onward
 * diverges — e.g. Noise_XX message 3 and all transport messages.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { x25519 } from '@noble/curves/ed25519';
import { HandshakeState, CipherState } from '../src/noise';
import { PATTERNS } from '../src/patterns';
import { fromHex, toHex, KeyPair, EMPTY } from '../src/crypto';

interface VectorMessage { payload: string; ciphertext: string; }
interface Vector {
  pattern: string;
  init_prologue: string;
  init_static: string | null;
  init_ephemeral: string;
  resp_static: string | null;
  resp_ephemeral: string;
  handshake_hash: string;
  messages: VectorMessage[];
}

const vectors: Record<string, Vector> = JSON.parse(
  readFileSync(fileURLToPath(new URL('./noise-c-vectors.json', import.meta.url)), 'utf8'),
);

function keyPairFromPrivate(hex: string): KeyPair {
  const priv = fromHex(hex);
  return { privateKey: priv, publicKey: new Uint8Array(x25519.getPublicKey(priv)) };
}

async function runVector(vec: Vector) {
  const pattern = PATTERNS[vec.pattern].pattern;
  const iStatic = vec.init_static ? keyPairFromPrivate(vec.init_static) : null;
  const rStatic = vec.resp_static ? keyPairFromPrivate(vec.resp_static) : null;
  const iEph = keyPairFromPrivate(vec.init_ephemeral);
  const rEph = keyPairFromPrivate(vec.resp_ephemeral);
  const prologue = fromHex(vec.init_prologue);

  // Pre-message known static keys (e.g. IK/KK where the responder static is
  // learned out of band before message 1).
  let initiatorKnowsRS: Uint8Array | null = null;
  let responderKnowsRS: Uint8Array | null = null;
  for (const pm of pattern.preMessages) {
    if (pm.direction === '<-' && pm.tokens.includes('s') && rStatic) initiatorKnowsRS = rStatic.publicKey;
    if (pm.direction === '->' && pm.tokens.includes('s') && iStatic) responderKnowsRS = iStatic.publicKey;
  }

  const initiator = new HandshakeState();
  await initiator.initialize(pattern, true, prologue, iStatic, null, initiatorKnowsRS, null, null);
  initiator.setFixedEphemerals(iEph);

  const responder = new HandshakeState();
  await responder.initialize(pattern, false, prologue, rStatic, null, responderKnowsRS, null, null);
  responder.setFixedEphemerals(rEph);

  const nHandshake = pattern.messages.length;
  let iCiphers: [CipherState, CipherState] | undefined;
  let rCiphers: [CipherState, CipherState] | undefined;

  const wireMatches: boolean[] = [];
  for (let i = 0; i < nHandshake; i++) {
    const initiatorSends = i % 2 === 0;
    const sender = initiatorSends ? initiator : responder;
    const receiver = initiatorSends ? responder : initiator;
    const payload = fromHex(vec.messages[i].payload);

    const w = await sender.writeMessage(payload);
    wireMatches.push(toHex(w.messageBuffer!) === vec.messages[i].ciphertext);

    const r = await receiver.readMessage(w.messageBuffer!);
    // The receiver must recover the exact payload.
    expect(toHex(r.payload!)).toBe(vec.messages[i].payload);

    if (w.done) (initiatorSends ? (iCiphers = w.cipherStates) : (rCiphers = w.cipherStates));
    if (r.done) (initiatorSends ? (rCiphers = r.cipherStates) : (iCiphers = r.cipherStates));
  }

  // Transport messages (any messages beyond the handshake length) alternate
  // initiator -> responder, responder -> initiator, using the Split() ciphers.
  const transportMatches: boolean[] = [];
  for (let i = nHandshake; i < vec.messages.length; i++) {
    const initiatorSends = i % 2 === 0;
    // Split() returns [c1 = initiator->responder, c2 = responder->initiator]
    // for BOTH parties in the same order. So the initiator sends on index 0 and
    // the responder sends on index 1.
    const sendCipher = initiatorSends ? iCiphers![0] : rCiphers![1];
    const ct = await sendCipher.encryptWithAd(EMPTY, fromHex(vec.messages[i].payload));
    transportMatches.push(toHex(ct) === vec.messages[i].ciphertext);
  }

  return {
    wireMatches,
    transportMatches,
    handshakeHash: toHex(initiator.getHandshakeHash()),
    initiatorHash: toHex(initiator.getHandshakeHash()),
    responderHash: toHex(responder.getHandshakeHash()),
  };
}

describe('Noise handshake known-answer tests (noise-c vectors)', () => {
  for (const [name, vec] of Object.entries(vectors)) {
    describe(name, () => {
      it('produces the exact handshake message wire bytes', async () => {
        const { wireMatches } = await runVector(vec);
        // Assert each message individually for readable failures.
        wireMatches.forEach((ok, i) => {
          expect(ok, `handshake message ${i} wire bytes must match the vector`).toBe(true);
        });
      });

      it('derives the published handshake hash (channel binding)', async () => {
        const { handshakeHash, initiatorHash, responderHash } = await runVector(vec);
        expect(handshakeHash).toBe(vec.handshake_hash);
        // Both parties must agree on the channel binding.
        expect(initiatorHash).toBe(responderHash);
      });

      it('produces the exact transport ciphertexts after Split()', async () => {
        const { transportMatches } = await runVector(vec);
        transportMatches.forEach((ok, i) => {
          expect(ok, `transport message ${i} must match the vector`).toBe(true);
        });
      });
    });
  }
});
