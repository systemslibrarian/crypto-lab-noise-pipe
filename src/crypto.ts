/**
 * Cryptographic primitives for Noise Protocol Framework.
 * Uses @noble/curves for X25519 and WebCrypto for AES-256-GCM and HKDF-SHA-256.
 * Reference: Noise Protocol Framework, Revision 34 — Section 4
 * https://noiseprotocol.org/noise.html
 */

import { x25519 } from '@noble/curves/ed25519';

// ----- X25519 (Curve25519 DH) -----

export interface KeyPair {
  privateKey: Uint8Array; // 32 bytes
  publicKey: Uint8Array;  // 32 bytes
}

/** Generate a new X25519 key pair. */
export function generateKeyPair(): KeyPair {
  const privateKey = new Uint8Array(32);
  crypto.getRandomValues(privateKey);
  const publicKey = x25519.getPublicKey(privateKey);
  return { privateKey, publicKey: new Uint8Array(publicKey) };
}

/** Perform X25519 Diffie-Hellman. */
export function dh(keyPair: KeyPair, publicKey: Uint8Array): Uint8Array {
  return new Uint8Array(x25519.getSharedSecret(keyPair.privateKey, publicKey));
}

/** X25519 DH output length */
export const DHLEN = 32;

// ----- Buffer Safety -----
// Uint8Array.buffer may reference a larger ArrayBuffer if the array is a slice.
// Always copy to a fresh buffer for WebCrypto APIs.

function toBuffer(arr: Uint8Array): ArrayBuffer {
  return arr.buffer.byteLength === arr.byteLength
    ? arr.buffer as ArrayBuffer
    : arr.slice().buffer as ArrayBuffer;
}

// ----- HKDF-SHA-256 (RFC 5869) -----
// Noise spec Section 4: HKDF(chaining_key, input_key_material, num_outputs)

async function hmacSha256(key: Uint8Array, data: Uint8Array): Promise<Uint8Array> {
  const cryptoKey = await crypto.subtle.importKey(
    'raw', toBuffer(key), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
  );
  const sig = await crypto.subtle.sign('HMAC', cryptoKey, toBuffer(data));
  return new Uint8Array(sig);
}

/**
 * HKDF per Noise spec Section 4.3:
 * HKDF(chaining_key, input_key_material, num_outputs)
 * Returns 2 or 3 outputs of 32 bytes each.
 */
export async function hkdf(
  chainingKey: Uint8Array,
  inputKeyMaterial: Uint8Array,
  numOutputs: 2 | 3
): Promise<Uint8Array[]> {
  const tempKey = await hmacSha256(chainingKey, inputKeyMaterial);
  const output1 = await hmacSha256(tempKey, new Uint8Array([1]));
  const output2 = await hmacSha256(tempKey, concat(output1, new Uint8Array([2])));
  if (numOutputs === 2) return [output1, output2];
  const output3 = await hmacSha256(tempKey, concat(output2, new Uint8Array([3])));
  return [output1, output2, output3];
}

// ----- SHA-256 -----

export async function sha256(data: Uint8Array): Promise<Uint8Array> {
  const hash = await crypto.subtle.digest('SHA-256', toBuffer(data));
  return new Uint8Array(hash);
}

// ----- AES-256-GCM -----

const NONCE_LEN = 12; // 96-bit nonce for AES-GCM

/**
 * Build the 12-byte AES-GCM nonce for Noise counter `n`.
 *
 * Noise spec Section 12.3 (AESGCM): "The 96-bit nonce is formed by encoding
 * 32 bits of zeros followed by big-endian encoding of n." (ChaChaPoly, by
 * contrast, uses little-endian — this is a cipher-specific detail.) So the
 * layout is: 4 zero bytes || 8-byte big-endian counter. Encoding `n` little-
 * endian instead only diverges from the standard once n >= 1, which is exactly
 * when known-answer vectors start to disagree.
 */
export function nonceFromCounter(n: number): Uint8Array {
  const nonce = new Uint8Array(NONCE_LEN);
  const view = new DataView(nonce.buffer);
  // Big-endian 64-bit counter in bytes 4..11 (bytes 0..3 stay zero).
  view.setUint32(4, Math.floor(n / 0x100000000) & 0xFFFFFFFF, false); // high 32 bits
  view.setUint32(8, n & 0xFFFFFFFF, false); // low 32 bits
  return nonce;
}

/** Encrypt plaintext with AES-256-GCM. Returns ciphertext || 16-byte tag. */
export async function aesGcmEncrypt(
  key: Uint8Array,
  nonce: Uint8Array,
  plaintext: Uint8Array,
  ad: Uint8Array
): Promise<Uint8Array> {
  const cryptoKey = await crypto.subtle.importKey(
    'raw', toBuffer(key), { name: 'AES-GCM' }, false, ['encrypt']
  );
  const ct = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: toBuffer(nonce), additionalData: toBuffer(ad), tagLength: 128 },
    cryptoKey,
    toBuffer(plaintext)
  );
  return new Uint8Array(ct);
}

/** Decrypt ciphertext (with appended 16-byte tag) with AES-256-GCM. */
export async function aesGcmDecrypt(
  key: Uint8Array,
  nonce: Uint8Array,
  ciphertext: Uint8Array,
  ad: Uint8Array
): Promise<Uint8Array> {
  const cryptoKey = await crypto.subtle.importKey(
    'raw', toBuffer(key), { name: 'AES-GCM' }, false, ['decrypt']
  );
  const pt = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: toBuffer(nonce), additionalData: toBuffer(ad), tagLength: 128 },
    cryptoKey,
    toBuffer(ciphertext)
  );
  return new Uint8Array(pt);
}

// ----- Utilities -----

export function concat(...arrays: Uint8Array[]): Uint8Array {
  const totalLen = arrays.reduce((sum, a) => sum + a.length, 0);
  const result = new Uint8Array(totalLen);
  let offset = 0;
  for (const a of arrays) {
    result.set(a, offset);
    offset += a.length;
  }
  return result;
}

export function toHex(bytes: Uint8Array): string {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

export function fromHex(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  }
  return bytes;
}

/** Constant-time comparison */
export function equal(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff === 0;
}

/** Empty byte array (used as empty payload or empty key) */
export const EMPTY = new Uint8Array(0);
