# crypto-lab-noise-pipe

> `Noise Protocol` · `X25519` · `AES-256-GCM` · `HKDF-SHA-256`

Interactive browser-based demonstration of the **Noise Protocol Framework** — a framework for building secure channel protocols from composable handshake patterns.

**[Live Demo →](https://systemslibrarian.github.io/crypto-lab-noise-pipe/)**

Based on the [Noise Protocol Framework, Revision 34](https://noiseprotocol.org/noise.html).

---

## Overview

Noise is a framework for constructing cryptographic handshake protocols. Instead of negotiating cipher suites like TLS, you choose a **handshake pattern** — a fixed sequence of Diffie-Hellman operations — and the security properties follow deterministically.

This demo lets you:

1. **Select a handshake pattern** (NN, NK, NX, KN, KK, KX, XN, XK, XX, IX, IK, IKpsk2) and see its message flow and security properties
2. **Step through the handshake** message by message, with real X25519 DH outputs, chaining key evolution, and handshake hash updates
3. **Encrypt and decrypt messages** using the derived transport keys (AES-256-GCM with nonce tracking)
4. **Compare patterns** side-by-side: NN vs XX vs IK vs IKpsk2
5. **Deep dive into WireGuard** — how IKpsk2 maps to WireGuard's handshake messages

All cryptographic operations are **real** — X25519 via `@noble/curves`, AES-256-GCM and HKDF-SHA-256 via WebCrypto. No simulated math.

## Patterns Covered

| Pattern | Auth       | Forward Secrecy | Identity Hiding | Real-World Use |
|---------|------------|-----------------|-----------------|----------------|
| NN      | None       | Full            | Both            | Anonymous tunneling |
| NK      | None       | Full            | Initiator       | Known server connection |
| NX      | None       | Full            | Initiator       | TOFU server auth |
| KN      | One-way    | Full            | None            | Device-to-server |
| KK      | Mutual     | Full            | None            | Peer-to-peer w/ pre-shared keys |
| KX      | Mutual     | Full            | Responder       | Authenticated session w/ privacy |
| XN      | One-way    | Full            | Initiator       | Client → relay |
| XK      | Mutual     | Full            | Initiator       | Signal-like flows |
| XX      | Mutual     | Full            | Both            | libp2p secure channel |
| IX      | Mutual     | Full            | None            | Fast mutual auth |
| IK      | Mutual     | Full            | Initiator       | Low-latency encrypted channels |
| IKpsk2  | Mutual     | Full            | Initiator       | **WireGuard VPN** |

## Primitives Used

- **Noise Protocol Framework** — handshake pattern composition (Rev 34)
- **X25519** (Curve25519 Diffie-Hellman) — ephemeral and static key exchange
- **AES-256-GCM** — authenticated encryption for transport
- **HKDF-SHA-256** — key derivation via chaining key and handshake hash
- **SHA-256** — handshake transcript hashing

## Running Locally

```bash
git clone https://github.com/systemslibrarian/crypto-lab-noise-pipe.git
cd crypto-lab-noise-pipe
npm install
npm run dev
```

Open `http://localhost:5173/crypto-lab-noise-pipe/` in your browser.

### Build for production

```bash
npm run build
```

### Deploy to GitHub Pages

```bash
npm run deploy
```

## Security Notes

> **Pattern selection determines security properties — wrong pattern choice is a real-world vulnerability.**

- **NN** provides no authentication: anyone can impersonate either party. Suitable only for anonymous tunneling where identity doesn't matter.
- **IK** assumes the initiator already knows the responder's static key. If this assumption is violated, the security model breaks down.
- **IKpsk2** (WireGuard) adds a pre-shared key as a post-quantum defensive layer. Even if X25519 is broken by a quantum computer, the PSK protects the session.
- **Forward secrecy** comes from ephemeral keys — past sessions stay secure even if long-term keys are compromised.
- **Identity hiding** depends on the pattern: some patterns leak identity to passive observers, others protect both parties.

This is an educational demonstration. The implementation follows the Noise specification but has not been audited for production use. Do not use this code to protect real data.

Reference: [WireGuard: Next Generation Kernel Network Tunnel](https://www.wireguard.com/papers/wireguard.pdf) — Jason A. Donenfeld, 2017

## Accessibility

This demo meets **WCAG 2.1 AA** requirements:

- All interactive elements have descriptive ARIA labels
- Full keyboard navigation with logical tab order and no keyboard traps
- Visible focus indicators in both dark and light modes (minimum 3:1 contrast ratio)
- Security property indicators use text + icon — never color alone
- Animations respect `prefers-reduced-motion`
- All form inputs have associated `<label>` elements
- Error states announced via `aria-live` regions
- Minimum 4.5:1 contrast ratio for normal text, 3:1 for large text
- Tab panel navigation follows WAI-ARIA tabs pattern with arrow key support
- Screen reader navigable: panels, step walkthroughs, and pattern selector all accessible without a mouse

## Why This Matters

Noise powers real-world security infrastructure:

- **WireGuard** — the modern VPN protocol used by millions, built on Noise IKpsk2
- **Lightning Network** — Bitcoin's payment channel network uses Noise for encrypted transport
- **WhatsApp** — transport layer encryption uses a Noise-based protocol
- **libp2p** — peer-to-peer networking library uses Noise XX for mutual authentication

Noise provides **composable security without TLS complexity**. No cipher suite negotiation, no certificate authorities, no downgrade attacks. Choose a pattern, and the properties are guaranteed by construction.

## Related Demos

- [crypto-lab-ratchet-wire](https://github.com/systemslibrarian/crypto-lab-ratchet-wire) — Double Ratchet algorithm (Signal Protocol)
- [crypto-lab-x3dh-wire](https://github.com/systemslibrarian/crypto-lab-x3dh-wire) — X3DH key agreement protocol
- [crypto-lab-hybrid-wire](https://github.com/systemslibrarian/crypto-lab-hybrid-wire) — Hybrid post-quantum key exchange
- [crypto-compare](https://github.com/systemslibrarian/crypto-compare) — Comparative cryptography reference
- [crypto-lab](https://github.com/systemslibrarian/crypto-lab) — Full crypto-lab collection

---

*"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31*