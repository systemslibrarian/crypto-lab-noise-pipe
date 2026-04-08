# crypto-lab-noise-pipe

> `Noise Protocol` · `X25519` · `AES-256-GCM` · `HKDF-SHA-256`

## What It Is

The **Noise Protocol Framework** is a framework for constructing cryptographic handshake protocols from composable patterns. Instead of negotiating cipher suites like TLS, you choose a **handshake pattern** — a fixed sequence of **X25519** (Curve25519 ECDH) Diffie-Hellman operations — and the security properties follow deterministically from the pattern definition. Key material is derived throughout the handshake using **HKDF-SHA-256** applied to a chaining key and running handshake hash; once the handshake completes, both parties hold symmetric **AES-256-GCM** transport keys with independent send and receive nonce counters. The security model is asymmetric during the handshake (static and ephemeral Diffie-Hellman key pairs) and symmetric during transport (128-bit-keyed AEAD encryption). The optional PSK mode used in IKpsk2 adds a pre-shared symmetric secret as a post-quantum defensive hedge without changing the handshake round-trips.

## When to Use It

- **You need a secure channel without TLS PKI** — Noise eliminates certificate authorities, cipher-suite negotiation, and downgrade attacks; the pattern chosen at design time determines all authentication and secrecy properties with no runtime negotiation.
- **You need precisely scoped authentication** — patterns such as XX (mutual), NK (known responder static key), NN (anonymous), and IKpsk2 (mutual + PSK) let you express exactly the authentication model your application requires, not whatever TLS negotiates.
- **You are building a peer-to-peer or embedded transport** — Noise is designed for application-layer use where PKI infrastructure is absent or impractical, such as VPN tunnels, IoT devices, or payment-channel networks.
- **You require proven forward secrecy** — every Noise pattern uses ephemeral X25519 key pairs per session, so past sessions remain secure even if long-term static keys are later compromised.
- **Do not use Noise** when you need interoperability with existing TLS-based infrastructure (web servers, browsers, HTTPS APIs) — Noise is not TLS and does not speak the TLS record protocol.

## Live Demo

**[Live Demo →](https://systemslibrarian.github.io/crypto-lab-noise-pipe/)**

Select one of twelve handshake patterns (NN, NK, NX, KN, KK, KX, XN, XK, XX, IX, IK, IKpsk2) to view its complete message sequence and security properties. Step through each handshake message one at a time, observing real X25519 DH scalar multiplications, chaining key evolution via HKDF-SHA-256, and running handshake hash updates. After handshake completion, encrypt and decrypt plaintext messages using the derived AES-256-GCM transport keys with live nonce tracking; a Pattern Comparison panel shows NN, XX, IK, and IKpsk2 side-by-side, and a WireGuard Deep Dive panel maps IKpsk2 token-by-token to WireGuard's actual Initiator and Responder messages.

## What Can Go Wrong

- **Wrong pattern chosen for the threat model** — selecting NN when authentication is required means either party can be impersonated by anyone; Noise provides no runtime negotiation or fallback to detect this mismatch.
- **IK or IKpsk2 with an unverified static key** — these patterns assume the initiator already holds the responder's authentic static public key; if this key is substituted by an attacker (e.g., via a compromised key-distribution channel), the responder can be fully impersonated without breaking X25519.
- **AES-256-GCM nonce counter exhaustion** — the transport nonce is a 64-bit counter; a session that encrypts 2⁶⁴ messages without rekeying will repeat nonces, catastrophically breaking AES-GCM's authentication and confidentiality guarantees.
- **PSK reuse in IKpsk2** — the pre-shared key must be rotated out-of-band; a long-lived PSK that is never rotated steadily erodes its post-quantum and identity-hiding contributions, especially if the PSK is shared across multiple sessions.
- **Handshake hash not bound at the application layer** — if the application does not verify the channel binding (the final handshake hash) out-of-band or via a higher-level protocol message, a network-level adversary can attempt session confusion attacks across concurrent connections.

## Real-World Usage

- **WireGuard** — uses the Noise IKpsk2 pattern as its entire VPN handshake; the pattern's mutual static-key authentication, ephemeral forward secrecy, and PSK layer map directly to WireGuard's Initiator and Responder handshake messages ([WireGuard paper, Donenfeld 2017](https://www.wireguard.com/papers/wireguard.pdf)).
- **Lightning Network** — BOLT #8 specifies Noise_XK_secp256k1_ChaChaPoly_SHA256 for encrypted transport between Lightning nodes, providing forward secrecy and responder identity hiding without a PKI.
- **WhatsApp** — the transport layer between WhatsApp clients and servers uses a Noise-based protocol, providing forward secrecy and mutual authentication independently of the Signal end-to-end encryption layer.
- **libp2p** — the peer-to-peer networking library used by IPFS and Ethereum clients implements Noise XX as its default secure channel protocol (libp2p Noise spec), providing mutual authentication and identity hiding for both peers.

---

## Related Demos

- [crypto-lab-ratchet-wire](https://github.com/systemslibrarian/crypto-lab-ratchet-wire) — Double Ratchet algorithm (Signal Protocol)
- [crypto-lab-x3dh-wire](https://github.com/systemslibrarian/crypto-lab-x3dh-wire) — X3DH key agreement protocol
- [crypto-lab-hybrid-wire](https://github.com/systemslibrarian/crypto-lab-hybrid-wire) — Hybrid post-quantum key exchange
- [crypto-compare](https://github.com/systemslibrarian/crypto-compare) — Comparative cryptography reference
- [crypto-lab](https://github.com/systemslibrarian/crypto-lab) — Full crypto-lab collection

---

*"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31*