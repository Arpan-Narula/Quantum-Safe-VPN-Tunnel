# Quantum Safe VPN Tunnel

A proof-of-concept Layer 3 encrypted network tunnel implemented in C++. This project demonstrates a quantum-resistant architecture by combining classical Elliptic Curve Cryptography (X25519) with a Post-Quantum Key Encapsulation Mechanism (CRYSTALS-Kyber) to derive a secure AES-256-GCM symmetric key.

## The Strategic Value ("Harvest Now, Decrypt Later")
Standard RSA and ECC encryption face existential threats from future cryptographically relevant quantum computers (CRQCs). This project implements a **Hybrid Key Exchange**—the current industry-standard recommendation by NIST and ENISA—ensuring that data intercepted today remains secure against the quantum computers of tomorrow.

## Technology Stack
* **Language:** C++ (Raw sockets, TUN/TAP interface manipulation)
* **Classical Crypto:** OpenSSL (X25519, HKDF, AES-256-GCM)
* **Post-Quantum Crypto:** liboqs (CRYSTALS-Kyber-512)
* **Networking:** Linux IPv4 routing, UDP transport

## Architecture & Key Exchange
1. **Phase A:** Client and Server generate X25519 keypairs and CRYSTALS-Kyber keypairs.
2. **Phase B:** Public keys are exchanged over a UDP socket. Both parties independently calculate a Classical Shared Secret and a PQC Shared Secret.
3. **Phase C:** Both secrets are concatenated and fed into an HMAC-based Key Derivation Function (HKDF-SHA256) to produce the final `final_symmetric_key`.
4. **Phase D:** OS-level traffic is captured via `/dev/net/tun`, encrypted using AES-256-GCM (providing both confidentiality and integrity), and routed to the peer.

## Build Instructions
### Prerequisites
You must have `liboqs` and `openssl` (version 3.0+) installed on your Linux machine.

### Compilation
```bash
git clone [https://github.com/yourusername/Quantum-Safe-VPN-Tunnel.git](https://github.com/yourusername/Quantum-Safe-VPN-Tunnel.git)
cd Quantum-Safe-VPN-Tunnel
make
