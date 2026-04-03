# govis

A Proof-of-Concept for Threshold and Key Rotation based Proactive Secret Sharing library built in Rust.

## Status: Early POC (Core Engine)
- [x] Modular Architecture (`types`, `core`, `protocol`)
- [x] Distributed Key Generation (DKG)
- [x] 'Net-Zero' Key Refresh (Key Rotation)
- [x] Identity Persistence Unit Tests (Math Verification)
- [ ] Async Networking (Round-based implementation)

## Description
Built using `generic-ec` and `round-based` as part of exploring Threshold Cryptography.
The goal is to provide a clean, verifiable way to rotate threshold shares without changing 
the Master Public Key.
