# FastWebToken
[![Build, Test](https://github.com/DeltaLaboratory/fwt/actions/workflows/checker.yml/badge.svg)](https://github.com/DeltaLaboratory/fwt/actions/workflows/checker.yml)

Small, Fast and simple JWT alternative that uses CBOR for serialization and EdDSA, HMAC, blake2b and blake3 for signing.
## Structure
|                  Header                   |             Payload              |                                                     Signature                                                      |
|:-----------------------------------------:|:--------------------------------:|:------------------------------------------------------------------------------------------------------------------:|
| 1 (SignatureType) + 8 (Payload size) byte | Varies based on the Payload size | 32 bytes for HMACSha256, Blake2b256, blake3 or 64 bytes for Ed25519, HMACSha512, Blake2b512 or 114 bytes for Ed448 |

1. Header: This begins with a single byte that determines the SignatureType.
   The next eight bytes are the size of the payload encoded in big endian.
2. Payload: Payload that encoded in CBOR format. The size of the payload is specified in the header.
3. Signature: This is either 32, 64 or 114 bytes depending on the SignatureType specified in the header.

## Signature Types
* Ed25519: RFC-8032 Ed25519 signature.
* Ed448: RFC-8032 Ed448 signature.
* HMACSha256: HMAC with SHA-256.
* HMACSha512: HMAC with SHA-512.
* Blake2b256: Blake2b with 256-bit output.
* Blake2b512: Blake2b with 512-bit output.
* Blake3: Blake3 with 256-bit output.