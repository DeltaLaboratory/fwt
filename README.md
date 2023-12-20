# FastWebToken
[![Build, Test](https://github.com/DeltaLaboratory/fwt/actions/workflows/checker.yml/badge.svg)](https://github.com/DeltaLaboratory/fwt/actions/workflows/checker.yml)

Small, Fast and simple JWT alternative that uses CBOR for serialization and EdDSA, HMAC, blake2b and blake3 for signing.
## Structure
|                  Header                   |             Payload              |                                                     Signature                                                      |
|:-----------------------------------------:|:--------------------------------:|:------------------------------------------------------------------------------------------------------------------:|
| 1 (SignatureType) + 8 (Payload size) byte | Varies based on the Payload size | 32 bytes for HMACSha256, Blake2b256, blake3 or 64 bytes for Ed25519, HMACSha512, Blake2b512 or 114 bytes for Ed448 |

1. Header: This begins with a single byte that determines the SignatureType. The available options are Ed25519 (0x00), Ed448 (0x01), HMACSha256 (0x02), HMACSha512 (0x03), Blake2b256 (0x04), Blake2b512 (0x05) and Blake3 (0x06). Following 8-byte block represents the size of the payload.
2. Payload: Payload that encoded in CBOR format. The size of the payload is specified in the header.
3. Signature: This is either 32, 64 or 114 bytes depending on the SignatureType specified in the header.