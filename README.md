# MessagePackWebToken
Smol and simple JWT alternative that uses MessagePack for serialization and EdDSA for signing.
## Structure
|                  Header                   |             Payload              |                  Signature                  |
|:-----------------------------------------:|:--------------------------------:|:-------------------------------------------:|
| 1 (SignatureType) + 8 byte (Payload size) | Varies based on the Payload size | 64 bytes for Ed25519 or 114 bytes for Ed448 |

1. Header: This begins with a single byte that determines the SignatureType. The available options are Ed25519 (0x00) and Ed448 (0x01). Following 8-byte block represents the size of the payload.
2. Payload: Payload that encoded in MessagePack format. The size of the payload is specified in the header.
3. Signature: This is either 64 or 114 bytes depending on the SignatureType specified in the header.