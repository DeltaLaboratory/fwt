# FastWebToken (FWT)
[![Build, Test](https://github.com/DeltaLaboratory/fwt/actions/workflows/checker.yml/badge.svg)](https://github.com/DeltaLaboratory/fwt/actions/workflows/checker.yml)

A lightweight, high-performance JWT alternative that leverages CBOR (Concise Binary Object Representation) for serialization and provides multiple secure signing options including EdDSA, HMAC, Blake2b, and Blake3.

## Token Structure
|     Header      |        Payload         |                Signature                 |
|:---------------:|:----------------------:|:----------------------------------------:|
| 9 bytes (fixed) | Variable length (CBOR) | 32/64/114 bytes (depending on algorithm) |

### Header Details
- Byte 1: SignatureType identifier
- Bytes 2-9: Payload size (big-endian encoded)

### Supported Signature Types
| Algorithm  | Output Size | Description                 | Use Case                           |
|------------|-------------|-----------------------------|------------------------------------|
| Ed25519    | 64 bytes    | RFC-8032 EdDSA signature    | General-purpose digital signatures |
| Ed448      | 114 bytes   | RFC-8032 EdDSA signature    | Post-quantum resistant signatures  |
| HMACSha256 | 32 bytes    | HMAC with SHA-256           | Symmetric key authentication       |
| HMACSha512 | 64 bytes    | HMAC with SHA-512           | Enhanced symmetric authentication  |
| Blake2b256 | 32 bytes    | Blake2b with 256-bit output | Fast hash-based signatures         |
| Blake2b512 | 64 bytes    | Blake2b with 512-bit output | Enhanced hash-based signatures     |
| Blake3     | 32 bytes    | Blake3 with 256-bit output  | Modern, high-performance signing   |

## Usage

### Creating a Signer
```
// Example with Ed25519
signer := fwt.NewSigner(
signFunction,    // Signing function
nil,            // Optional encryption function
fwt.SignatureTypeEd25519,
)
```

### Signing Data
```
data := map[string]interface{}{
"user_id": 123,
"exp": time.Now().Add(time.Hour).Unix(),
}

token, err := signer.Sign(data)
if err != nil {
// Handle error
}
```

### Verifying Tokens
```
verifier := fwt.NewVerifier(
verifyFunction,  // Verification function
nil,            // Optional decryption function
fwt.SignatureTypeEd25519,
)

var dst map[string]interface{}
err := verifier.VerifyAndUnmarshal(token, &dst)
if err != nil {
// Handle error
}
```

## Customization
### Custom CBOR Encoding
```
// Set custom encoder
fwt.SetEncoder(customEncoder)

// Set custom decoder
fwt.SetDecoder(customDecoder)
```

## Contributing
Contributions are welcome! Please feel free to submit pull requests.

For bug reports and feature requests, please use the GitHub issue tracker.
