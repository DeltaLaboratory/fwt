# Fast Web Token

[![Build Status](https://github.com/DeltaLaboratory/fwt/actions/workflows/checker.yml/badge.svg)](https://github.com/DeltaLaboratory/fwt/actions/workflows/checker.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/DeltaLaboratory/fwt.svg)](https://pkg.go.dev/github.com/DeltaLaboratory/fwt)
[![Go Report Card](https://goreportcard.com/badge/github.com/DeltaLaboratory/fwt)](https://goreportcard.com/report/github.com/DeltaLaboratory/fwt)

A lightweight, high-performance JWT alternative leveraging CBOR serialization with multiple secure signing options.

## Features

- Multiple secure signing options (EdDSA, HMAC, Blake2b, Blake3)
- Compact binary format using CBOR
- High-performance implementation
- Post-quantum resistant signatures (Ed448)
- Customizable CBOR encoding
- Lightweight design

## Installation

```bash
go get github.com/DeltaLaboratory/fwt/v2
```

## Quick Start

### Create and Sign a Token

```go
package main

import (
	"time"

	"github.com/DeltaLaboratory/fwt/v2"
)

func main() {
	signer, err := fwt.NewSigner(
		fwt.NewBlake3Signer([]byte("somekeyhere")),
		nil,          // Optional encryption
	)
	
	if err != nil {
		panic(err)
	}

	payload := map[string]interface{}{
		"user_id": 123,
		"exp":     time.Now().Add(time.Hour).Unix(),
	}

	token, err := signer.Sign(payload)
	if err != nil {
		panic(err)
	}
}
```

### Verify a Token

```go
package main

import "github.com/DeltaLaboratory/fwt/v2"

func verifyToken(token []byte) {
	verifier, err := fwt.NewVerifier(
		fwt.NewBlake3Verifier([]byte("somekey")), 
		nil,
	)
	
	if err != nil {
		panic(err)
	}
	
	var payload map[string]interface{}
	if err := verifier.VerifyAndUnmarshal(token, &payload); err != nil {
		panic(err)
	}
}
```

For working example, see [test code](fwt_test.go).

## Token Structure

FWT uses a compact binary structure:

| Section   | Size                | Description             |
|-----------|---------------------|-------------------------|
| Header    | 2 ~ 10 bytes (vary) | Type + Payload Size     |
| Payload   | Variable (CBOR)     | Token Data              |
| Signature | 32/64/114 bytes     | Cryptographic Signature |

## Supported Algorithms

| Algorithm  | Signature Size (bytes) |
|------------|------------------------|
| Ed25519    | 64                     |
| Ed448      | 114                    |
| HMACSha256 | 32                     |
| HMACSha512 | 64                     |
| Blake2b256 | 32                     |
| Blake2b512 | 64                     |
| Blake3     | 32                     |

## Supported Encryption Algorithms

| Algorithm          | Type          |
|--------------------|---------------|
| XChaCha20-Poly1305 | AEAD          |
| AES-GCM            | AEAD          |
| AES-CBC            | Block Cipher  |
| AES-CTR            | Stream Cipher |
| HPKE               | Hybrid        |
| AES-ECB            | Block Cipher  |

## Advanced Usage

### Custom CBOR Encoding

```go
// Set custom encoder
fwt.SetEncoder(customEncoder)

// Set custom decoder
fwt.SetDecoder(customDecoder)
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
