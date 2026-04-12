# compsig

Post-quantum composite signatures for [github.com/lestrrat-go/jwx](https://github.com/lestrrat-go/jwx), tracking [draft-ietf-jose-pq-composite-sigs](https://datatracker.ietf.org/doc/draft-ietf-jose-pq-composite-sigs/). Each composite algorithm pairs ML-DSA (FIPS 204) with a traditional signature scheme; both component signatures must verify for the composite to be accepted.

## Status

**Experimental.** This module tracks an active IETF draft. The underlying cryptographic construction is inherited from the more mature [draft-ietf-lamps-pq-composite-sigs](https://datatracker.ietf.org/doc/draft-ietf-lamps-pq-composite-sigs/), but the JOSE-specific bindings (algorithm identifiers, JWK shape) may shift as the draft evolves. Do not rely on on-wire compatibility across releases until the draft reaches WG Last Call.

## Installation

```
go get github.com/jwx-go/compsig/v4
```

## Usage

Side-effect import registers all six composite algorithms with jwx. It transitively pulls in `github.com/jwx-go/mldsa` and `github.com/jwx-go/ed448`, so pure `ML-DSA-44/65/87` and `Ed448` are also registered.

```go
import _ "github.com/jwx-go/compsig/v4"
```

### Sign and verify

```go
import (
    compsig "github.com/jwx-go/compsig/v4"
    "github.com/lestrrat-go/jwx/v4/jws"
)

sk, _ := compsig.GenerateKey(compsig.MLDSA65ES256())
pub := sk.Public()

signed, _ := jws.Sign(payload, jws.WithKey(compsig.MLDSA65ES256(), sk))
verified, _ := jws.Verify(signed, jws.WithKey(compsig.MLDSA65ES256(), pub))
```

### JWK round-trip

```go
import (
    compsig "github.com/jwx-go/compsig/v4"
    "github.com/lestrrat-go/jwx/v4/jwk"
)

sk, _ := compsig.GenerateKey(compsig.MLDSA65Ed25519())
jwkKey, _ := jwk.Import[jwk.Key](sk)

pubJWK, _ := jwkKey.PublicKey()
```

## Algorithms

Each composite algorithm uses the `AKP` (Algorithm Key Pair) JWK key type, discriminated by the `alg` field. Public and private key material is a concatenation of the ML-DSA component followed by the traditional component.

| Algorithm | ML-DSA | Traditional | Pre-hash |
|-----------|--------|-------------|----------|
| ML-DSA-44-ES256 | ML-DSA-44 | ECDSA P-256 | SHA-256 |
| ML-DSA-65-ES256 | ML-DSA-65 | ECDSA P-256 | SHA-512 |
| ML-DSA-87-ES384 | ML-DSA-87 | ECDSA P-384 | SHA-512 |
| ML-DSA-44-Ed25519 | ML-DSA-44 | Ed25519 | SHA-512 |
| ML-DSA-65-Ed25519 | ML-DSA-65 | Ed25519 | SHA-512 |
| ML-DSA-87-Ed448 | ML-DSA-87 | Ed448 | SHAKE256(64) |

Note: the ECDSA component inside the composite is encoded as ASN.1 DER-encoded `Ecdsa-Sig-Value` (inherited from LAMPS), not the JOSE fixed-length `r‖s` encoding.

## License

MIT
