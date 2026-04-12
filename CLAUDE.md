# compsig Extension for JWX

## Overview

This module (`github.com/jwx-go/compsig/v4`) provides post-quantum composite signatures per [draft-ietf-jose-pq-composite-sigs](https://datatracker.ietf.org/doc/draft-ietf-jose-pq-composite-sigs/) for `github.com/lestrrat-go/jwx`.

Each composite algorithm pairs ML-DSA (FIPS 204) with a traditional signature scheme — ECDSA, Ed25519, or Ed448 — and a JWS verifies only when **both** component signatures verify.

## Architecture

### Composite construction

Per the JOSE draft (inheriting from draft-ietf-lamps-pq-composite-sigs):

```
M' := Prefix || Label || 0x00 || PH(M)
Prefix = "CompositeAlgorithmSignatures2025"
Label  = "COMPSIG-..."    (one per algorithm, see params.go)
PH(M)  = per-algorithm pre-hash (SHA-256, SHA-512, or SHAKE256(64))

Composite_Sig := MLDSA_Sig(sk_mldsa, M') || Traditional_Sig(sk_trad, M')
```

Both components sign `M'`, not `M`. Because ML-DSA signatures are fixed-length, the concatenation can be split unambiguously at `mldsaSigSize`.

### ECDSA encoding quirk

The draft defers ECDSA signature serialization to LAMPS, which uses ASN.1 DER-encoded `Ecdsa-Sig-Value`. This differs from the usual JWS `r‖s` format. The compsig module therefore calls `crypto/ecdsa.SignASN1` / `VerifyASN1` directly for the ECDSA component and does **not** go through `jwsbb.Sign("ES256"...)`.

### JWK Key Type: AKP

- `kty`: `"AKP"`
- `alg`: one of the six composite algorithm names (REQUIRED)
- `pub`: base64url of `mldsa_pub || traditional_pub`
- `priv`: base64url of `mldsa_32byte_seed || traditional_priv` (private keys only)

### Registration Points

| JWX Package | Registration Function | Purpose |
|-------------|----------------------|---------|
| `jwa` | `RegisterSignatureAlgorithm()` | Register 6 composite algorithms |
| `jwk` | `RegisterKeyImporter()` | `*compsig.PrivateKey`/`*compsig.PublicKey` → `jwk.Key` |
| `jwk` | `RegisterKeyExporter()` | `jwk.Key` → `*compsig.PrivateKey`/`*compsig.PublicKey`, one registration per alg (KeyKind `"AKP:<alg>"`) |
| `dsig` | `RegisterAlgorithm()` | 6 dsig Custom family entries |
| `jwsbb` | `RegisterDsigAlgorithm()` | JWS alg name → dsig alg name |
| `jws` | `RegisterSigner()` / `RegisterVerifier()` | JWK-unwrapping wrappers |
| `jws` | `RegisterAlgorithmForKeyType()` | Associate composite algs with AKP |

### Coupling to jwx-go/mldsa and jwx-go/ed448

This module imports `github.com/jwx-go/mldsa/v4` and `github.com/jwx-go/ed448/v4` for their `init()` side effects. Their init() registers pure `ML-DSA-44/65/87` and `Ed448` with `dsig`/`jwsbb`, which the composite signer reuses via `jwsbb.Sign(..., "ML-DSA-44"/"Ed448", ...)` for those components. ECDSA and Ed25519 are handled directly (stdlib) — ECDSA because of the DER format, Ed25519 because no companion module is needed.

## Files

| File | Purpose |
|------|---------|
| `compsig.go` | Package doc, algorithm accessor functions, `init()` registration |
| `params.go` | Per-algorithm parameter table (label, pre-hash, sizes, component handlers) |
| `message.go` | `composeMessage()` and pre-hash implementations |
| `keys.go` | `PrivateKey`/`PublicKey` raw types, `GenerateKey`, marshalers |
| `signer.go` | `jws.Signer` wrapper (unwraps JWK, delegates to dsig) |
| `verifier.go` | `jws.Verifier` wrapper (unwraps JWK, delegates to dsig) |
| `dsig.go` | `dsig.Custom` Signer/Verifier impl (computes `M'`, dispatches to components) |
| `jwk.go` | Key importers / exporters |
| `compsig_test.go` | Round-trip tests (6 variants) |

## Build / Test

```
go test ./...
```

Go 1.26+ (uses stdlib `crypto/sha3` and `encoding/json/v2`).

## Branch Policy

| Branch | Purpose |
|--------|---------|
| `v*` (e.g. `v4`) | Release tags only. NEVER commit directly to these branches. |
| `develop/v*` (e.g. `develop/v4`) | Active development. All feature branches merge here. |
| Feature branches | Branch from `develop/v*`, merge back via PR. |

- Tags are cut from `v*` branches.
- `v*` branches should never be directly worked on.
- Regular development happens on `develop/v*` and feature branches.
