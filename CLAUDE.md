# compsig Extension for JWX

## Overview

This module (`github.com/jwx-go/compsig/v4`) provides post-quantum composite signatures per [draft-ietf-jose-pq-composite-sigs](https://datatracker.ietf.org/doc/draft-ietf-jose-pq-composite-sigs/) for `github.com/lestrrat-go/jwx`.

Each composite algorithm pairs ML-DSA (FIPS 204) with a traditional signature scheme — ECDSA, Ed25519, or Ed448 — and a JWS verifies only when **both** component signatures verify.

## Architecture

### Composite construction

Per the JOSE draft (inheriting from draft-ietf-lamps-pq-composite-sigs), `M'` is built in two steps and then fed to both component signers:

```
Step 1:  M' := Prefix || Label || 0x00 || PH(M)
Step 2:  M' := base64url(M')        // JOSE; COSE would use raw binary

Prefix = "CompositeAlgorithmSignatures2025"
Label  = "COMPSIG-..."   (one per algorithm, see params.go)
PH(M)  = per-algorithm pre-hash (SHA-256, SHA-512, or SHAKE256(64))

ML-DSA component: ML-DSA.Sign(sk_mldsa, M', ctx=Label)   // per-variant context
Trad component:   trad.Sign(sk_trad, M')                  // empty ctx

Composite_Sig := MLDSA_Sig || Traditional_Sig
```

Step 2 is the JOSE-specific `Encode(M')`: the raw vector from step 1 is re-encoded as unpadded base64url ASCII, and those ASCII bytes — not the raw vector — are what each component signer receives. `composeMessage` in `message.go` performs both steps. Because ML-DSA signatures are fixed-length, the concatenation in `Composite_Sig` can be split unambiguously at `mldsaSigSize`.

The ML-DSA component receives `ctx=Label` (the per-variant domain separator from Table 4 of the draft), which is mandatory for interop. The traditional component uses an empty context per the draft's `ctx=""` rule.

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

This module imports `github.com/jwx-go/mldsa/v4` and `github.com/jwx-go/ed448/v4` for their `init()` side effects. Their init() registers pure `ML-DSA-44/65/87` and `Ed448` with `dsig`/`jwsbb`, which the composite signer reuses for those components. ECDSA and Ed25519 are handled directly (stdlib) — ECDSA because of the DER format, Ed25519 because no companion module is needed.

The ML-DSA component dispatches through `jwsbb.SignWithOpts` / `jwsbb.VerifyWithOpts` carrying `&mldsa.Options{Context: string(info.label)}`, so the per-variant context label reaches `filippo.io/mldsa`. This requires `github.com/jwx-go/mldsa` ≥ `v4.0.0-alpha3` — that release adds `SignerWithOpts` / `VerifierWithOpts` to the mldsa dsig adapter, which forwards `*mldsa.Options` to `filippo.io/mldsa.(*PrivateKey).Sign` and `filippo.io/mldsa.Verify`. The plain `jwsbb.Sign` / `jwsbb.Verify` path does not carry opts and would silently sign with `ctx=""`, breaking draft interop — do not regress to it.

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
