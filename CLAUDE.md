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

The ML-DSA component dispatches through `jwsbb.SignWithOpts` / `jwsbb.VerifyWithOpts` carrying an options value with `Context: string(info.label)`, so the per-variant context label reaches the implementation. The plain `jwsbb.Sign` / `jwsbb.Verify` path does not carry opts and would silently sign with `ctx=""`, breaking draft interop — do not regress to it.

#### Two implementations answer to the ML-DSA names

`jwsbb` dispatches on the algorithm name, and two different implementations can be registered under `ML-DSA-44/65/87`:

| Registered by | Key type | Options type | When |
|---------------|----------|--------------|------|
| `dsig` (`MLDSAFamily`) | `crypto/mldsa` | `*crypto/mldsa.Options` | dsig v1.4.0 on Go 1.27, which jwx v4.4.0 relies on |
| `jwx-go/mldsa` (`dsig.Custom`) | `filippo.io/mldsa` | `*filippo.io/mldsa.Options` | every other case |

compsig stores filippo keys either way, so `mldsaSignInput` / `mldsaVerifyInput` in `mldsakey_go127.go` pick the right pair. The owner is resolved once, by an `init()` in that file that reads `dsig.GetAlgorithmInfo(algName).Family` for each ML-DSA name into the `stdlibMLDSA` map. That distinguishes the two owners without this module reasoning about dependency versions. Resolving once is safe because the answer cannot change after start-up: each implementation registers from its own `init()`, an imported package's `init()` runs before the importing package's, and `dsig` refuses to register a name twice. Signing then converts the key to `crypto/mldsa` when dsig owns the name. Both libraries encode a private key as the FIPS 204 seed, so the conversion is exact and signatures are unchanged.

`mldsakey_pre_go127.go` is the Go 1.26 counterpart. `crypto/mldsa` does not exist there and neither dsig's nor jwx's ML-DSA compiles in, so the filippo key always passes through untouched.

#### Minimum versions on Go 1.27

Two requirements in `go.mod` carry a floor that Go 1.27 needs. Both were pseudo-versions until the releases existed; they are now ordinary versions and must not be lowered.

| Module | Minimum | Needed for |
|--------|---------|-----------|
| `github.com/lestrrat-go/jwx/v4` | v4.4.0 | `jwsbb` handling of `dsig.MLDSAFamily`. v4.3.0 rejects it with `unsupported dsig algorithm family "ML-DSA"`. |
| `github.com/jwx-go/mldsa/v4` | v4.0.5 | Interop mode. v4.0.4 has no stand-down probe and panics at import with `algorithm ML-DSA-44 is already registered` once dsig v1.4.0 owns the names. |

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
| `mldsakey_go127.go` | Picks the key and options types the registered ML-DSA implementation expects (`//go:build go1.27`) |
| `mldsakey_pre_go127.go` | Go 1.26 counterpart, where only the filippo implementation can be registered |
| `compsig_test.go` | Round-trip tests (6 variants) |

## Build / Test

On Go 1.26, `GOEXPERIMENT=jsonv2` is required (jwx v4 dependency). On Go 1.27 it must NOT be set, because that toolchain already ships `encoding/json/v2`.

```
GOEXPERIMENT=jsonv2 go test ./...   # Go 1.26
go test ./...                       # Go 1.27
```

Go 1.26+ (uses stdlib `crypto/sha3` and `encoding/json/v2`).

| Workflow | Toolchain | ML-DSA component key type |
|----------|-----------|---------------------------|
| `ci.yml` | `go.mod` (Go 1.26), `GOEXPERIMENT=jsonv2` | `filippo.io/mldsa`, passed straight through |
| `go127.yml` | Go 1.27 | `crypto/mldsa`, converted before `jwsbb` |

`ci.yml` is synced from the shared companion template, so Go 1.27 coverage lives in `go127.yml` instead of being added there.

## Branch Policy

| Branch | Purpose |
|--------|---------|
| `v*` (e.g. `v4`) | Release tags only. NEVER commit directly to these branches. |
| `develop/v*` (e.g. `develop/v4`) | Active development. All feature branches merge here. |
| Feature branches | Branch from `develop/v*`, merge back via PR. |

- Tags are cut from `v*` branches.
- `v*` branches should never be directly worked on.
- Regular development happens on `develop/v*` and feature branches.
