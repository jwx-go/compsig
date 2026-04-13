// Package compsig provides post-quantum composite signatures for the jwx
// library, tracking draft-ietf-jose-pq-composite-sigs.
//
// Each composite algorithm pairs ML-DSA (FIPS 204) with a traditional
// signature scheme (ECDSA P-256/P-384, Ed25519, or Ed448). A composite
// signature verifies only if BOTH component signatures verify, providing
// defense-in-depth against failure in either the post-quantum or traditional
// component.
//
// # Supported algorithms
//
//   - ML-DSA-44-ES256
//   - ML-DSA-65-ES256
//   - ML-DSA-87-ES384
//   - ML-DSA-44-Ed25519
//   - ML-DSA-65-Ed25519
//   - ML-DSA-87-Ed448
//
// # Status
//
// This module tracks an active IETF draft (draft-ietf-jose-pq-composite-sigs)
// that inherits its cryptographic construction from the more mature
// draft-ietf-lamps-pq-composite-sigs. JOSE-specific details (algorithm
// identifiers, JWK shape, pre-hash table) may shift as the draft evolves.
//
// # Usage
//
// Import for side effects to register all six composite algorithms with jwx:
//
//	import _ "github.com/jwx-go/compsig/v4"
//
// The side-effect import also transitively registers pure ML-DSA and Ed448
// algorithms (via github.com/jwx-go/mldsa and github.com/jwx-go/ed448), which
// the composite signer reuses for the ML-DSA and Ed448 component signatures.
// ECDSA and Ed25519 components are handled directly via crypto/ecdsa and
// crypto/ed25519 — ECDSA because the composite format demands ASN.1 DER
// Ecdsa-Sig-Value (per LAMPS) rather than the JOSE r||s encoding.
//
// Registration happens in init(). If any underlying jwx Register* call
// returns an error, init() panics — importing this package will crash the
// program at load time. This is the house style across all jwx-go extension
// modules.
package compsig

import (
	"fmt"

	"github.com/lestrrat-go/dsig"
	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jws"
	"github.com/lestrrat-go/jwx/v4/jws/jwsbb"

	// Side-effect imports: register pure ML-DSA and Ed448 in dsig/jwsbb so
	// compsig's composite signer can reuse them via jwsbb.Sign dispatch.
	_ "github.com/jwx-go/ed448/v4"
	_ "github.com/jwx-go/mldsa/v4"
)

func init() {
	// Register the six composite algorithms in jwa.
	for _, info := range compSigAlgs {
		panicOnRegistrationError(jwa.RegisterSignatureAlgorithm(info.alg))
		panicOnRegistrationError(jws.RegisterAlgorithmForKeyType(jwa.AKP(), info.alg))

		if err := dsig.RegisterAlgorithm(info.name, dsig.AlgorithmInfo{
			Family: dsig.Custom,
			Meta:   &compSigDsig{info: info},
		}); err != nil {
			panic(fmt.Sprintf("jwx-go/compsig: dsig RegisterAlgorithm %s: %s", info.name, err))
		}
		panicOnRegistrationError(jwsbb.RegisterDsigAlgorithm(info.name, info.name))

		panicOnRegistrationError(jws.RegisterSigner(info.alg, &compSigSigner{info: info}))
		panicOnRegistrationError(jws.RegisterVerifier(info.alg, &compSigVerifier{info: info}))

		// AKP keys report KeyKind "AKP:<alg>", so the exporter is registered
		// per algorithm. The plain "AKP" fallback is handled by jwx-go/mldsa
		// for pure ML-DSA and by jwx core for ML-KEM.
		panicOnRegistrationError(jwk.RegisterKeyExporter(jwk.KeyKind("AKP:"+info.name), jwk.KeyExportFunc(exportKey)))
	}

	panicOnRegistrationError(jwk.RegisterKeyImporter(importPrivateKey))
	panicOnRegistrationError(jwk.RegisterKeyImporter(importPublicKey))
}

// panicOnRegistrationError converts a non-nil error returned by a jwx
// Register* call during init() into an import-time panic. The rule
// (documented in jwx's internals.md) is that a failed Register* leaves
// the extension unusable, so we surface it immediately instead of
// letting the program continue in a broken state.
func panicOnRegistrationError(err error) {
	if err != nil {
		panic(fmt.Sprintf("jwx-go/compsig: registration failed: %s", err))
	}
}
