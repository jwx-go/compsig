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
		jwa.RegisterSignatureAlgorithm(info.alg)
		jws.RegisterAlgorithmForKeyType(jwa.AKP(), info.alg)

		if err := dsig.RegisterAlgorithm(info.name, dsig.AlgorithmInfo{
			Family: dsig.Custom,
			Meta:   &compSigDsig{info: info},
		}); err != nil {
			panic(fmt.Sprintf("compsig: dsig RegisterAlgorithm %s: %s", info.name, err))
		}
		jwsbb.RegisterDsigAlgorithm(info.name, info.name)

		if err := jws.RegisterSigner(info.alg, &compSigSigner{info: info}); err != nil {
			panic(fmt.Sprintf("compsig: jws RegisterSigner %s: %s", info.name, err))
		}
		if err := jws.RegisterVerifier(info.alg, &compSigVerifier{info: info}); err != nil {
			panic(fmt.Sprintf("compsig: jws RegisterVerifier %s: %s", info.name, err))
		}

		// AKP keys report KeyKind "AKP:<alg>", so the exporter is registered
		// per algorithm. The plain "AKP" fallback is handled by jwx-go/mldsa
		// for pure ML-DSA and by jwx core for ML-KEM.
		jwk.RegisterKeyExporter(jwk.KeyKind("AKP:"+info.name), jwk.KeyExportFunc(exportKey))
	}

	jwk.RegisterKeyImporter(importPrivateKey)
	jwk.RegisterKeyImporter(importPublicKey)
}
