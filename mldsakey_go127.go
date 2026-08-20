//go:build go1.27

package compsig

import (
	"crypto"
	stdmldsa "crypto/mldsa"
	"fmt"

	"filippo.io/mldsa"
	"github.com/lestrrat-go/dsig"
)

// The ML-DSA component is signed and verified through jwsbb, which dispatches
// on the algorithm name. Two different implementations can be registered under
// that name, and they accept different key types:
//
//   - dsig's own, on top of crypto/mldsa, from dsig v1.4.0 on Go 1.27. jwx
//     v4.4.0 relies on it, so this is what an up-to-date build sees.
//   - jwx-go/mldsa's, on top of filippo.io/mldsa, in every other case.
//
// compsig stores filippo keys either way, so when dsig owns the name the key
// is converted to crypto/mldsa on the way in. Both libraries encode a private
// key as the FIPS 204 seed and a public key as the encoded public key, so the
// conversion is exact.

// stdlibMLDSA records, per ML-DSA algorithm name, whether the implementation
// registered with dsig is dsig's own crypto/mldsa one. dsig registers it under
// MLDSAFamily while jwx-go/mldsa registers under dsig.Custom, so the family
// tells the two apart without this package reasoning about module versions.
var stdlibMLDSA = map[string]bool{}

// Resolving the owner once is safe because it cannot change afterwards. Every
// implementation registers from its own init(), Go runs an imported package's
// init() before the importing package's, and dsig refuses to register a name
// twice. This init() reads only the ML-DSA names, so it has no ordering
// relationship with the one in compsig.go.
func init() {
	// The six composite algorithms share three ML-DSA names, so this writes
	// each entry twice with the same value.
	for _, info := range compSigAlgs {
		dsigInfo, ok := dsig.GetAlgorithmInfo(info.mldsaAlgName)
		stdlibMLDSA[info.mldsaAlgName] = ok && dsigInfo.Family == dsig.MLDSAFamily
	}
}

// dsigUsesStdlibMLDSA reports whether the implementation registered for algName
// is dsig's crypto/mldsa one. The map is written once during init and only
// read afterwards, so concurrent signers share it safely.
func dsigUsesStdlibMLDSA(algName string) bool {
	return stdlibMLDSA[algName]
}

// stdMLDSAParams returns the crypto/mldsa parameter set for an ML-DSA
// algorithm name.
func stdMLDSAParams(algName string) (stdmldsa.Parameters, error) {
	for _, params := range []stdmldsa.Parameters{stdmldsa.MLDSA44(), stdmldsa.MLDSA65(), stdmldsa.MLDSA87()} {
		if params.String() == algName {
			return params, nil
		}
	}
	return stdmldsa.Parameters{}, fmt.Errorf(`unknown ML-DSA algorithm %q`, algName)
}

// mldsaSignInput returns the key and options to hand to jwsbb for the ML-DSA
// component. ctx is the per-variant domain separator, and it must reach the
// implementation whichever one is registered.
func mldsaSignInput(sk *mldsa.PrivateKey, algName, ctx string) (any, crypto.SignerOpts, error) {
	if !dsigUsesStdlibMLDSA(algName) {
		return sk, &mldsa.Options{Context: ctx}, nil
	}

	params, err := stdMLDSAParams(algName)
	if err != nil {
		return nil, nil, err
	}
	converted, err := stdmldsa.NewPrivateKey(params, sk.Bytes())
	if err != nil {
		return nil, nil, fmt.Errorf(`failed to convert private key to crypto/mldsa: %w`, err)
	}
	return converted, &stdmldsa.Options{Context: ctx}, nil
}

// mldsaVerifyInput is the verification-side counterpart of [mldsaSignInput].
func mldsaVerifyInput(pk *mldsa.PublicKey, algName, ctx string) (any, crypto.SignerOpts, error) {
	if !dsigUsesStdlibMLDSA(algName) {
		return pk, &mldsa.Options{Context: ctx}, nil
	}

	params, err := stdMLDSAParams(algName)
	if err != nil {
		return nil, nil, err
	}
	converted, err := stdmldsa.NewPublicKey(params, pk.Bytes())
	if err != nil {
		return nil, nil, fmt.Errorf(`failed to convert public key to crypto/mldsa: %w`, err)
	}
	return converted, &stdmldsa.Options{Context: ctx}, nil
}
