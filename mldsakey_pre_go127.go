//go:build !go1.27

package compsig

import (
	"crypto"

	"filippo.io/mldsa"
)

// Before Go 1.27 there is no crypto/mldsa, so dsig cannot own the ML-DSA
// algorithm names — its implementation is constrained to go1.27, as is jwx's.
// jwx-go/mldsa is therefore always the one registered, and it takes the
// filippo key unchanged. See mldsakey_go127.go for the case this mirrors.

// mldsaSignInput returns the key and options to hand to jwsbb for the ML-DSA
// component. ctx is the per-variant domain separator.
func mldsaSignInput(sk *mldsa.PrivateKey, _, ctx string) (any, crypto.SignerOpts, error) {
	return sk, &mldsa.Options{Context: ctx}, nil
}

// mldsaVerifyInput is the verification-side counterpart of [mldsaSignInput].
func mldsaVerifyInput(pk *mldsa.PublicKey, _, ctx string) (any, crypto.SignerOpts, error) {
	return pk, &mldsa.Options{Context: ctx}, nil
}
