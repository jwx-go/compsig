package compsig

import (
	"errors"
	"fmt"
	"io"

	"filippo.io/mldsa"
	"github.com/lestrrat-go/jwx/v4/jws/jwsbb"
)

// compSigDsig implements dsig.Signer and dsig.Verifier for one composite
// algorithm variant. It operates on raw *PrivateKey / *PublicKey values
// (higher-level jwk.Key unwrapping happens in signer.go / verifier.go).
//
// Sign computes the M' representative, signs it with both components, and
// concatenates. Verify splits at the fixed ML-DSA boundary and requires both
// component verifications to succeed.
type compSigDsig struct {
	info *algInfo
}

func (d *compSigDsig) Sign(key any, payload []byte, r io.Reader) ([]byte, error) {
	sk, err := d.extractPrivate(key)
	if err != nil {
		return nil, err
	}

	mPrime := composeMessage(d.info, payload)

	// ML-DSA component: dispatch through jwsbb.SignWithOpts so the
	// underlying jwx-go/mldsa adapter receives ctx=Label as required by
	// draft-ietf-jose-pq-composite-sigs §4.2 step 3. The plain
	// jwsbb.Sign / jwx-go/mldsa Sign path hard-codes ctx=nil and would
	// silently produce signatures that are not interoperable with any
	// spec-compliant implementation.
	mldsaSig, err := jwsbb.SignWithOpts(sk.mldsa, d.info.mldsaAlgName, mPrime, &mldsa.Options{Context: string(d.info.label)}, r)
	if err != nil {
		return nil, fmt.Errorf(`compsig: ml-dsa sign: %w`, err)
	}
	if len(mldsaSig) != d.info.mldsaSigSize {
		return nil, fmt.Errorf(`compsig: ml-dsa sign returned %d bytes, want %d`, len(mldsaSig), d.info.mldsaSigSize)
	}

	// Traditional component: always pass the caller's entropy source through.
	// Randomized variants such as ECDSA must consume it; deterministic variants
	// such as Ed25519 and Ed448 document that they intentionally ignore it.
	tradSig, err := d.info.trad.sign(sk.trad, mPrime, r)
	if err != nil {
		return nil, fmt.Errorf(`compsig: traditional sign: %w`, err)
	}

	out := make([]byte, 0, len(mldsaSig)+len(tradSig))
	out = append(out, mldsaSig...)
	out = append(out, tradSig...)
	return out, nil
}

func (d *compSigDsig) Verify(key any, payload, signature []byte) error {
	pk, err := d.extractPublic(key)
	if err != nil {
		return err
	}
	if len(signature) < d.info.mldsaSigSize {
		return fmt.Errorf(`compsig: signature length %d shorter than ml-dsa minimum %d`, len(signature), d.info.mldsaSigSize)
	}

	mPrime := composeMessage(d.info, payload)
	mldsaSig := signature[:d.info.mldsaSigSize]
	tradSig := signature[d.info.mldsaSigSize:]

	// Same ctx=Label as Sign — see Sign for the rationale.
	if err := jwsbb.VerifyWithOpts(pk.mldsa, d.info.mldsaAlgName, mPrime, mldsaSig, &mldsa.Options{Context: string(d.info.label)}); err != nil {
		return fmt.Errorf(`compsig: ml-dsa verify: %w`, err)
	}
	if err := d.info.trad.verify(pk.trad, mPrime, tradSig); err != nil {
		return fmt.Errorf(`compsig: traditional verify: %w`, err)
	}
	return nil
}

func (d *compSigDsig) extractPrivate(key any) (*PrivateKey, error) {
	sk, ok := key.(*PrivateKey)
	if !ok {
		return nil, fmt.Errorf(`compsig: expected *compsig.PrivateKey for %s, got %T`, d.info.name, key)
	}
	if sk.info != d.info {
		return nil, fmt.Errorf(`compsig: private key alg %s does not match signer %s`, sk.info.name, d.info.name)
	}
	return sk, nil
}

func (d *compSigDsig) extractPublic(key any) (*PublicKey, error) {
	switch k := key.(type) {
	case *PublicKey:
		if k.info != d.info {
			return nil, fmt.Errorf(`compsig: public key alg %s does not match verifier %s`, k.info.name, d.info.name)
		}
		return k, nil
	case *PrivateKey:
		if k.info != d.info {
			return nil, fmt.Errorf(`compsig: private key alg %s does not match verifier %s`, k.info.name, d.info.name)
		}
		return k.Public(), nil
	default:
		return nil, fmt.Errorf(`compsig: expected *compsig.PublicKey for %s, got %T`, d.info.name, key)
	}
}

// Sentinel error used when jwk.Key unwrapping fails before even reaching the
// dsig layer. Kept separate so that signer.go / verifier.go can produce a
// consistent error shape.
var errUnsupportedKey = errors.New(`compsig: unsupported key type`)
