package compsig

import (
	"errors"
	"fmt"
	"io"

	"filippo.io/mldsa"
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

	// ML-DSA component: call filippo.io/mldsa directly so we can supply
	// ctx=Label as required by draft-ietf-jose-pq-composite-sigs §4.2 step 3.
	// Going through jwsbb / jwx-go/mldsa would lose the context (its
	// Sign hard-codes ctx=nil), and the resulting signature would not be
	// interoperable with any spec-compliant implementation.
	mldsaSig, err := sk.mldsa.Sign(r, mPrime, &mldsa.Options{Context: string(d.info.label)})
	if err != nil {
		return nil, fmt.Errorf(`compsig: ml-dsa sign: %w`, err)
	}
	if len(mldsaSig) != d.info.mldsaSigSize {
		return nil, fmt.Errorf(`compsig: ml-dsa sign returned %d bytes, want %d`, len(mldsaSig), d.info.mldsaSigSize)
	}

	// Traditional component: ECDSA uses direct crypto/ecdsa to emit DER
	// (per LAMPS); Ed25519 uses stdlib; Ed448 uses cloudflare/circl.
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

	// Same context as Sign: required by the draft and by filippo.io/mldsa.
	if err := mldsa.Verify(pk.mldsa, mPrime, mldsaSig, &mldsa.Options{Context: string(d.info.label)}); err != nil {
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
