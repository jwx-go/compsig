package compsig

import (
	"fmt"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jws/jwsbb"
)

// compSigVerifier implements jws.Verifier for one composite variant. It
// accepts a raw *compsig.PublicKey / *compsig.PrivateKey or a matching jwk.Key
// and delegates to the dsig layer via jwsbb after unwrapping.
type compSigVerifier struct {
	info *algInfo
}

func (v *compSigVerifier) Verify(key any, payload, signature []byte) error {
	pk, err := extractCompositePub(v.info, key)
	if err != nil {
		return fmt.Errorf(`compsig.Verify %s: %w`, v.info.name, err)
	}
	return jwsbb.Verify(pk, v.info.name, payload, signature)
}

func extractCompositePub(info *algInfo, key any) (*PublicKey, error) {
	switch k := key.(type) {
	case *PublicKey:
		if k.info != info {
			return nil, fmt.Errorf(`public key alg %s does not match %s`, k.info.name, info.name)
		}
		return k, nil
	case *PrivateKey:
		if k.info != info {
			return nil, fmt.Errorf(`private key alg %s does not match %s`, k.info.name, info.name)
		}
		return k.Public(), nil
	case jwk.Key:
		if k.KeyType() != jwa.AKP() {
			return nil, fmt.Errorf(`expected AKP key type, got %s`, k.KeyType())
		}
		algV, ok := k.Algorithm()
		if !ok {
			return nil, fmt.Errorf(`AKP key missing "alg" field`)
		}
		if algV.String() != info.name {
			return nil, fmt.Errorf(`AKP key alg %s does not match %s`, algV.String(), info.name)
		}
		pubV, ok := k.Field(jwk.AKPPubKey)
		if !ok {
			return nil, fmt.Errorf(`AKP key missing "pub" field`)
		}
		pubBytes, ok := pubV.([]byte)
		if !ok {
			return nil, fmt.Errorf(`"pub" field is not []byte`)
		}
		return newPublicKeyForInfo(info, pubBytes)
	default:
		return nil, fmt.Errorf(`%w: %T`, errUnsupportedKey, key)
	}
}
