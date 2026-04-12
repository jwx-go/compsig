package compsig

import (
	"fmt"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jws/jwsbb"
)

// compSigSigner implements jws.Signer for one composite variant. It accepts
// either a raw *compsig.PrivateKey or a jwk.Key with matching AKP payload,
// unwraps to the raw form, and delegates to the dsig layer via jwsbb.
type compSigSigner struct {
	info *algInfo
}

func (s *compSigSigner) Sign(key any, payload []byte) ([]byte, error) {
	sk, err := extractCompositePriv(s.info, key)
	if err != nil {
		return nil, fmt.Errorf(`compsig.Sign %s: %w`, s.info.name, err)
	}
	return jwsbb.Sign(sk, s.info.name, payload, nil)
}

func extractCompositePriv(info *algInfo, key any) (*PrivateKey, error) {
	switch k := key.(type) {
	case *PrivateKey:
		if k.info != info {
			return nil, fmt.Errorf(`private key alg %s does not match %s`, k.info.name, info.name)
		}
		return k, nil
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
		privV, ok := k.Field(jwk.AKPPrivKey)
		if !ok {
			return nil, fmt.Errorf(`AKP key missing "priv" field`)
		}
		privBytes, ok := privV.([]byte)
		if !ok {
			return nil, fmt.Errorf(`"priv" field is not []byte`)
		}
		return newPrivateKeyForInfo(info, privBytes)
	default:
		return nil, fmt.Errorf(`%w: %T`, errUnsupportedKey, key)
	}
}
