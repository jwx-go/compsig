package compsig

import (
	"bytes"
	"fmt"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jwk/jwkunsafe"
)

// importPrivateKey converts a *compsig.PrivateKey into a jwk.Key of type AKP.
func importPrivateKey(raw *PrivateKey) (jwk.Key, error) {
	key, err := jwkunsafe.NewKey(jwa.AKP())
	if err != nil {
		return nil, fmt.Errorf(`compsig import priv: %w`, err)
	}
	if err := key.Set(jwk.AlgorithmKey, raw.info.name); err != nil {
		return nil, fmt.Errorf(`compsig import priv: %w`, err)
	}

	pubBytes, err := raw.Public().MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf(`compsig import priv: %w`, err)
	}
	if err := key.Set(jwk.AKPPubKey, pubBytes); err != nil {
		return nil, fmt.Errorf(`compsig import priv: %w`, err)
	}

	privBytes, err := raw.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf(`compsig import priv: %w`, err)
	}
	if err := key.Set(jwk.AKPPrivKey, privBytes); err != nil {
		return nil, fmt.Errorf(`compsig import priv: %w`, err)
	}
	return key, nil
}

// importPublicKey converts a *compsig.PublicKey into a jwk.Key of type AKP.
func importPublicKey(raw *PublicKey) (jwk.Key, error) {
	key, err := jwkunsafe.NewPublicKey(jwa.AKP())
	if err != nil {
		return nil, fmt.Errorf(`compsig import pub: %w`, err)
	}
	if err := key.Set(jwk.AlgorithmKey, raw.info.name); err != nil {
		return nil, fmt.Errorf(`compsig import pub: %w`, err)
	}

	pubBytes, err := raw.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf(`compsig import pub: %w`, err)
	}
	if err := key.Set(jwk.AKPPubKey, pubBytes); err != nil {
		return nil, fmt.Errorf(`compsig import pub: %w`, err)
	}
	return key, nil
}

// exportKey converts a jwk.Key (AKP with composite algorithm) into the
// corresponding raw *compsig.PrivateKey or *compsig.PublicKey. The exporter
// is registered per algorithm-specific KeyKind ("AKP:ML-DSA-44-ES256", etc.)
// so it is called only for composite variants and never for plain ML-DSA.
func exportKey(key jwk.Key, _ any) (any, error) {
	algV, ok := key.Algorithm()
	if !ok {
		return nil, fmt.Errorf(`compsig export: missing "alg" field`)
	}
	info, ok := lookupAlgInfoByName(algV.String())
	if !ok {
		// Not one of our composite algs; yield to the next registered exporter.
		return nil, jwk.ContinueError()
	}

	pubV, ok := key.Field(jwk.AKPPubKey)
	if !ok {
		return nil, fmt.Errorf(`compsig export %s: missing "pub" field`, info.name)
	}
	pubBytes, ok := pubV.([]byte)
	if !ok {
		return nil, fmt.Errorf(`compsig export %s: "pub" field is not []byte`, info.name)
	}

	if privV, hasPriv := key.Field(jwk.AKPPrivKey); hasPriv {
		privBytes, ok := privV.([]byte)
		if !ok {
			return nil, fmt.Errorf(`compsig export %s: "priv" field is not []byte`, info.name)
		}
		sk, err := newPrivateKeyForInfo(info, privBytes)
		if err != nil {
			return nil, err
		}
		derivedPub, err := sk.Public().MarshalBinary()
		if err != nil {
			return nil, fmt.Errorf(`compsig export %s: derive pub: %w`, info.name, err)
		}
		if !bytes.Equal(derivedPub, pubBytes) {
			return nil, fmt.Errorf(`compsig export %s: "pub" does not match derived public key`, info.name)
		}
		return sk, nil
	}

	return newPublicKeyForInfo(info, pubBytes)
}
