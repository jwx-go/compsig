package compsig

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"io"

	"filippo.io/mldsa"
	"github.com/lestrrat-go/jwx/v4/jwa"
)

// PrivateKey is a composite private key pairing an ML-DSA private key with a
// traditional-algorithm private key. The raw form is
// mldsaSeed (32 bytes) || traditionalPriv (algorithm-specific), matching the
// "priv" field of the JWK representation.
type PrivateKey struct {
	info  *algInfo
	mldsa *mldsa.PrivateKey
	trad  any // per info.trad: *ecdsa.PrivateKey, ed25519.PrivateKey, or ed448.PrivateKey
}

// PublicKey is the public half of a composite key. The raw form is
// mldsaPub || traditionalPub, matching the "pub" field of the JWK
// representation.
type PublicKey struct {
	info  *algInfo
	mldsa *mldsa.PublicKey
	trad  any
}

// Algorithm returns the composite algorithm identifier for this key.
func (sk *PrivateKey) Algorithm() jwa.SignatureAlgorithm { return sk.info.alg }

// Algorithm returns the composite algorithm identifier for this key.
func (pk *PublicKey) Algorithm() jwa.SignatureAlgorithm { return pk.info.alg }

// Public returns the public half of this private key.
func (sk *PrivateKey) Public() *PublicKey {
	pub, err := sk.info.trad.publicFrom(sk.trad)
	if err != nil {
		// publicFrom only fails on type mismatch, which cannot happen if sk
		// was built via this package.
		panic(fmt.Sprintf("compsig: Public: %s", err))
	}
	return &PublicKey{info: sk.info, mldsa: sk.mldsa.PublicKey(), trad: pub}
}

// MarshalBinary returns the concatenated mldsaSeed || tradPriv encoding used
// by the JWK "priv" field.
func (sk *PrivateKey) MarshalBinary() ([]byte, error) {
	seed := sk.mldsa.Bytes() // 32-byte seed
	tradBytes, err := sk.info.trad.marshalPriv(sk.trad)
	if err != nil {
		return nil, fmt.Errorf(`compsig: marshal priv: %w`, err)
	}
	out := make([]byte, 0, len(seed)+len(tradBytes))
	out = append(out, seed...)
	out = append(out, tradBytes...)
	return out, nil
}

// Bytes is an alias for MarshalBinary.
func (sk *PrivateKey) Bytes() ([]byte, error) { return sk.MarshalBinary() }

// MarshalBinary returns the concatenated mldsaPub || tradPub encoding used
// by the JWK "pub" field.
func (pk *PublicKey) MarshalBinary() ([]byte, error) {
	mldsaPub := pk.mldsa.Bytes()
	tradBytes, err := pk.info.trad.marshalPub(pk.trad)
	if err != nil {
		return nil, fmt.Errorf(`compsig: marshal pub: %w`, err)
	}
	out := make([]byte, 0, len(mldsaPub)+len(tradBytes))
	out = append(out, mldsaPub...)
	out = append(out, tradBytes...)
	return out, nil
}

// Bytes is an alias for MarshalBinary.
func (pk *PublicKey) Bytes() ([]byte, error) { return pk.MarshalBinary() }

// GenerateKey produces a fresh composite key pair for the given composite
// algorithm using crypto/rand.
func GenerateKey(alg jwa.SignatureAlgorithm) (*PrivateKey, error) {
	return GenerateKeyWithRand(alg, rand.Reader)
}

// GenerateKeyWithRand is like GenerateKey but draws randomness from r.
func GenerateKeyWithRand(alg jwa.SignatureAlgorithm, r io.Reader) (*PrivateKey, error) {
	info, ok := lookupAlgInfo(alg)
	if !ok {
		return nil, fmt.Errorf(`compsig: unknown composite algorithm %s`, alg)
	}
	if r == nil {
		r = rand.Reader
	}

	// Draw a fresh 32-byte seed for the ML-DSA component.
	seed := make([]byte, 32)
	if _, err := io.ReadFull(r, seed); err != nil {
		return nil, fmt.Errorf(`compsig: read ml-dsa seed: %w`, err)
	}
	mldsaKey, err := mldsa.NewPrivateKey(info.mldsaParams, seed)
	if err != nil {
		return nil, fmt.Errorf(`compsig: derive ml-dsa key: %w`, err)
	}

	tradPriv, _, err := info.trad.generate(r)
	if err != nil {
		return nil, err
	}

	return &PrivateKey{info: info, mldsa: mldsaKey, trad: tradPriv}, nil
}

// NewPrivateKey reconstructs a composite private key from its raw byte form
// (mldsaSeed || traditionalPriv) for the given algorithm.
func NewPrivateKey(alg jwa.SignatureAlgorithm, raw []byte) (*PrivateKey, error) {
	info, ok := lookupAlgInfo(alg)
	if !ok {
		return nil, fmt.Errorf(`compsig: unknown composite algorithm %s`, alg)
	}
	return newPrivateKeyForInfo(info, raw)
}

func newPrivateKeyForInfo(info *algInfo, raw []byte) (*PrivateKey, error) {
	const seedSize = 32
	want := seedSize + info.trad.privSize
	if len(raw) != want {
		return nil, fmt.Errorf(`compsig: %s priv length %d, want %d`, info.name, len(raw), want)
	}
	mldsaKey, err := mldsa.NewPrivateKey(info.mldsaParams, raw[:seedSize])
	if err != nil {
		return nil, fmt.Errorf(`compsig: %s ml-dsa priv: %w`, info.name, err)
	}
	tradKey, err := info.trad.parsePriv(raw[seedSize:])
	if err != nil {
		return nil, err
	}
	return &PrivateKey{info: info, mldsa: mldsaKey, trad: tradKey}, nil
}

// NewPublicKey reconstructs a composite public key from its raw byte form
// (mldsaPub || traditionalPub) for the given algorithm.
func NewPublicKey(alg jwa.SignatureAlgorithm, raw []byte) (*PublicKey, error) {
	info, ok := lookupAlgInfo(alg)
	if !ok {
		return nil, fmt.Errorf(`compsig: unknown composite algorithm %s`, alg)
	}
	return newPublicKeyForInfo(info, raw)
}

func newPublicKeyForInfo(info *algInfo, raw []byte) (*PublicKey, error) {
	want := info.mldsaPubSize + info.trad.pubSize
	if len(raw) != want {
		return nil, fmt.Errorf(`compsig: %s pub length %d, want %d`, info.name, len(raw), want)
	}
	mldsaKey, err := mldsa.NewPublicKey(info.mldsaParams, raw[:info.mldsaPubSize])
	if err != nil {
		return nil, fmt.Errorf(`compsig: %s ml-dsa pub: %w`, info.name, err)
	}
	tradKey, err := info.trad.parsePub(raw[info.mldsaPubSize:])
	if err != nil {
		return nil, err
	}
	return &PublicKey{info: info, mldsa: mldsaKey, trad: tradKey}, nil
}

// Equal reports whether two composite private keys represent the same
// underlying key material for the same algorithm.
func (sk *PrivateKey) Equal(other *PrivateKey) bool {
	if sk == nil || other == nil || sk.info != other.info {
		return false
	}
	a, err := sk.MarshalBinary()
	if err != nil {
		return false
	}
	b, err := other.MarshalBinary()
	if err != nil {
		return false
	}
	return bytes.Equal(a, b)
}

// Equal reports whether two composite public keys represent the same
// underlying key material for the same algorithm.
func (pk *PublicKey) Equal(other *PublicKey) bool {
	if pk == nil || other == nil || pk.info != other.info {
		return false
	}
	a, err := pk.MarshalBinary()
	if err != nil {
		return false
	}
	b, err := other.MarshalBinary()
	if err != nil {
		return false
	}
	return bytes.Equal(a, b)
}
