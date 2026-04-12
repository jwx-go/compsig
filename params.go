package compsig

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha3"
	"crypto/sha512"
	"errors"
	"fmt"
	"io"
	"math/big"

	"filippo.io/mldsa"
	"github.com/cloudflare/circl/sign/ed448"
	"github.com/lestrrat-go/dsig"
	"github.com/lestrrat-go/jwx/v4/jwa"
)

// Prefix is the fixed 32-byte ASCII domain separator defined in
// draft-ietf-jose-pq-composite-sigs §4.2.
const Prefix = "CompositeAlgorithmSignatures2025"

// MLDSA44ES256 returns the ML-DSA-44 + ECDSA P-256 composite signature algorithm identifier.
func MLDSA44ES256() jwa.SignatureAlgorithm { return algMLDSA44ES256 }

// MLDSA65ES256 returns the ML-DSA-65 + ECDSA P-256 composite signature algorithm identifier.
func MLDSA65ES256() jwa.SignatureAlgorithm { return algMLDSA65ES256 }

// MLDSA87ES384 returns the ML-DSA-87 + ECDSA P-384 composite signature algorithm identifier.
func MLDSA87ES384() jwa.SignatureAlgorithm { return algMLDSA87ES384 }

// MLDSA44Ed25519 returns the ML-DSA-44 + Ed25519 composite signature algorithm identifier.
func MLDSA44Ed25519() jwa.SignatureAlgorithm { return algMLDSA44Ed25519 }

// MLDSA65Ed25519 returns the ML-DSA-65 + Ed25519 composite signature algorithm identifier.
func MLDSA65Ed25519() jwa.SignatureAlgorithm { return algMLDSA65Ed25519 }

// MLDSA87Ed448 returns the ML-DSA-87 + Ed448 composite signature algorithm identifier.
func MLDSA87Ed448() jwa.SignatureAlgorithm { return algMLDSA87Ed448 }

var (
	algMLDSA44ES256   = jwa.NewSignatureAlgorithm("ML-DSA-44-ES256")
	algMLDSA65ES256   = jwa.NewSignatureAlgorithm("ML-DSA-65-ES256")
	algMLDSA87ES384   = jwa.NewSignatureAlgorithm("ML-DSA-87-ES384")
	algMLDSA44Ed25519 = jwa.NewSignatureAlgorithm("ML-DSA-44-Ed25519")
	algMLDSA65Ed25519 = jwa.NewSignatureAlgorithm("ML-DSA-65-Ed25519")
	algMLDSA87Ed448   = jwa.NewSignatureAlgorithm("ML-DSA-87-Ed448")
)

// traditionalOps encapsulates the per-algorithm operations for the "T" half
// of a composite ML-DSA + T signature.
type traditionalOps struct {
	pubSize  int // marshaled public key size
	privSize int // marshaled private key size

	generate    func(r io.Reader) (priv any, pub any, err error)
	parsePriv   func(raw []byte) (any, error)
	parsePub    func(raw []byte) (any, error)
	marshalPriv func(key any) ([]byte, error)
	marshalPub  func(key any) ([]byte, error)
	publicFrom  func(priv any) (any, error)
	sign        func(priv any, mPrime []byte, r io.Reader) ([]byte, error)
	verify      func(pub any, mPrime, sig []byte) error
}

// algInfo drives registration, signing, and verification for a single
// composite variant. Every composite algorithm is described by exactly one
// entry in compSigAlgs.
type algInfo struct {
	name         string
	alg          jwa.SignatureAlgorithm
	mldsaAlgName string // matches the algorithm name registered by jwx-go/mldsa
	mldsaParams  *mldsa.Parameters
	mldsaSigSize int
	mldsaPubSize int
	label        []byte
	prehash      func(msg []byte) []byte
	trad         *traditionalOps
}

// compSigAlgs is the canonical table of all six composite algorithms.
// Ordered by ML-DSA security level then traditional algorithm for readability.
var compSigAlgs = []*algInfo{
	{
		name:         "ML-DSA-44-ES256",
		alg:          algMLDSA44ES256,
		mldsaAlgName: "ML-DSA-44",
		mldsaParams:  mldsa.MLDSA44(),
		mldsaSigSize: mldsa.MLDSA44().SignatureSize(),
		mldsaPubSize: mldsa.MLDSA44().PublicKeySize(),
		label:        []byte("COMPSIG-MLDSA44-ECDSA-P256-SHA256"),
		prehash:      prehashSHA256,
		trad:         ecdsaP256Ops,
	},
	{
		name:         "ML-DSA-65-ES256",
		alg:          algMLDSA65ES256,
		mldsaAlgName: "ML-DSA-65",
		mldsaParams:  mldsa.MLDSA65(),
		mldsaSigSize: mldsa.MLDSA65().SignatureSize(),
		mldsaPubSize: mldsa.MLDSA65().PublicKeySize(),
		label:        []byte("COMPSIG-MLDSA65-ECDSA-P256-SHA512"),
		prehash:      prehashSHA512,
		trad:         ecdsaP256Ops,
	},
	{
		name:         "ML-DSA-87-ES384",
		alg:          algMLDSA87ES384,
		mldsaAlgName: "ML-DSA-87",
		mldsaParams:  mldsa.MLDSA87(),
		mldsaSigSize: mldsa.MLDSA87().SignatureSize(),
		mldsaPubSize: mldsa.MLDSA87().PublicKeySize(),
		label:        []byte("COMPSIG-MLDSA87-ECDSA-P384-SHA512"),
		prehash:      prehashSHA512,
		trad:         ecdsaP384Ops,
	},
	{
		name:         "ML-DSA-44-Ed25519",
		alg:          algMLDSA44Ed25519,
		mldsaAlgName: "ML-DSA-44",
		mldsaParams:  mldsa.MLDSA44(),
		mldsaSigSize: mldsa.MLDSA44().SignatureSize(),
		mldsaPubSize: mldsa.MLDSA44().PublicKeySize(),
		label:        []byte("COMPSIG-MLDSA44-Ed25519-SHA512"),
		prehash:      prehashSHA512,
		trad:         ed25519Ops,
	},
	{
		name:         "ML-DSA-65-Ed25519",
		alg:          algMLDSA65Ed25519,
		mldsaAlgName: "ML-DSA-65",
		mldsaParams:  mldsa.MLDSA65(),
		mldsaSigSize: mldsa.MLDSA65().SignatureSize(),
		mldsaPubSize: mldsa.MLDSA65().PublicKeySize(),
		label:        []byte("COMPSIG-MLDSA65-Ed25519-SHA512"),
		prehash:      prehashSHA512,
		trad:         ed25519Ops,
	},
	{
		name:         "ML-DSA-87-Ed448",
		alg:          algMLDSA87Ed448,
		mldsaAlgName: "ML-DSA-87",
		mldsaParams:  mldsa.MLDSA87(),
		mldsaSigSize: mldsa.MLDSA87().SignatureSize(),
		mldsaPubSize: mldsa.MLDSA87().PublicKeySize(),
		label:        []byte("COMPSIG-MLDSA87-Ed448-SHAKE256"),
		prehash:      prehashSHAKE256_64,
		trad:         ed448Ops,
	},
}

func lookupAlgInfo(alg jwa.SignatureAlgorithm) (*algInfo, bool) {
	name := alg.String()
	for _, info := range compSigAlgs {
		if info.name == name {
			return info, true
		}
	}
	return nil, false
}

func lookupAlgInfoByName(name string) (*algInfo, bool) {
	for _, info := range compSigAlgs {
		if info.name == name {
			return info, true
		}
	}
	return nil, false
}

// --- Pre-hash functions ---

func prehashSHA256(msg []byte) []byte {
	h := sha256.Sum256(msg)
	return h[:]
}

func prehashSHA512(msg []byte) []byte {
	h := sha512.Sum512(msg)
	return h[:]
}

func prehashSHAKE256_64(msg []byte) []byte {
	return sha3.SumSHAKE256(msg, 64)
}

// --- Traditional operations: ECDSA P-256 / P-384 ---

// ES256 and ES384 use ASN.1 DER-encoded Ecdsa-Sig-Value per the LAMPS
// SerializeSignatureValue routine that the JOSE composite draft inherits.
// This differs from the JWS r||s format, so ECDSA operations dispatch through
// dsig.SignECDSADER / VerifyECDSADER (added in dsig v1.2.2) rather than the
// jwsbb "ES256"/"ES384" path which produces r||s.

var ecdsaP256Ops = &traditionalOps{
	pubSize:     65, // 0x04 || X(32) || Y(32)
	privSize:    32, // scalar d (P-256 field size)
	generate:    func(r io.Reader) (any, any, error) { return generateECDSA(elliptic.P256(), r) },
	parsePriv:   func(raw []byte) (any, error) { return parseECDSAPriv(elliptic.P256(), raw) },
	parsePub:    func(raw []byte) (any, error) { return parseECDSAPub(elliptic.P256(), raw) },
	marshalPriv: marshalECDSAPriv,
	marshalPub:  marshalECDSAPub,
	publicFrom:  ecdsaPublicFrom,
	sign:        ecdsaDERSigner(crypto.SHA256),
	verify:      ecdsaDERVerifier(crypto.SHA256),
}

var ecdsaP384Ops = &traditionalOps{
	pubSize:     97, // 0x04 || X(48) || Y(48)
	privSize:    48, // scalar d (P-384 field size)
	generate:    func(r io.Reader) (any, any, error) { return generateECDSA(elliptic.P384(), r) },
	parsePriv:   func(raw []byte) (any, error) { return parseECDSAPriv(elliptic.P384(), raw) },
	parsePub:    func(raw []byte) (any, error) { return parseECDSAPub(elliptic.P384(), raw) },
	marshalPriv: marshalECDSAPriv,
	marshalPub:  marshalECDSAPub,
	publicFrom:  ecdsaPublicFrom,
	sign:        ecdsaDERSigner(crypto.SHA384),
	verify:      ecdsaDERVerifier(crypto.SHA384),
}

func ecdsaDERSigner(h crypto.Hash) func(priv any, mPrime []byte, r io.Reader) ([]byte, error) {
	return func(priv any, mPrime []byte, r io.Reader) ([]byte, error) {
		sk, ok := priv.(*ecdsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf(`compsig: expected *ecdsa.PrivateKey, got %T`, priv)
		}
		return dsig.SignECDSADER(sk, mPrime, h, r)
	}
}

func ecdsaDERVerifier(h crypto.Hash) func(pub any, mPrime, sig []byte) error {
	return func(pub any, mPrime, sig []byte) error {
		pk, ok := pub.(*ecdsa.PublicKey)
		if !ok {
			return fmt.Errorf(`compsig: expected *ecdsa.PublicKey, got %T`, pub)
		}
		return dsig.VerifyECDSADER(pk, mPrime, sig, h)
	}
}

func generateECDSA(curve elliptic.Curve, r io.Reader) (any, any, error) {
	if r == nil {
		r = rand.Reader
	}
	priv, err := ecdsa.GenerateKey(curve, r)
	if err != nil {
		return nil, nil, fmt.Errorf(`compsig: ecdsa keygen: %w`, err)
	}
	return priv, &priv.PublicKey, nil
}

func parseECDSAPriv(curve elliptic.Curve, raw []byte) (any, error) {
	byteLen := (curve.Params().BitSize + 7) / 8
	if len(raw) != byteLen {
		return nil, fmt.Errorf(`compsig: ecdsa priv length %d, want %d`, len(raw), byteLen)
	}
	d := new(big.Int).SetBytes(raw)
	if d.Sign() == 0 || d.Cmp(curve.Params().N) >= 0 {
		return nil, errors.New(`compsig: ecdsa priv scalar out of range`)
	}
	x, y := curve.ScalarBaseMult(raw)
	return &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{Curve: curve, X: x, Y: y},
		D:         d,
	}, nil
}

func parseECDSAPub(curve elliptic.Curve, raw []byte) (any, error) {
	byteLen := (curve.Params().BitSize + 7) / 8
	if len(raw) != 1+2*byteLen {
		return nil, fmt.Errorf(`compsig: ecdsa pub length %d, want %d`, len(raw), 1+2*byteLen)
	}
	if raw[0] != 0x04 {
		return nil, fmt.Errorf(`compsig: ecdsa pub first byte %#x, want 0x04 (uncompressed)`, raw[0])
	}
	x := new(big.Int).SetBytes(raw[1 : 1+byteLen])
	y := new(big.Int).SetBytes(raw[1+byteLen:])
	if !curve.IsOnCurve(x, y) {
		return nil, errors.New(`compsig: ecdsa pub point not on curve`)
	}
	return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
}

func marshalECDSAPriv(key any) ([]byte, error) {
	sk, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf(`compsig: expected *ecdsa.PrivateKey, got %T`, key)
	}
	byteLen := (sk.Curve.Params().BitSize + 7) / 8
	out := make([]byte, byteLen)
	d := sk.D.Bytes()
	copy(out[byteLen-len(d):], d)
	return out, nil
}

func marshalECDSAPub(key any) ([]byte, error) {
	pk, ok := key.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf(`compsig: expected *ecdsa.PublicKey, got %T`, key)
	}
	byteLen := (pk.Curve.Params().BitSize + 7) / 8
	out := make([]byte, 1+2*byteLen)
	out[0] = 0x04
	x := pk.X.Bytes()
	y := pk.Y.Bytes()
	copy(out[1+byteLen-len(x):1+byteLen], x)
	copy(out[1+2*byteLen-len(y):], y)
	return out, nil
}

func ecdsaPublicFrom(priv any) (any, error) {
	sk, ok := priv.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf(`compsig: expected *ecdsa.PrivateKey, got %T`, priv)
	}
	return &sk.PublicKey, nil
}

// --- Traditional operations: Ed25519 (stdlib) ---

var ed25519Ops = &traditionalOps{
	pubSize:     ed25519.PublicKeySize, // 32
	privSize:    ed25519.SeedSize,      // 32
	generate:    generateEd25519,
	parsePriv:   parseEd25519Priv,
	parsePub:    parseEd25519Pub,
	marshalPriv: marshalEd25519Priv,
	marshalPub:  marshalEd25519Pub,
	publicFrom:  ed25519PublicFrom,
	sign:        ed25519Sign,
	verify:      ed25519Verify,
}

func generateEd25519(r io.Reader) (any, any, error) {
	if r == nil {
		r = rand.Reader
	}
	pub, priv, err := ed25519.GenerateKey(r)
	if err != nil {
		return nil, nil, fmt.Errorf(`compsig: ed25519 keygen: %w`, err)
	}
	return priv, pub, nil
}

func parseEd25519Priv(raw []byte) (any, error) {
	if len(raw) != ed25519.SeedSize {
		return nil, fmt.Errorf(`compsig: ed25519 seed length %d, want %d`, len(raw), ed25519.SeedSize)
	}
	return ed25519.NewKeyFromSeed(raw), nil
}

func parseEd25519Pub(raw []byte) (any, error) {
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf(`compsig: ed25519 pub length %d, want %d`, len(raw), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(append([]byte(nil), raw...)), nil
}

func marshalEd25519Priv(key any) ([]byte, error) {
	sk, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf(`compsig: expected ed25519.PrivateKey, got %T`, key)
	}
	return append([]byte(nil), sk.Seed()...), nil
}

func marshalEd25519Pub(key any) ([]byte, error) {
	pk, ok := key.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf(`compsig: expected ed25519.PublicKey, got %T`, key)
	}
	return append([]byte(nil), pk...), nil
}

func ed25519PublicFrom(priv any) (any, error) {
	sk, ok := priv.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf(`compsig: expected ed25519.PrivateKey, got %T`, priv)
	}
	pub, ok := sk.Public().(ed25519.PublicKey)
	if !ok {
		return nil, errors.New(`compsig: ed25519 public key type mismatch`)
	}
	return pub, nil
}

func ed25519Sign(priv any, mPrime []byte, _ io.Reader) ([]byte, error) {
	sk, ok := priv.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf(`compsig: expected ed25519.PrivateKey, got %T`, priv)
	}
	return ed25519.Sign(sk, mPrime), nil
}

func ed25519Verify(pub any, mPrime, sig []byte) error {
	pk, ok := pub.(ed25519.PublicKey)
	if !ok {
		return fmt.Errorf(`compsig: expected ed25519.PublicKey, got %T`, pub)
	}
	if !ed25519.Verify(pk, mPrime, sig) {
		return errors.New(`compsig: ed25519 signature invalid`)
	}
	return nil
}

// --- Traditional operations: Ed448 (cloudflare/circl) ---

var ed448Ops = &traditionalOps{
	pubSize:     ed448.PublicKeySize, // 57
	privSize:    ed448.SeedSize,      // 57
	generate:    generateEd448,
	parsePriv:   parseEd448Priv,
	parsePub:    parseEd448Pub,
	marshalPriv: marshalEd448Priv,
	marshalPub:  marshalEd448Pub,
	publicFrom:  ed448PublicFrom,
	sign:        ed448Sign,
	verify:      ed448Verify,
}

func generateEd448(r io.Reader) (any, any, error) {
	if r == nil {
		r = rand.Reader
	}
	pub, priv, err := ed448.GenerateKey(r)
	if err != nil {
		return nil, nil, fmt.Errorf(`compsig: ed448 keygen: %w`, err)
	}
	return priv, pub, nil
}

func parseEd448Priv(raw []byte) (any, error) {
	if len(raw) != ed448.SeedSize {
		return nil, fmt.Errorf(`compsig: ed448 seed length %d, want %d`, len(raw), ed448.SeedSize)
	}
	return ed448.NewKeyFromSeed(raw), nil
}

func parseEd448Pub(raw []byte) (any, error) {
	if len(raw) != ed448.PublicKeySize {
		return nil, fmt.Errorf(`compsig: ed448 pub length %d, want %d`, len(raw), ed448.PublicKeySize)
	}
	return ed448.PublicKey(append([]byte(nil), raw...)), nil
}

func marshalEd448Priv(key any) ([]byte, error) {
	sk, ok := key.(ed448.PrivateKey)
	if !ok {
		return nil, fmt.Errorf(`compsig: expected ed448.PrivateKey, got %T`, key)
	}
	return sk.Seed(), nil
}

func marshalEd448Pub(key any) ([]byte, error) {
	pk, ok := key.(ed448.PublicKey)
	if !ok {
		return nil, fmt.Errorf(`compsig: expected ed448.PublicKey, got %T`, key)
	}
	return append([]byte(nil), pk...), nil
}

func ed448PublicFrom(priv any) (any, error) {
	sk, ok := priv.(ed448.PrivateKey)
	if !ok {
		return nil, fmt.Errorf(`compsig: expected ed448.PrivateKey, got %T`, priv)
	}
	pub, ok := sk.Public().(ed448.PublicKey)
	if !ok {
		return nil, errors.New(`compsig: ed448 public type mismatch`)
	}
	return pub, nil
}

func ed448Sign(priv any, mPrime []byte, _ io.Reader) ([]byte, error) {
	sk, ok := priv.(ed448.PrivateKey)
	if !ok {
		return nil, fmt.Errorf(`compsig: expected ed448.PrivateKey, got %T`, priv)
	}
	// circl Ed448: context must be empty for the composite construction.
	return ed448.Sign(sk, mPrime, ""), nil
}

func ed448Verify(pub any, mPrime, sig []byte) error {
	pk, ok := pub.(ed448.PublicKey)
	if !ok {
		return fmt.Errorf(`compsig: expected ed448.PublicKey, got %T`, pub)
	}
	if !ed448.Verify(pk, mPrime, sig, "") {
		return errors.New(`compsig: ed448 signature invalid`)
	}
	return nil
}
