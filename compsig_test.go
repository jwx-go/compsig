package compsig_test

import (
	"bytes"
	"testing"

	compsig "github.com/jwx-go/compsig/v4"
	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/stretchr/testify/require"
)

// allAlgs is the canonical list of algorithms driven by the compsig package.
// Every table test should iterate this slice so that adding a variant touches
// one place only.
func allAlgs() []jwa.SignatureAlgorithm {
	return []jwa.SignatureAlgorithm{
		compsig.MLDSA44ES256(),
		compsig.MLDSA65ES256(),
		compsig.MLDSA87ES384(),
		compsig.MLDSA44Ed25519(),
		compsig.MLDSA65Ed25519(),
		compsig.MLDSA87Ed448(),
	}
}

func TestPrefix(t *testing.T) {
	require.Equal(t, "CompositeAlgorithmSignatures2025", compsig.Prefix)
	require.Len(t, compsig.Prefix, 32, "prefix must be 32 bytes per draft §4.2")
}

func TestGenerateKey(t *testing.T) {
	for _, alg := range allAlgs() {
		t.Run(alg.String(), func(t *testing.T) {
			sk, err := compsig.GenerateKey(alg)
			require.NoError(t, err, "GenerateKey")
			require.NotNil(t, sk)
			require.Equal(t, alg, sk.Algorithm())

			pub := sk.Public()
			require.NotNil(t, pub)
			require.Equal(t, alg, pub.Algorithm())
		})
	}
}

func TestKeyMarshalRoundTrip(t *testing.T) {
	for _, alg := range allAlgs() {
		t.Run(alg.String(), func(t *testing.T) {
			sk, err := compsig.GenerateKey(alg)
			require.NoError(t, err)

			privBytes, err := sk.MarshalBinary()
			require.NoError(t, err)
			require.NotEmpty(t, privBytes)

			sk2, err := compsig.NewPrivateKey(alg, privBytes)
			require.NoError(t, err)
			require.True(t, sk.Equal(sk2), "round-tripped private key differs")

			pub := sk.Public()
			pubBytes, err := pub.MarshalBinary()
			require.NoError(t, err)
			require.NotEmpty(t, pubBytes)

			pub2, err := compsig.NewPublicKey(alg, pubBytes)
			require.NoError(t, err)
			require.True(t, pub.Equal(pub2), "round-tripped public key differs")
		})
	}
}

func TestNewPrivateKeyRejectsWrongLength(t *testing.T) {
	_, err := compsig.NewPrivateKey(compsig.MLDSA44ES256(), []byte{0x00})
	require.Error(t, err)
}

func TestNewPublicKeyRejectsWrongLength(t *testing.T) {
	_, err := compsig.NewPublicKey(compsig.MLDSA44ES256(), []byte{0x04})
	require.Error(t, err)
}

func TestNewPublicKeyRejectsCrossAlg(t *testing.T) {
	// ML-DSA public keys differ in length across variants, so loading
	// ML-DSA-44-ES256 bytes as ML-DSA-65-ES256 must be rejected.
	sk, err := compsig.GenerateKey(compsig.MLDSA44ES256())
	require.NoError(t, err)
	raw, err := sk.Public().MarshalBinary()
	require.NoError(t, err)

	_, err = compsig.NewPublicKey(compsig.MLDSA65ES256(), raw)
	require.Error(t, err)
}

func TestMarshalDeterministic(t *testing.T) {
	// Marshaling the same key twice must produce identical bytes.
	for _, alg := range allAlgs() {
		t.Run(alg.String(), func(t *testing.T) {
			sk, err := compsig.GenerateKey(alg)
			require.NoError(t, err)
			a, err := sk.MarshalBinary()
			require.NoError(t, err)
			b, err := sk.MarshalBinary()
			require.NoError(t, err)
			require.True(t, bytes.Equal(a, b))
		})
	}
}
