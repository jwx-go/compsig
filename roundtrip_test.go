package compsig_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"testing"

	"filippo.io/mldsa"
	compsig "github.com/jwx-go/compsig/v4"
	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jws"
	"github.com/stretchr/testify/require"
)

const testPayload = "hello, composite signature world"

func TestRoundTripRawKeys(t *testing.T) {
	for _, alg := range allAlgs() {
		t.Run(alg.String(), func(t *testing.T) {
			sk, err := compsig.GenerateKey(alg)
			require.NoError(t, err)
			pub := sk.Public()

			signed, err := jws.Sign([]byte(testPayload), jws.WithKey(alg, sk))
			require.NoError(t, err, "jws.Sign")

			got, err := jws.Verify(signed, jws.WithKey(alg, pub))
			require.NoError(t, err, "jws.Verify")
			require.Equal(t, testPayload, string(got))
		})
	}
}

func TestRoundTripJWK(t *testing.T) {
	for _, alg := range allAlgs() {
		t.Run(alg.String(), func(t *testing.T) {
			sk, err := compsig.GenerateKey(alg)
			require.NoError(t, err)

			privJWK, err := jwk.Import[jwk.Key](sk)
			require.NoError(t, err, "jwk.Import private")
			require.Equal(t, jwa.AKP(), privJWK.KeyType())

			privJSON, err := json.Marshal(privJWK)
			require.NoError(t, err, "json.Marshal private")

			privParsed, err := jwk.ParseKeyAs[jwk.Key](privJSON)
			require.NoError(t, err, "jwk.ParseKey private")

			pubJWK, err := privJWK.PublicKey()
			require.NoError(t, err, "PublicKey")
			pubJSON, err := json.Marshal(pubJWK)
			require.NoError(t, err, "json.Marshal public")
			pubParsed, err := jwk.ParseKeyAs[jwk.Key](pubJSON)
			require.NoError(t, err, "jwk.ParseKey public")

			signed, err := jws.Sign([]byte(testPayload), jws.WithKey(alg, privParsed))
			require.NoError(t, err, "jws.Sign with parsed JWK")

			got, err := jws.Verify(signed, jws.WithKey(alg, pubParsed))
			require.NoError(t, err, "jws.Verify with parsed JWK")
			require.Equal(t, testPayload, string(got))
		})
	}
}

func TestTamperedPayloadFails(t *testing.T) {
	for _, alg := range allAlgs() {
		t.Run(alg.String(), func(t *testing.T) {
			sk, err := compsig.GenerateKey(alg)
			require.NoError(t, err)

			signed, err := jws.Sign([]byte(testPayload), jws.WithKey(alg, sk))
			require.NoError(t, err)

			// Flip a bit in the payload portion and expect verification to fail.
			// The compact JWS format is header.payload.signature, so mangling
			// the last byte of the payload section is enough.
			tampered := append([]byte(nil), signed...)
			dotCount := 0
			for i, c := range tampered {
				if c != '.' {
					continue
				}
				dotCount++
				if dotCount == 2 {
					// Tamper the byte just before the second dot.
					tampered[i-1] ^= 0x01
					break
				}
			}

			_, err = jws.Verify(tampered, jws.WithKey(alg, sk.Public()))
			require.Error(t, err, "tampered payload must not verify")
		})
	}
}

func TestTamperedMLDSAHalfFails(t *testing.T) {
	// Directly exercise the dsig-level Sign/Verify via the raw
	// PrivateKey so we can corrupt the first mldsaSigSize bytes of the
	// signature and confirm the ML-DSA half is checked.
	for _, alg := range allAlgs() {
		t.Run(alg.String(), func(t *testing.T) {
			sk, err := compsig.GenerateKey(alg)
			require.NoError(t, err)

			signed, err := jws.Sign([]byte(testPayload), jws.WithKey(alg, sk))
			require.NoError(t, err)

			// Flip a byte inside the JWS signature segment (after the second dot).
			tampered := append([]byte(nil), signed...)
			secondDot := findNthDot(tampered, 2)
			require.Greater(t, secondDot, 0)
			tampered[secondDot+1] ^= 0x01

			_, err = jws.Verify(tampered, jws.WithKey(alg, sk.Public()))
			require.Error(t, err, "tampered ML-DSA half must not verify")
		})
	}
}

func TestSignerRejectsMismatchedPub(t *testing.T) {
	// Regression: the signer must refuse to sign with a JWK whose "pub"
	// field disagrees with the public half derived from "priv". The
	// exporter already enforces this; the signer used to not.
	for _, alg := range allAlgs() {
		t.Run(alg.String(), func(t *testing.T) {
			sk, err := compsig.GenerateKey(alg)
			require.NoError(t, err)

			privJWK, err := jwk.Import[jwk.Key](sk)
			require.NoError(t, err)

			pubV, ok := privJWK.Field(jwk.AKPPubKey)
			require.True(t, ok)
			pubBytes, ok := pubV.([]byte)
			require.True(t, ok)

			// Flip a single byte in "pub" to break the pub/priv binding
			// without changing its length.
			tampered := append([]byte(nil), pubBytes...)
			tampered[0] ^= 0x01
			require.NoError(t, privJWK.Set(jwk.AKPPubKey, tampered))

			_, err = jws.Sign([]byte(testPayload), jws.WithKey(alg, privJWK))
			require.Error(t, err, "signer must reject JWK with mismatched pub")
		})
	}
}

func findNthDot(s []byte, n int) int {
	count := 0
	for i, c := range s {
		if c != '.' {
			continue
		}
		count++
		if count == n {
			return i
		}
	}
	return -1
}

// retampedSignature replaces the signature segment of a compact JWS
// with the supplied raw bytes (re-encoded as base64url-without-padding).
// Returns the rewritten JWS.
func retampedSignature(t *testing.T, signed, newSigBytes []byte) []byte {
	t.Helper()
	secondDot := findNthDot(signed, 2)
	require.Greater(t, secondDot, 0, "JWS must have at least two dots")
	prefix := append([]byte(nil), signed[:secondDot+1]...)
	return append(prefix, []byte(base64.RawURLEncoding.EncodeToString(newSigBytes))...)
}

// rawSignature decodes the JWS signature segment back to the raw
// (mldsaSig || tradSig) bytes.
func rawSignature(t *testing.T, signed []byte) []byte {
	t.Helper()
	secondDot := findNthDot(signed, 2)
	require.Greater(t, secondDot, 0)
	raw, err := base64.RawURLEncoding.DecodeString(string(signed[secondDot+1:]))
	require.NoError(t, err)
	return raw
}

// TestTradSigLengthGate pins the composite-layer length check on the
// trailing component. The check is defense-in-depth: every in-tree
// traditional verifier rejects wrong-length input, but a future
// variant whose verifier ignores trailing bytes would let
// `mldsaSig || tradSig || JUNK` verify and amplify a forgery.
func TestTradSigLengthGate(t *testing.T) {
	t.Run("Ed25519 (fixed): truncated tradSig rejected", func(t *testing.T) {
		alg := compsig.MLDSA44Ed25519()
		sk, err := compsig.GenerateKey(alg)
		require.NoError(t, err)

		signed, err := jws.Sign([]byte(testPayload), jws.WithKey(alg, sk))
		require.NoError(t, err)

		raw := rawSignature(t, signed)
		// Drop the last byte of tradSig; len(tradSig) becomes 63
		// instead of the required 64.
		tampered := retampedSignature(t, signed, raw[:len(raw)-1])

		_, err = jws.Verify(tampered, jws.WithKey(alg, sk.Public()))
		require.Error(t, err)
		require.Contains(t, err.Error(), "does not match expected",
			"composite layer must reject wrong-length Ed25519 tradSig")
	})

	t.Run("Ed25519 (fixed): oversize tradSig rejected", func(t *testing.T) {
		alg := compsig.MLDSA44Ed25519()
		sk, err := compsig.GenerateKey(alg)
		require.NoError(t, err)

		signed, err := jws.Sign([]byte(testPayload), jws.WithKey(alg, sk))
		require.NoError(t, err)

		raw := rawSignature(t, signed)
		// Append a junk byte to push tradSig past 64.
		tampered := retampedSignature(t, signed, append(append([]byte(nil), raw...), 0xff))

		_, err = jws.Verify(tampered, jws.WithKey(alg, sk.Public()))
		require.Error(t, err)
		require.Contains(t, err.Error(), "does not match expected")
	})

	t.Run("ECDSA P-256 (variable): empty tradSig rejected", func(t *testing.T) {
		alg := compsig.MLDSA44ES256()
		sk, err := compsig.GenerateKey(alg)
		require.NoError(t, err)

		signed, err := jws.Sign([]byte(testPayload), jws.WithKey(alg, sk))
		require.NoError(t, err)

		mldsaSize := mldsa.MLDSA44().SignatureSize()
		raw := rawSignature(t, signed)
		require.Len(t, raw, mldsaSize+len(raw)-mldsaSize) // sanity
		require.Greater(t, len(raw), mldsaSize)

		// Truncate to exactly mldsaSigSize: empty tradSig.
		tampered := retampedSignature(t, signed, raw[:mldsaSize])

		_, err = jws.Verify(tampered, jws.WithKey(alg, sk.Public()))
		require.Error(t, err)
		require.Contains(t, err.Error(), "is empty",
			"composite layer must reject empty ECDSA tradSig")
	})

	t.Run("ECDSA P-256 (variable): oversize tradSig rejected", func(t *testing.T) {
		alg := compsig.MLDSA44ES256()
		sk, err := compsig.GenerateKey(alg)
		require.NoError(t, err)

		signed, err := jws.Sign([]byte(testPayload), jws.WithKey(alg, sk))
		require.NoError(t, err)

		// Append 100 bytes of junk to push tradSig past the 72-byte
		// P-256 maximum.
		raw := rawSignature(t, signed)
		oversize := append(append([]byte(nil), raw...), bytes.Repeat([]byte{0xff}, 100)...)
		tampered := retampedSignature(t, signed, oversize)

		_, err = jws.Verify(tampered, jws.WithKey(alg, sk.Public()))
		require.Error(t, err)
		require.Contains(t, err.Error(), "exceeds maximum",
			"composite layer must reject oversized ECDSA tradSig")
	})
}
