package compsig_test

import (
	"encoding/json"
	"testing"

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

			privParsed, err := jwk.ParseKey[jwk.Key](privJSON)
			require.NoError(t, err, "jwk.ParseKey private")

			pubJWK, err := privJWK.PublicKey()
			require.NoError(t, err, "PublicKey")
			pubJSON, err := json.Marshal(pubJWK)
			require.NoError(t, err, "json.Marshal public")
			pubParsed, err := jwk.ParseKey[jwk.Key](pubJSON)
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
