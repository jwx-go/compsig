package compsig_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"testing"

	compsig "github.com/jwx-go/compsig/v4"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jws"
	"github.com/stretchr/testify/require"
)

func FuzzSignAndVerifyMLDSA44ES256(f *testing.F) {
	f.Add([]byte("Hello, composite world!"))
	f.Add([]byte(""))
	f.Add([]byte(`{"iss":"test"}`))

	alg := compsig.MLDSA44ES256()
	sk, err := compsig.GenerateKey(alg)
	if err != nil {
		f.Fatal(err)
	}
	pub := sk.Public()

	f.Fuzz(func(t *testing.T, payload []byte) {
		signed, err := jws.Sign(payload, jws.WithKey(alg, sk))
		require.NoError(t, err)

		verified, err := jws.Verify(signed, jws.WithKey(alg, pub))
		require.NoError(t, err)
		require.Equal(t, payload, verified)
	})
}

func FuzzSignAndVerifyMLDSA65Ed25519(f *testing.F) {
	f.Add([]byte("Hello, composite world!"))
	f.Add([]byte(""))
	f.Add([]byte(`{"iss":"test"}`))

	alg := compsig.MLDSA65Ed25519()
	sk, err := compsig.GenerateKey(alg)
	if err != nil {
		f.Fatal(err)
	}
	pub := sk.Public()

	f.Fuzz(func(t *testing.T, payload []byte) {
		signed, err := jws.Sign(payload, jws.WithKey(alg, sk))
		require.NoError(t, err)

		verified, err := jws.Verify(signed, jws.WithKey(alg, pub))
		require.NoError(t, err)
		require.Equal(t, payload, verified)
	})
}

// FuzzVerifyTamperedSignature checks that jws.Verify rejects an arbitrary
// replacement of the signature segment of an otherwise well-formed compact
// JWS, and never panics while doing so. The header/payload prefix and the
// genuine signature bytes are computed once in the seed stage; the fuzz
// input only supplies the bytes that replace the signature segment.
func FuzzVerifyTamperedSignature(f *testing.F) {
	alg := compsig.MLDSA44ES256()
	sk, err := compsig.GenerateKey(alg)
	if err != nil {
		f.Fatal(err)
	}
	pub := sk.Public()

	signed, err := jws.Sign([]byte("tamper target payload"), jws.WithKey(alg, sk))
	if err != nil {
		f.Fatal(err)
	}

	lastDot := bytes.LastIndexByte(signed, '.')
	if lastDot < 0 {
		f.Fatal("compact JWS is missing the signature segment")
	}
	prefix := append([]byte(nil), signed[:lastDot+1]...)

	genuineSig, err := base64.RawURLEncoding.DecodeString(string(signed[lastDot+1:]))
	if err != nil {
		f.Fatal(err)
	}

	f.Add(genuineSig)
	f.Add([]byte{})
	f.Add(genuineSig[:len(genuineSig)/2])
	flipped := append([]byte(nil), genuineSig...)
	flipped[0] ^= 0x01
	f.Add(flipped)

	f.Fuzz(func(t *testing.T, sigBytes []byte) {
		tampered := append(append([]byte(nil), prefix...), []byte(base64.RawURLEncoding.EncodeToString(sigBytes))...)

		_, err := jws.Verify(tampered, jws.WithKey(alg, pub))
		if bytes.Equal(sigBytes, genuineSig) {
			require.NoError(t, err, "reproducing the genuine signature must verify")
			return
		}
		require.Error(t, err, "a tampered signature must not verify")
	})
}

// FuzzParseJWK checks that the composite JWK parser (kty "AKP" with a
// composite "alg") never panics on arbitrary input, including inputs that
// happen to parse successfully and are then round-tripped through
// marshal/parse again.
func FuzzParseJWK(f *testing.F) {
	alg := compsig.MLDSA44ES256()
	sk, err := compsig.GenerateKey(alg)
	if err != nil {
		f.Fatal(err)
	}
	jwkKey, err := jwk.Import[jwk.Key](sk)
	if err != nil {
		f.Fatal(err)
	}
	genuineJSON, err := json.Marshal(jwkKey)
	if err != nil {
		f.Fatal(err)
	}

	f.Add(genuineJSON)
	f.Add([]byte(""))
	f.Add([]byte("not-json"))
	f.Add(genuineJSON[:len(genuineJSON)/2])

	mutated := append([]byte(nil), genuineJSON...)
	if len(mutated) > 0 {
		mutated[len(mutated)/2] ^= 0x01
	}
	f.Add(mutated)

	f.Fuzz(func(_ *testing.T, data []byte) {
		parsed, err := jwk.ParseKey(data)
		if err != nil {
			return
		}

		buf, err := json.Marshal(parsed)
		if err != nil {
			return
		}

		_, _ = jwk.ParseKey(buf)
	})
}
