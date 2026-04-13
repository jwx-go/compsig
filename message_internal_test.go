package compsig

import (
	"bytes"
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestComposeMessageBase64URLEncoded is a regression test for EXT-007:
// draft-ietf-jose-pq-composite-sigs §4.2 step 1 has two lines:
//
//	M' <- Prefix || Label || 0x00 || PH(M)
//	M' <- Encode(M')
//
// For JOSE, Encode(M') is the base64url (no padding) ASCII form of the
// raw byte vector, and that encoded form is what each component signer
// sees. The pre-fix code returned only the raw concatenation, so every
// compsig signature was computed over the wrong bytes and was not
// interoperable with any spec-compliant implementation.
//
// This test asserts the output is valid base64url ASCII, and that it
// decodes back to the expected `Prefix || Label || 0x00 || PH(M)` raw
// bytes for every algorithm variant.
func TestComposeMessageBase64URLEncoded(t *testing.T) {
	payload := []byte("EXT-007 regression payload")
	for _, info := range compSigAlgs {
		t.Run(info.name, func(t *testing.T) {
			got := composeMessage(info, payload)

			// Every byte must be a base64url alphabet character; that
			// alone catches a regression to returning the raw form.
			decoded, err := base64.RawURLEncoding.DecodeString(string(got))
			require.NoError(t, err, `composeMessage output must be base64url`)

			// The decoded bytes must equal Prefix || Label || 0x00 || PH(M).
			ph := info.prehash(payload)
			expectedRaw := make([]byte, 0, len(Prefix)+len(info.label)+1+len(ph))
			expectedRaw = append(expectedRaw, Prefix...)
			expectedRaw = append(expectedRaw, info.label...)
			expectedRaw = append(expectedRaw, 0x00)
			expectedRaw = append(expectedRaw, ph...)
			require.True(t, bytes.Equal(decoded, expectedRaw), `decoded M' must match Prefix || Label || 0x00 || PH(M)`)
		})
	}
}
