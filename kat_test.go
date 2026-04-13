package compsig

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// XCUT-009 / EXT-008 Known Answer Tests.
//
// Pins the exact base64url ASCII bytes produced by composeMessage for a
// fixed payload, one entry per composite variant. This guards the
// Prefix || Label || 0x00 || PH(M) construction and its base64url encoding
// — the two pieces that EXT-006 (missing per-variant ML-DSA context label)
// and EXT-007 (missing base64url encoding of M') got wrong and that were
// only caught by post-hoc review. End-to-end sign+verify is already exercised
// by roundtrip_test.go; ML-DSA signing is randomized, so pinning signature
// bytes would require checking in tens of KB of per-variant hex and is not
// worth the bloat over what roundtrip_test.go + this KAT already cover.

const katComposePayload = "XCUT-009 KAT payload"

// katComposeExpected is the pinned base64url(no-padding) ASCII output of
// composeMessage for katComposePayload, one entry per variant.
//
// To regenerate (if the spec label table or pre-hash changes):
//
//	go test -run TestComposeMessageKAT -v ./...
//
// then paste the printed actuals into the map below.
var katComposeExpected = map[string]string{
	"ML-DSA-44-ES256":   "Q29tcG9zaXRlQWxnb3JpdGhtU2lnbmF0dXJlczIwMjVDT01QU0lHLU1MRFNBNDQtRUNEU0EtUDI1Ni1TSEEyNTYAogwKMJ2Uhyx-I_2_nBkfIpYvwd5RRFgCssXRD1iFrlk",
	"ML-DSA-65-ES256":   "Q29tcG9zaXRlQWxnb3JpdGhtU2lnbmF0dXJlczIwMjVDT01QU0lHLU1MRFNBNjUtRUNEU0EtUDI1Ni1TSEE1MTIA77aS1R9Pzv6iffOKMvuj1s6R92xtpPYBVzqZ3mE1dyuLlAFIA4OFr95gy5L6wnaQ3pwnN31Ng8UcFfLdd2njJw",
	"ML-DSA-87-ES384":   "Q29tcG9zaXRlQWxnb3JpdGhtU2lnbmF0dXJlczIwMjVDT01QU0lHLU1MRFNBODctRUNEU0EtUDM4NC1TSEE1MTIA77aS1R9Pzv6iffOKMvuj1s6R92xtpPYBVzqZ3mE1dyuLlAFIA4OFr95gy5L6wnaQ3pwnN31Ng8UcFfLdd2njJw",
	"ML-DSA-44-Ed25519": "Q29tcG9zaXRlQWxnb3JpdGhtU2lnbmF0dXJlczIwMjVDT01QU0lHLU1MRFNBNDQtRWQyNTUxOS1TSEE1MTIA77aS1R9Pzv6iffOKMvuj1s6R92xtpPYBVzqZ3mE1dyuLlAFIA4OFr95gy5L6wnaQ3pwnN31Ng8UcFfLdd2njJw",
	"ML-DSA-65-Ed25519": "Q29tcG9zaXRlQWxnb3JpdGhtU2lnbmF0dXJlczIwMjVDT01QU0lHLU1MRFNBNjUtRWQyNTUxOS1TSEE1MTIA77aS1R9Pzv6iffOKMvuj1s6R92xtpPYBVzqZ3mE1dyuLlAFIA4OFr95gy5L6wnaQ3pwnN31Ng8UcFfLdd2njJw",
	"ML-DSA-87-Ed448":   "Q29tcG9zaXRlQWxnb3JpdGhtU2lnbmF0dXJlczIwMjVDT01QU0lHLU1MRFNBODctRWQ0NDgtU0hBS0UyNTYAZNcZced6ucCY0bs36NLug0lkSNlAkGZrwO68bA1OcHFm_pSVk407l5lSoQOQgW8djSu8wFxKUNj_6X_yx-P5Ww",
}

func TestComposeMessageKAT(t *testing.T) {
	for _, info := range compSigAlgs {
		t.Run(info.name, func(t *testing.T) {
			got := string(composeMessage(info, []byte(katComposePayload)))
			want, ok := katComposeExpected[info.name]
			require.True(t, ok, "missing katComposeExpected entry for %s", info.name)
			require.Equal(t, want, got,
				"composeMessage M' KAT mismatch for %s — if the spec label table or pre-hash changed, update katComposeExpected to the new value:\n  actual: %q",
				info.name, got)
		})
	}
}
