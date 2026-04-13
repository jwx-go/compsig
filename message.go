package compsig

import "encoding/base64"

// composeMessage builds the M' representative per
// draft-ietf-jose-pq-composite-sigs §4.2:
//
//	M' := Prefix || Label || 0x00 || PH(M)
//	M' := Encode(M')
//
// where Prefix is the fixed ASCII constant "CompositeAlgorithmSignatures2025",
// Label is the per-algorithm domain separator from Table 4, the 0x00 byte is
// the empty-context length field, PH(M) is the per-algorithm pre-hash of the
// raw JWS signing input, and Encode is base64url (no padding) for JOSE
// (binary for COSE, which is not used here). Both component signers see the
// encoded ASCII form.
func composeMessage(info *algInfo, msg []byte) []byte {
	ph := info.prehash(msg)
	raw := make([]byte, 0, len(Prefix)+len(info.label)+1+len(ph))
	raw = append(raw, Prefix...)
	raw = append(raw, info.label...)
	raw = append(raw, 0x00)
	raw = append(raw, ph...)

	encoded := make([]byte, base64.RawURLEncoding.EncodedLen(len(raw)))
	base64.RawURLEncoding.Encode(encoded, raw)
	return encoded
}
