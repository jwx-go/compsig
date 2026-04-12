package compsig

// composeMessage builds the M' representative per
// draft-ietf-jose-pq-composite-sigs §4.2:
//
//	M' := Prefix || Label || 0x00 || PH(M)
//
// where Prefix is the fixed ASCII constant "CompositeAlgorithmSignatures2025",
// Label is the per-algorithm domain separator from Table 4, the 0x00 byte is
// the empty-context length field, and PH(M) is the per-algorithm pre-hash of
// the raw JWS signing input.
func composeMessage(info *algInfo, msg []byte) []byte {
	ph := info.prehash(msg)
	out := make([]byte, 0, len(Prefix)+len(info.label)+1+len(ph))
	out = append(out, Prefix...)
	out = append(out, info.label...)
	out = append(out, 0x00)
	out = append(out, ph...)
	return out
}
