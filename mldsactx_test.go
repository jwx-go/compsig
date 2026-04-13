package compsig

import (
	"testing"

	"filippo.io/mldsa"
	"github.com/stretchr/testify/require"
)

// TestMLDSAContextDomainSeparation is a regression test for EXT-006:
// draft-ietf-jose-pq-composite-sigs §4.2 step 3 requires the ML-DSA
// component to be invoked with ctx=Label (e.g. "COMPSIG-MLDSA44-..."),
// not the empty context. Before the fix, compsig dispatched ML-DSA
// signing through jwsbb -> jwx-go/mldsa, which hard-coded ctx=nil; the
// resulting signatures were not interoperable with any spec-compliant
// implementation. The fix introduces jwsbb.SignWithOpts /
// dsig.SignerWithOpts so the context can flow from compsig all the
// way down to filippo.io/mldsa without bypassing any layer.
//
// This test pins the contract by:
//  1. Producing a compsig signature via the compSigDsig.Sign code path,
//  2. Extracting the ML-DSA half of the concatenated output,
//  3. Asserting it verifies with mldsa.Verify when given the spec
//     ctx=Label,
//  4. Asserting it does NOT verify with ctx="" (empty context).
//
// Step 4 is what catches a regression to the old behavior: under the
// pre-fix code the empty-context verification would succeed, because
// the signature was produced with an empty context.
func TestMLDSAContextDomainSeparation(t *testing.T) {
	for _, info := range compSigAlgs {
		t.Run(info.name, func(t *testing.T) {
			sk, err := GenerateKey(info.alg)
			require.NoError(t, err, "GenerateKey")

			payload := []byte("EXT-006 regression payload")
			d := &compSigDsig{info: info}
			sig, err := d.Sign(sk, payload, nil)
			require.NoError(t, err, "compSigDsig.Sign")
			require.GreaterOrEqual(t, len(sig), info.mldsaSigSize)

			mldsaSig := sig[:info.mldsaSigSize]
			mPrime := composeMessage(info, payload)
			pk := sk.mldsa.PublicKey()

			// Spec-mandated context: must verify.
			err = mldsa.Verify(pk, mPrime, mldsaSig, &mldsa.Options{
				Context: string(info.label),
			})
			require.NoError(t, err, "mldsa.Verify with ctx=Label must succeed")

			// Empty context: must NOT verify. If this passes, ctx=Label
			// is not actually flowing into the ML-DSA signer.
			err = mldsa.Verify(pk, mPrime, mldsaSig, nil)
			require.Error(t, err, "mldsa.Verify with empty ctx must fail (would mean SignWithOpts dropped ctx=Label)")
		})
	}
}
