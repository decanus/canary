package consensus

import "github.com/cloudflare/circl/sign/slhdsa"

// SPEC §1: the one non-stdlib dependency of consensus. Keep every use of CIRCL in this file.

// SLH-DSA-SHA2-128s sizes.
const (
	PubKeySize    = 32
	SignatureSize = 7856
)

// verifySLHDSA reports whether sig is a pure (FIPS 205) SLH-DSA-SHA2-128s signature of msg by
// pubkey with an empty context.
func verifySLHDSA(pubkey, msg, sig []byte) bool {
	if len(pubkey) != PubKeySize || len(sig) != SignatureSize {
		return false
	}
	pk := slhdsa.PublicKey{ID: slhdsa.SHA2_128s}
	if pk.UnmarshalBinary(pubkey) != nil {
		return false
	}
	return slhdsa.Verify(&pk, slhdsa.NewMessage(msg), sig, nil)
}
