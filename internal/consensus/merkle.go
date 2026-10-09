package consensus

// MerkleRoot computes the Bitcoin-style merkle root of txs (SPEC.md §4.3). An empty list yields
// all-zero bytes, as in the reference; such blocks are invalid anyway.
func MerkleRoot(txs [][]byte) [32]byte {
	if len(txs) == 0 {
		return [32]byte{}
	}
	layer := make([][32]byte, len(txs))
	for i, tx := range txs {
		layer[i] = H2(tx)
	}
	for len(layer) > 1 {
		if len(layer)%2 == 1 {
			layer = append(layer, layer[len(layer)-1])
		}
		next := make([][32]byte, len(layer)/2)
		for i := range next {
			next[i] = H2(layer[2*i][:], layer[2*i+1][:])
		}
		layer = next
	}
	return layer[0]
}

// Coinbase builds the conventional coinbase "coinbase|" ‖ u32le(height) ‖ "|" ‖ miner ‖ "|" ‖ extra.
// Not enforced by consensus in v0.1.
func Coinbase(height uint32, miner string, extra []byte) []byte {
	b := []byte("coinbase|")
	b = append(b, u32le(height)...)
	b = append(b, '|')
	b = append(b, miner...)
	b = append(b, '|')
	return append(b, extra...)
}
