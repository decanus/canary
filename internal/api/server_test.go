package api

import (
	"encoding/hex"
	"encoding/json"
	"math"
	"math/big"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	ma "github.com/multiformats/go-multiaddr"

	"github.com/decanus/canary/internal/chain"
	"github.com/decanus/canary/internal/chainjson"
	"github.com/decanus/canary/internal/conformance"
	"github.com/decanus/canary/internal/consensus"
)

// loadVectors returns the vector chain: 70 blocks, epoch 64, retarget from 36 to 40 bits at
// height 64.
func loadVectors(t *testing.T) (*conformance.Vectors, []*consensus.Block) {
	t.Helper()
	v, err := conformance.Load("../../reference/test_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	blocks, err := chainjson.DecodeBlocks(v.Chain.Blocks)
	if err != nil {
		t.Fatal(err)
	}
	return v, blocks
}

func newManager(t *testing.T, p *consensus.Params, blocks []*consensus.Block) *chain.Manager {
	t.Helper()
	cm, err := chain.NewMemory(p)
	if err != nil {
		t.Fatal(err)
	}
	for i, b := range blocks {
		if _, err := cm.AddBlock(b, time.Now().Unix()); err != nil {
			t.Fatalf("block %d: %v", i, err)
		}
	}
	return cm
}

type fakeNet struct {
	peers     []peer.AddrInfo
	published []*consensus.Block
}

func (f *fakeNet) Peers() []peer.AddrInfo { return f.peers }

func (f *fakeNet) Publish(blk *consensus.Block) error {
	f.published = append(f.published, blk)
	return nil
}

func do(t *testing.T, s http.Handler, method, path, body string, wantCode int, out any) {
	t.Helper()
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, httptest.NewRequest(method, path, strings.NewReader(body)))
	if rec.Code != wantCode {
		t.Fatalf("%s %s: status %d, want %d: %s", method, path, rec.Code, wantCode, rec.Body)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("%s %s: content type %q", method, path, ct)
	}
	if out != nil {
		if err := json.Unmarshal(rec.Body.Bytes(), out); err != nil {
			t.Fatalf("%s %s: %v", method, path, err)
		}
	}
}

// TestStatsOnVectorChain recomputes the stats of the vector chain's last epoch from the informational
// JSON fields, independently of computeStats.
func TestStatsOnVectorChain(t *testing.T) {
	v, blocks := loadVectors(t)
	s := New(newManager(t, &v.Params, blocks), &fakeNet{}, nil)
	var got Stats
	do(t, s, "GET", "/stats", "", http.StatusOK, &got)

	bj := v.Chain.Blocks
	if len(bj) != 70 || v.Params.Epoch != 64 {
		t.Fatalf("unexpected vector chain: %d blocks, epoch %d", len(bj), v.Params.Epoch)
	}
	// Tip height 69 is in epoch 1 (heights 64..69); its first interval is 63 → 64.
	wantAvg := float64(int64(bj[69].Time)-int64(bj[63].Time)) / 6
	var sum float64
	for _, b := range bj[64:] {
		n, _ := new(big.Float).SetString(b.N)
		f, _ := n.Float64()
		sum += math.Sqrt(math.Pi * f / 4)
	}
	want := Stats{
		Bits:              40,
		Epoch:             1,
		BlocksInEpoch:     6,
		AvgInterval:       wantAvg,
		CapacityOpsPerSec: sum / 6 / wantAvg,
		Secp256k1Distance: 216,
	}
	if wantAvg <= 0 {
		t.Fatalf("vector chain has non-increasing times: avg interval %v", wantAvg)
	}
	if math.Abs(got.CapacityOpsPerSec-want.CapacityOpsPerSec) > 1e-9*want.CapacityOpsPerSec {
		t.Fatalf("capacity %v, want %v", got.CapacityOpsPerSec, want.CapacityOpsPerSec)
	}
	got.CapacityOpsPerSec = want.CapacityOpsPerSec
	if got != want {
		t.Fatalf("stats\n got %+v\nwant %+v", got, want)
	}
}

func TestComputeStatsEpochZero(t *testing.T) {
	v, blocks := loadVectors(t)
	headers := make([]*consensus.Header, len(blocks))
	for i, b := range blocks {
		headers[i] = b.Header
	}

	st := computeStats(&v.Params, 0, headers[:1])
	if st != (Stats{Bits: 36, Epoch: 0, BlocksInEpoch: 1, Secp256k1Distance: 220}) {
		t.Fatalf("genesis-only stats %+v", st)
	}

	// Genesis has no interval, so neither the interval nor the capacity mean includes it.
	st = computeStats(&v.Params, 0, headers[:10])
	wantAvg := float64(int64(headers[9].Time)-int64(headers[0].Time)) / 9
	var sum float64
	for _, h := range headers[1:10] {
		n, _ := new(big.Float).SetInt(h.N).Float64()
		sum += math.Sqrt(math.Pi * n / 4)
	}
	if st.Epoch != 0 || st.BlocksInEpoch != 10 || st.AvgInterval != wantAvg || st.Bits != 36 ||
		math.Abs(st.CapacityOpsPerSec-sum/9/wantAvg) > 1e-9*st.CapacityOpsPerSec {
		t.Fatalf("stats at height 9: %+v (want avg %v, capacity %v)", st, wantAvg, sum/9/wantAvg)
	}

	// The last block of epoch 0 counts all 64 blocks.
	if st = computeStats(&v.Params, 0, headers[:64]); st.BlocksInEpoch != 64 {
		t.Fatalf("stats at height 63: %+v", st)
	}
	// For the tip at 69, the tail from height 63 (as /stats reads it) is enough.
	full, tail := computeStats(&v.Params, 0, headers), computeStats(&v.Params, 63, headers[63:])
	if full != tail {
		t.Fatalf("stats from full chain %+v, from tail %+v", full, tail)
	}
}

func TestReadEndpoints(t *testing.T) {
	v, blocks := loadVectors(t)
	empty := New(newManager(t, &v.Params, nil), &fakeNet{}, nil)
	do(t, empty, "GET", "/tip", "", http.StatusNotFound, nil)
	do(t, empty, "GET", "/stats", "", http.StatusNotFound, nil)
	var none []PeerInfo
	do(t, empty, "GET", "/peers", "", http.StatusOK, &none)
	if none == nil || len(none) != 0 {
		t.Fatalf("peers with none connected: %#v", none)
	}

	id, _ := peer.Decode("12D3KooWD3eckifWpRn9wQpMG9R9hX3sD158z7EqHWmweQAJU5SA")
	net := &fakeNet{peers: []peer.AddrInfo{{ID: id, Addrs: []ma.Multiaddr{ma.StringCast("/ip4/127.0.0.1/tcp/18555")}}}}
	s := New(newManager(t, &v.Params, blocks), net, nil)
	var tip Tip
	do(t, s, "GET", "/tip", "", http.StatusOK, &tip)
	last := v.Chain.Blocks[69]
	if tip != (Tip{Height: 69, Hash: last.Hash, Bits: last.Bits, Time: last.Time, CumulativeWork: v.Chain.CumulativeWork}) {
		t.Fatalf("tip %+v", tip)
	}

	for _, path := range []string{"/block/64", "/block/" + v.Chain.Blocks[64].Hash} {
		var got chainjson.BlockJSON
		do(t, s, "GET", path, "", http.StatusOK, &got)
		if !reflect.DeepEqual(got, v.Chain.Blocks[64]) {
			t.Fatalf("%s:\n got %+v\nwant %+v", path, got, v.Chain.Blocks[64])
		}
	}
	do(t, s, "GET", "/block/70", "", http.StatusNotFound, nil)
	do(t, s, "GET", "/block/"+strings.Repeat("00", 32), "", http.StatusNotFound, nil)
	do(t, s, "GET", "/block/-1", "", http.StatusBadRequest, nil)
	do(t, s, "GET", "/block/"+strings.Repeat("zz", 32), "", http.StatusBadRequest, nil)

	var peers []PeerInfo
	do(t, s, "GET", "/peers", "", http.StatusOK, &peers)
	if len(peers) != 1 || peers[0].ID != id.String() || peers[0].Addrs[0] != "/ip4/127.0.0.1/tcp/18555" {
		t.Fatalf("peers %+v", peers)
	}

	// Browser cross-origin requests are refused.
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/tip", nil)
	req.Header.Set("Origin", "https://example.com")
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("cross-origin request: status %d", rec.Code)
	}
}

func TestSubmitBlock(t *testing.T) {
	v, blocks := loadVectors(t)
	net := &fakeNet{}
	cm := newManager(t, &v.Params, blocks[:68])
	s := New(cm, net, nil)
	submit := func(blk *consensus.Block, wantCode int, wantStatus string) {
		t.Helper()
		var res SubmitResult
		do(t, s, "POST", "/submitblock", hex.EncodeToString(blk.Serialize())+"\n", wantCode, &res)
		if wantStatus != "" && res.Status != wantStatus {
			t.Fatalf("status %q, want %q", res.Status, wantStatus)
		}
	}

	// An orphan is kept but not relayed; its parent connects both and is relayed.
	submit(blocks[69], http.StatusOK, "orphan")
	submit(blocks[69], http.StatusOK, "duplicate") // still an orphan: not relayed
	submit(blocks[68], http.StatusOK, "new-tip")
	if h, _, _, _ := cm.Tip(); h != blocks[69].Hash() {
		t.Fatal("orphan was not connected")
	}
	// Resubmitting a connected block relays it again, so a failed relay can be retried.
	submit(blocks[68], http.StatusOK, "duplicate")
	if len(net.published) != 2 || net.published[0].Hash() != blocks[68].Hash() || net.published[1].Hash() != blocks[68].Hash() {
		t.Fatalf("published %d blocks, want block 68 twice", len(net.published))
	}

	bad := *blocks[69].Header
	bad.K = new(big.Int).Add(bad.K, big.NewInt(1))
	submit(&consensus.Block{Header: &bad, Txs: blocks[69].Txs}, http.StatusBadRequest, "")
	do(t, s, "POST", "/submitblock", "not hex", http.StatusBadRequest, nil)
	do(t, s, "POST", "/submitblock", "00", http.StatusBadRequest, nil)
	do(t, s, "POST", "/submitblock", strings.Repeat("0", 2*consensus.MaxBlockSize+2048), http.StatusRequestEntityTooLarge, nil)
	if len(net.published) != 2 {
		t.Fatal("rejected block was relayed")
	}
}
