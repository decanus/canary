// Package api serves the node's local HTTP JSON API (SPEC.md §10).
package api

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"math/big"
	"net/http"
	"strconv"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"

	"github.com/decanus/canary/internal/chain"
	"github.com/decanus/canary/internal/chainjson"
	"github.com/decanus/canary/internal/consensus"
)

// Network is the part of the P2P node the API uses.
type Network interface {
	Peers() []peer.AddrInfo
	Publish(blk *consensus.Block) error
}

type server struct {
	chain *chain.Manager
	net   Network
	now   func() int64
}

// New returns the API handler for cm. now is the local clock in Unix seconds (default
// time.Now).
func New(cm *chain.Manager, net Network, now func() int64) http.Handler {
	if now == nil {
		now = func() int64 { return time.Now().Unix() }
	}
	s := &server{chain: cm, net: net, now: now}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /tip", s.tip)
	mux.HandleFunc("GET /block/{id}", s.block)
	mux.HandleFunc("GET /stats", s.stats)
	mux.HandleFunc("GET /peers", s.peers)
	mux.HandleFunc("POST /submitblock", s.submitBlock)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Browsers attach Origin to cross-origin requests; refusing them stops any web page the
		// user visits from making the local node validate blocks (a plain-text POST needs no
		// CORS preflight). Non-browser clients do not send Origin.
		if r.Header.Get("Origin") != "" {
			writeError(w, http.StatusForbidden, "cross-origin requests are not allowed")
			return
		}
		mux.ServeHTTP(w, r)
	})
}

// Tip is the /tip response.
type Tip struct {
	Height         int    `json:"height"`
	Hash           string `json:"hash"`
	Bits           uint32 `json:"bits"`
	Time           uint32 `json:"time"`
	CumulativeWork string `json:"cumulativeWork"` // decimal
}

func (s *server) tip(w http.ResponseWriter, _ *http.Request) {
	hash, height, work, ok := s.chain.Tip()
	if !ok {
		writeError(w, http.StatusNotFound, "chain is empty")
		return
	}
	// The hash pins the block, so it matches height and work even if the tip has moved on.
	blk, _, err := s.chain.BlockByHash(hash)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, Tip{
		Height:         height,
		Hash:           hex.EncodeToString(hash[:]),
		Bits:           blk.Header.Bits,
		Time:           blk.Header.Time,
		CumulativeWork: work.String(),
	})
}

// block looks up an active block by decimal height, or any known block (including side chains)
// by its 64-hex-digit hash.
func (s *server) block(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var blk *consensus.Block
	var err error
	if len(id) == 64 {
		var hash [32]byte
		if _, herr := hex.Decode(hash[:], []byte(id)); herr != nil {
			writeError(w, http.StatusBadRequest, "bad block hash")
			return
		}
		blk, _, err = s.chain.BlockByHash(hash)
	} else {
		h, perr := strconv.Atoi(id)
		if perr != nil || h < 0 {
			writeError(w, http.StatusBadRequest, "want a block height or a 64-hex-digit hash")
			return
		}
		blk, err = s.chain.BlockByHeight(h)
	}
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, chainjson.FromBlock(blk))
}

// Stats is the /stats response, describing the epoch of the active tip.
type Stats struct {
	Bits          uint32 `json:"bits"`  // bits of the tip block
	Epoch         int64  `json:"epoch"` // tip height / Epoch
	BlocksInEpoch int64  `json:"blocksInEpoch"`
	// AvgInterval is the mean seconds between consecutive blocks of the epoch, counting the
	// epoch's first block against the previous epoch's last; 0 for a genesis-only chain.
	AvgInterval float64 `json:"avgInterval"`
	// CapacityOpsPerSec is the mean expected rho cost √(πn/4) of the blocks AvgInterval covers
	// (genesis has no interval) divided by AvgInterval; 0 when AvgInterval is not positive.
	CapacityOpsPerSec float64 `json:"capacityOpsPerSec"`
	Secp256k1Distance int     `json:"secp256k1Distance"` // 256 − bits
}

func (s *server) stats(w http.ResponseWriter, _ *http.Request) {
	p := s.chain.Params()
	// The epoch's blocks plus the block before it.
	start, headers := s.chain.ActiveTail(int(p.Epoch) + 1)
	if len(headers) == 0 {
		writeError(w, http.StatusNotFound, "chain is empty")
		return
	}
	writeJSON(w, http.StatusOK, computeStats(p, start, headers))
}

// computeStats computes /stats from the active headers at heights start.. through the tip.
// headers must reach back to the block before the tip's epoch (or to genesis).
//
// SPEC: §10 leaves the window open and the reference has no stats. "Current epoch" is taken
// to be the tip's epoch, bits the tip's bits, and capacity the mean √(πn/4) over the mean
// interval of the epoch's blocks.
func computeStats(p *consensus.Params, start int, headers []*consensus.Header) Stats {
	tipHeight := int64(start + len(headers) - 1)
	tip := headers[len(headers)-1]
	epochStart := tipHeight - tipHeight%p.Epoch
	at := func(h int64) *consensus.Header { return headers[h-int64(start)] }

	st := Stats{
		Bits:              tip.Bits,
		Epoch:             tipHeight / p.Epoch,
		BlocksInEpoch:     tipHeight - epochStart + 1,
		Secp256k1Distance: 256 - int(tip.Bits),
	}
	// Blocks first..tipHeight each have an interval from their parent.
	first := max(epochStart, 1)
	if tipHeight < first {
		return st
	}
	count := float64(tipHeight - first + 1)
	st.AvgInterval = float64(int64(tip.Time)-int64(at(first-1).Time)) / count
	if st.AvgInterval > 0 {
		var sum float64
		for h := first; h <= tipHeight; h++ {
			n, _ := new(big.Float).SetInt(at(h).N).Float64()
			sum += math.Sqrt(math.Pi * n / 4)
		}
		st.CapacityOpsPerSec = sum / count / st.AvgInterval
	}
	return st
}

// PeerInfo is one /peers entry.
type PeerInfo struct {
	ID    string   `json:"id"`
	Addrs []string `json:"addrs"`
}

func (s *server) peers(w http.ResponseWriter, _ *http.Request) {
	out := []PeerInfo{}
	for _, pi := range s.net.Peers() {
		info := PeerInfo{ID: pi.ID.String(), Addrs: []string{}}
		for _, a := range pi.Addrs {
			info.Addrs = append(info.Addrs, a.String())
		}
		out = append(out, info)
	}
	writeJSON(w, http.StatusOK, out)
}

// SubmitResult is the /submitblock response.
type SubmitResult struct {
	Hash   string `json:"hash"`
	Status string `json:"status"` // chain.Status: new-tip, side-chain, orphan or duplicate
}

// submitBlock adds a hex-encoded block to the chain and relays it if it is connected, including
// a resubmitted duplicate, so a client can retry a failed relay. Invalid blocks get 400; orphans
// are kept in the orphan pool but not relayed.
func (s *server) submitBlock(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 2*consensus.MaxBlockSize+1024))
	if err != nil {
		code := http.StatusBadRequest
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			code = http.StatusRequestEntityTooLarge
		}
		writeError(w, code, err.Error())
		return
	}
	raw := bytes.TrimSpace(body)
	n, err := hex.Decode(raw, raw)
	if err != nil {
		writeError(w, http.StatusBadRequest, "body must be the block as hex: "+err.Error())
		return
	}
	blk, err := consensus.DeserializeBlock(raw[:n])
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	st, err := s.chain.AddBlock(blk, s.now())
	switch {
	case errors.Is(err, consensus.ErrInvalid):
		writeError(w, http.StatusBadRequest, err.Error())
		return
	case err != nil:
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	hash := blk.Hash()
	if _, _, err := s.chain.BlockByHash(hash); err == nil { // connected, not an orphan
		if err := s.net.Publish(blk); err != nil {
			writeError(w, http.StatusInternalServerError, fmt.Sprintf("block %s but relay failed: %v", st, err))
			return
		}
	}
	writeJSON(w, http.StatusOK, SubmitResult{Hash: hex.EncodeToString(hash[:]), Status: st.String()})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}
