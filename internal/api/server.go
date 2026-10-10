// Package api serves the node's local HTTP JSON API (SPEC.md §10).
package api

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"math/big"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"

	"github.com/decanus/canary/internal/chain"
	"github.com/decanus/canary/internal/chainjson"
	"github.com/decanus/canary/internal/consensus"
)

// Network is the part of the P2P node the API uses. It may be nil (no peers, no relay).
type Network interface {
	Peers() []peer.AddrInfo
	Publish(blk *consensus.Block) error
}

// Server handles the API requests.
type Server struct {
	chain *chain.Manager
	net   Network
	now   func() int64
	mux   *http.ServeMux
}

// New returns a server for cm. now is the local clock in Unix seconds (default time.Now).
func New(cm *chain.Manager, net Network, now func() int64) *Server {
	if now == nil {
		now = func() int64 { return time.Now().Unix() }
	}
	s := &Server{chain: cm, net: net, now: now, mux: http.NewServeMux()}
	s.mux.HandleFunc("GET /tip", s.tip)
	s.mux.HandleFunc("GET /block/{id}", s.block)
	s.mux.HandleFunc("GET /stats", s.stats)
	s.mux.HandleFunc("GET /peers", s.peers)
	s.mux.HandleFunc("POST /submitblock", s.submitBlock)
	return s
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) { s.mux.ServeHTTP(w, r) }

// Tip is the /tip response.
type Tip struct {
	Height         int    `json:"height"`
	Hash           string `json:"hash"`
	Bits           uint32 `json:"bits"`
	Time           uint32 `json:"time"`
	CumulativeWork string `json:"cumulativeWork"` // decimal
}

func (s *Server) tip(w http.ResponseWriter, _ *http.Request) {
	blk, height, work, ok := s.chain.TipBlock()
	if !ok {
		writeError(w, http.StatusNotFound, "chain is empty")
		return
	}
	hash := blk.Hash()
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
func (s *Server) block(w http.ResponseWriter, r *http.Request) {
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
	// CapacityOpsPerSec is the epoch's mean expected rho cost √(πn/4) per block divided by
	// AvgInterval; 0 when AvgInterval is not positive.
	CapacityOpsPerSec float64 `json:"capacityOpsPerSec"`
	Secp256k1Distance int     `json:"secp256k1Distance"` // 256 − bits
}

func (s *Server) stats(w http.ResponseWriter, _ *http.Request) {
	p := s.chain.Params()
	// The epoch's blocks plus the block before it.
	start, headers := s.chain.ActiveTail(int(p.Epoch) + 1)
	if len(headers) == 0 {
		writeError(w, http.StatusNotFound, "chain is empty")
		return
	}
	writeJSON(w, http.StatusOK, ComputeStats(p, start, headers))
}

// ComputeStats computes /stats from the active headers at heights start.. through the tip.
// headers must reach back to the block before the tip's epoch (or to genesis).
//
// SPEC: §10 leaves the window open and the reference has no stats. "Current epoch" is taken
// to be the tip's epoch, bits the tip's bits, and capacity the epoch's mean √(πn/4) over its
// mean interval.
func ComputeStats(p *consensus.Params, start int, headers []*consensus.Header) Stats {
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
	if first := max(epochStart, 1); tipHeight >= first {
		span := int64(tip.Time) - int64(at(first-1).Time)
		st.AvgInterval = float64(span) / float64(tipHeight-first+1)
	}
	if st.AvgInterval > 0 {
		var sum float64
		for h := epochStart; h <= tipHeight; h++ {
			n, _ := new(big.Float).SetInt(at(h).N).Float64()
			sum += math.Sqrt(math.Pi * n / 4)
		}
		st.CapacityOpsPerSec = sum / float64(st.BlocksInEpoch) / st.AvgInterval
	}
	return st
}

// PeerInfo is one /peers entry.
type PeerInfo struct {
	ID    string   `json:"id"`
	Addrs []string `json:"addrs"`
}

func (s *Server) peers(w http.ResponseWriter, _ *http.Request) {
	out := []PeerInfo{}
	if s.net != nil {
		for _, pi := range s.net.Peers() {
			info := PeerInfo{ID: pi.ID.String(), Addrs: []string{}}
			for _, a := range pi.Addrs {
				info.Addrs = append(info.Addrs, a.String())
			}
			out = append(out, info)
		}
	}
	writeJSON(w, http.StatusOK, out)
}

// SubmitResult is the /submitblock response.
type SubmitResult struct {
	Hash   string `json:"hash"`
	Status string `json:"status"` // chain.Status: new-tip, side-chain, orphan or duplicate
}

// submitBlock adds a hex-encoded block to the chain and relays it if it was connected. Invalid
// blocks get 400; orphans are kept in the orphan pool but not relayed.
func (s *Server) submitBlock(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 2*consensus.MaxBlockSize+1024))
	if err != nil {
		writeError(w, http.StatusRequestEntityTooLarge, err.Error())
		return
	}
	raw, err := hex.DecodeString(strings.TrimSpace(string(body)))
	if err != nil {
		writeError(w, http.StatusBadRequest, "body must be the block as hex: "+err.Error())
		return
	}
	blk, err := consensus.DeserializeBlock(raw)
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
	if s.net != nil && (st == chain.NewTip || st == chain.SideChain) {
		if err := s.net.Publish(blk); err != nil {
			writeError(w, http.StatusInternalServerError, fmt.Sprintf("block %s but relay failed: %v", st, err))
			return
		}
	}
	hash := blk.Hash()
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
