// Package api serves the node's local HTTP JSON API (SPEC.md §10). It binds to localhost by
// default; it has no authentication.
package api

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/decanus/canary/internal/chain"
	"github.com/decanus/canary/internal/consensus"
	"github.com/decanus/canary/internal/mempool"
	"github.com/decanus/canary/internal/wallet"
)

// Backend is what the API serves from.
type Backend struct {
	Chain     *chain.Manager
	Pool      *mempool.Pool
	PublishTx func(*consensus.Transfer) error // relays an accepted transfer; may be nil
}

// Server is a running API server.
type Server struct {
	srv *http.Server
	ln  net.Listener
}

// Listen starts serving on addr (host:port).
func Listen(addr string, b Backend) (*Server, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /tip", b.tip)
	mux.HandleFunc("GET /account/{addr}", b.account)
	mux.HandleFunc("POST /tx", b.submitTx)
	s := &Server{srv: &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}, ln: ln}
	go s.srv.Serve(ln)
	return s, nil
}

// Addr returns the listening address.
func (s *Server) Addr() string { return s.ln.Addr().String() }

// Close stops the server.
func (s *Server) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return s.srv.Shutdown(ctx)
}

// Tip is the GET /tip response.
type Tip struct {
	Height         int    `json:"height"` // -1 for an empty chain
	Hash           string `json:"hash"`
	Genesis        string `json:"genesis"`
	Bits           uint32 `json:"bits"`
	Time           uint32 `json:"time"`
	CumulativeWork string `json:"cumulativeWork"`
	Mempool        int    `json:"mempool"`
}

func (b Backend) tip(w http.ResponseWriter, _ *http.Request) {
	hash, height, work, ok := b.Chain.Tip()
	t := Tip{Height: height, CumulativeWork: work.String(), Mempool: b.Pool.Len()}
	if ok {
		blk, _, _ := b.Chain.BlockByHash(hash)
		genesis, _ := b.Chain.GenesisHash()
		t.Hash, t.Genesis = hex.EncodeToString(hash[:]), hex.EncodeToString(genesis[:])
		t.Bits, t.Time = blk.Header.Bits, blk.Header.Time
	}
	writeJSON(w, http.StatusOK, t)
}

// Account is the GET /account/{addr} response. NextNonce accounts for transfers already in the
// mempool, so a wallet can queue several transfers without waiting for blocks.
type Account struct {
	Address   string `json:"address"`
	Balance   string `json:"balance"`
	Nonce     uint64 `json:"nonce"`
	NextNonce uint64 `json:"nextNonce"`
}

func (b Backend) account(w http.ResponseWriter, r *http.Request) {
	addr, err := wallet.ParseAddress(r.PathValue("addr"))
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	acc := b.Chain.Account(addr)
	writeJSON(w, http.StatusOK, Account{
		Address:   hex.EncodeToString(addr[:]),
		Balance:   acc.Balance.String(),
		Nonce:     acc.Nonce,
		NextNonce: acc.Nonce + uint64(b.Pool.Pending(addr)),
	})
}

// TxResult is the POST /tx response.
type TxResult struct {
	ID string `json:"id"` // H2(tx), its merkle leaf
}

// submitTx accepts a hex-encoded transfer into the mempool and relays it.
func (b Backend) submitTx(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 4*consensus.TransferSize))
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	raw, err := hex.DecodeString(strings.TrimSpace(string(body)))
	if err != nil {
		writeError(w, http.StatusBadRequest, fmt.Errorf("body must be a hex transfer: %w", err))
		return
	}
	tx, err := consensus.DecodeTx(raw)
	t, ok := tx.(*consensus.Transfer)
	if err != nil || !ok {
		writeError(w, http.StatusBadRequest, errors.New("body is not a transfer"))
		return
	}
	if err := b.Pool.Add(t); err != nil && !errors.Is(err, mempool.ErrKnown) {
		writeError(w, http.StatusUnprocessableEntity, err)
		return
	}
	if b.PublishTx != nil {
		if err := b.PublishTx(t); err != nil {
			writeError(w, http.StatusInternalServerError, fmt.Errorf("accepted but not relayed: %w", err))
			return
		}
	}
	id := consensus.H2(raw)
	writeJSON(w, http.StatusOK, TxResult{ID: hex.EncodeToString(id[:])})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, err error) {
	writeJSON(w, status, map[string]string{"error": err.Error()})
}
