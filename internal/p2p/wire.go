// Package p2p relays blocks between Canary nodes over libp2p (SPEC.md §9): a status protocol to
// compare chains, a sync protocol to fetch blocks, and a GossipSub topic for new blocks.
package p2p

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"

	"github.com/libp2p/go-libp2p/core/protocol"

	"github.com/decanus/canary/internal/consensus"
)

const (
	// ProtocolVersion is sent in status messages. It tracks the block format (v0.2 = header
	// version 2), as do the /2.0.0 protocol and topic IDs, so nodes of different formats never
	// exchange blocks.
	ProtocolVersion = 2
	// MaxSyncBlocks is the most blocks one sync response carries.
	MaxSyncBlocks = 500
	// maxSyncBytes bounds a sync response's total size.
	maxSyncBytes = 8 << 20
	// maxLocator is the most hashes in a block locator.
	maxLocator = 32
)

// syncBatch is how many blocks handleSync returns at most; tests lower it.
var syncBatch = MaxSyncBlocks

// Protocol IDs and topic names are namespaced by network, so different networks never mix.
func statusProtocol(network string) protocol.ID {
	return protocol.ID("/canary/" + network + "/status/2.0.0")
}

func syncProtocol(network string) protocol.ID {
	return protocol.ID("/canary/" + network + "/sync/2.0.0")
}

func blocksTopic(network string) string {
	return "/canary/" + network + "/blocks/2.0.0"
}

func txsTopic(network string) string {
	return "/canary/" + network + "/txs/2.0.0"
}

// Status describes a node's active chain: u32le version ‖ u32le height ‖ tip hash ‖
// u8 len ‖ cumulative work (big-endian). Height is the chain length (0 for an empty chain).
type Status struct {
	Version uint32
	Height  uint32
	Tip     [32]byte
	Work    *big.Int
}

func writeStatus(w io.Writer, s Status) error {
	work := s.Work.Bytes()
	if len(work) > 255 {
		return errors.New("work too large")
	}
	b := binary.LittleEndian.AppendUint32(nil, s.Version)
	b = binary.LittleEndian.AppendUint32(b, s.Height)
	b = append(b, s.Tip[:]...)
	b = append(b, byte(len(work)))
	_, err := w.Write(append(b, work...))
	return err
}

func readStatus(r io.Reader) (Status, error) {
	var hdr [41]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return Status{}, err
	}
	s := Status{
		Version: binary.LittleEndian.Uint32(hdr[0:4]),
		Height:  binary.LittleEndian.Uint32(hdr[4:8]),
	}
	copy(s.Tip[:], hdr[8:40])
	work := make([]byte, hdr[40])
	if _, err := io.ReadFull(r, work); err != nil {
		return Status{}, err
	}
	s.Work = new(big.Int).SetBytes(work)
	return s, nil
}

// A sync request is a block locator: u8 count ‖ count × 32-byte hashes, newest first.
func writeLocator(w io.Writer, locator [][32]byte) error {
	if len(locator) > maxLocator {
		locator = locator[:maxLocator]
	}
	b := []byte{byte(len(locator))}
	for _, h := range locator {
		b = append(b, h[:]...)
	}
	_, err := w.Write(b)
	return err
}

func readLocator(r io.Reader) ([][32]byte, error) {
	var n [1]byte
	if _, err := io.ReadFull(r, n[:]); err != nil {
		return nil, err
	}
	if n[0] > maxLocator {
		return nil, fmt.Errorf("locator has %d hashes", n[0])
	}
	locator := make([][32]byte, n[0])
	for i := range locator {
		if _, err := io.ReadFull(r, locator[i][:]); err != nil {
			return nil, err
		}
	}
	return locator, nil
}

// A sync response is u32le count ‖ count × (u32le len ‖ block bytes).
func writeBlocks(w io.Writer, blocks []*consensus.Block) error {
	b := binary.LittleEndian.AppendUint32(nil, uint32(len(blocks)))
	for _, blk := range blocks {
		enc := blk.Serialize()
		b = binary.LittleEndian.AppendUint32(b, uint32(len(enc)))
		b = append(b, enc...)
	}
	_, err := w.Write(b)
	return err
}

// readBlocks decodes a sync response. A block that fails to decode is returned as an error
// wrapping consensus.ErrInvalid, since the peer sent bytes no valid block encodes to.
func readBlocks(r io.Reader) ([]*consensus.Block, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	count := binary.LittleEndian.Uint32(hdr[:])
	if count > MaxSyncBlocks {
		return nil, fmt.Errorf("sync response has %d blocks", count)
	}
	blocks := make([]*consensus.Block, 0, count)
	total := 0
	for i := uint32(0); i < count; i++ {
		if _, err := io.ReadFull(r, hdr[:]); err != nil {
			return nil, err
		}
		n := binary.LittleEndian.Uint32(hdr[:])
		total += int(n)
		if n > consensus.MaxBlockSize || total > maxSyncBytes {
			return nil, fmt.Errorf("sync response too large")
		}
		buf := make([]byte, n)
		if _, err := io.ReadFull(r, buf); err != nil {
			return nil, err
		}
		blk, err := consensus.DeserializeBlock(buf)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", consensus.ErrInvalid, err)
		}
		blocks = append(blocks, blk)
	}
	return blocks, nil
}
