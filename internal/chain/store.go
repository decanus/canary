// Package chain stores blocks and tracks the block tree, the active chain and reorgs
// (SPEC.md §7–§8).
package chain

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/decanus/canary/internal/consensus"
)

// BlocksFile is the append-only block file inside the data directory.
const BlocksFile = "blocks.dat"

// Store is the append-only block file: records of u32le(len) ‖ block bytes.
type Store struct {
	f *os.File
}

// OpenStore opens (creating if needed) the block file in dir and returns it with every complete
// record in file order. A torn final record, left by a crash mid-append, is truncated away.
func OpenStore(dir string) (*Store, []*consensus.Block, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, nil, err
	}
	f, err := os.OpenFile(filepath.Join(dir, BlocksFile), os.O_RDWR|os.O_CREATE, 0o644)
	if err != nil {
		return nil, nil, err
	}
	blocks, good, err := readRecords(f)
	if err != nil {
		f.Close()
		return nil, nil, err
	}
	if err := f.Truncate(good); err != nil {
		f.Close()
		return nil, nil, err
	}
	if _, err := f.Seek(good, io.SeekStart); err != nil {
		f.Close()
		return nil, nil, err
	}
	return &Store{f: f}, blocks, nil
}

// readRecords reads records from the start of f. It returns the decoded blocks and the offset
// just past the last complete record. A complete record that does not decode is corruption.
func readRecords(f *os.File) ([]*consensus.Block, int64, error) {
	data, err := io.ReadAll(f)
	if err != nil {
		return nil, 0, err
	}
	var blocks []*consensus.Block
	off := int64(0)
	for {
		rest := data[off:]
		if len(rest) < 4 {
			return blocks, off, nil
		}
		n := int64(binary.LittleEndian.Uint32(rest))
		if n > consensus.MaxBlockSize {
			return nil, 0, fmt.Errorf("%s: record at offset %d has length %d", BlocksFile, off, n)
		}
		if int64(len(rest)-4) < n {
			return blocks, off, nil // torn tail
		}
		blk, err := consensus.DeserializeBlock(rest[4 : 4+n])
		if err != nil {
			return nil, 0, fmt.Errorf("%s: record at offset %d: %w", BlocksFile, off, err)
		}
		blocks = append(blocks, blk)
		off += 4 + n
	}
}

// Append writes blk and syncs it to disk.
func (s *Store) Append(blk *consensus.Block) error {
	if s.f == nil {
		return errors.New("store closed")
	}
	b := blk.Serialize()
	rec := binary.LittleEndian.AppendUint32(make([]byte, 0, 4+len(b)), uint32(len(b)))
	if _, err := s.f.Write(append(rec, b...)); err != nil {
		return err
	}
	return s.f.Sync()
}

// Close closes the block file.
func (s *Store) Close() error {
	if s.f == nil {
		return nil
	}
	err := s.f.Close()
	s.f = nil
	return err
}
