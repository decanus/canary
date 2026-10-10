// Package chain stores blocks and tracks the block tree, the active chain and reorgs
// (SPEC.md §7–§8).
package chain

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/decanus/canary/internal/consensus"
)

const (
	// BlocksFile is the append-only block file inside the data directory.
	BlocksFile = "blocks.dat"
	// ParamsFile records the chain params a data directory was created with.
	ParamsFile = "params.json"
)

// Store is the append-only block file: records of u32le(len) ‖ block bytes.
type Store struct {
	f    *os.File
	size int64 // offset just past the last complete record
}

// OpenStore opens (creating if needed) the block file in dir and returns it with every complete
// record in file order. A torn tail left by a crash mid-append is truncated away.
func OpenStore(dir string) (*Store, []*consensus.Block, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, nil, err
	}
	f, err := os.OpenFile(filepath.Join(dir, BlocksFile), os.O_RDWR|os.O_CREATE, 0o644)
	if err != nil {
		return nil, nil, err
	}
	blocks, size, err := readRecords(f)
	if err == nil {
		err = f.Truncate(size)
	}
	if err == nil {
		_, err = f.Seek(size, io.SeekStart)
	}
	if err != nil {
		f.Close()
		return nil, nil, err
	}
	return &Store{f: f, size: size}, blocks, nil
}

// ReadStore returns the complete records of dir's block file without modifying it; a torn tail
// is ignored rather than truncated.
func ReadStore(dir string) ([]*consensus.Block, error) {
	f, err := os.Open(filepath.Join(dir, BlocksFile))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	blocks, _, err := readRecords(f)
	return blocks, err
}

// readRecords decodes records from r and returns them with the offset just past the last
// complete one. A torn tail (a short final record, or a tail that is all zero bytes, as some
// filesystems leave after power loss) ends the read; any other undecodable record is corruption.
func readRecords(r io.Reader) ([]*consensus.Block, int64, error) {
	br := bufio.NewReader(r)
	var blocks []*consensus.Block
	var off int64
	var lenBuf [4]byte
	for {
		if _, err := io.ReadFull(br, lenBuf[:]); err != nil {
			return blocks, off, ignoreTorn(err)
		}
		n := binary.LittleEndian.Uint32(lenBuf[:])
		var blk *consensus.Block
		err := fmt.Errorf("record length %d", n)
		if n > 0 && n <= consensus.MaxBlockSize {
			body := make([]byte, n)
			if _, err := io.ReadFull(br, body); err != nil {
				return blocks, off, ignoreTorn(err)
			}
			if blk, err = consensus.DeserializeBlock(body); err == nil {
				blocks = append(blocks, blk)
				off += 4 + int64(n)
				continue
			}
			if isZero(body) {
				err = nil // zero-filled tail so far; confirmed below
			}
		}
		if n == 0 || err == nil {
			rest, rerr := io.ReadAll(br)
			if rerr != nil {
				return nil, 0, rerr
			}
			if isZero(rest) {
				return blocks, off, nil
			}
			err = errors.New("non-zero data after an empty record")
		}
		return nil, 0, fmt.Errorf("%s: record at offset %d: %w", BlocksFile, off, err)
	}
}

func ignoreTorn(err error) error {
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return nil
	}
	return err
}

func isZero(b []byte) bool {
	return len(bytes.Trim(b, "\x00")) == 0
}

// Append writes blk and syncs it to disk. On failure the file is rolled back to the last complete
// record so later appends are not written after a fragment.
func (s *Store) Append(blk *consensus.Block) error {
	if s.f == nil {
		return errors.New("store closed")
	}
	b := blk.Serialize()
	rec := binary.LittleEndian.AppendUint32(make([]byte, 0, 4+len(b)), uint32(len(b)))
	rec = append(rec, b...)
	_, err := s.f.Write(rec)
	if err == nil {
		err = s.f.Sync()
	}
	if err != nil {
		if terr := s.f.Truncate(s.size); terr != nil {
			return errors.Join(err, terr)
		}
		_, serr := s.f.Seek(s.size, io.SeekStart)
		return errors.Join(err, serr)
	}
	s.size += int64(len(rec))
	return nil
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

// ReadParams returns the params recorded in dir.
func ReadParams(dir string) (*consensus.Params, error) {
	data, err := os.ReadFile(filepath.Join(dir, ParamsFile))
	if err != nil {
		return nil, err
	}
	var p consensus.Params
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("%s: %w", ParamsFile, err)
	}
	return &p, p.Validate()
}

// checkParams records p in dir on first use and otherwise requires it to match.
func checkParams(dir string, p *consensus.Params) error {
	stored, err := ReadParams(dir)
	if errors.Is(err, os.ErrNotExist) {
		data, err := json.MarshalIndent(p, "", " ")
		if err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(dir, ParamsFile), append(data, '\n'), 0o644)
	}
	if err != nil {
		return err
	}
	if !p.SameConsensus(stored) {
		return fmt.Errorf("data directory %s was created with different chain params", dir)
	}
	return nil
}
