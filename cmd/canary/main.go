// Command canary is the Canary node, miner and conformance tool.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"os/signal"
	"runtime"
	"time"

	"github.com/decanus/canary/internal/chainjson"
	"github.com/decanus/canary/internal/conformance"
	"github.com/decanus/canary/internal/consensus"
	"github.com/decanus/canary/internal/miner"
)

const usage = `usage: canary <command> [args]

commands:
  vectors [FILE]   run the conformance vectors (default reference/test_vectors.json)
  verify FILE      validate a chain JSON file and print its cumulative work
  mine --chain FILE [--blocks N] [--threads N] [--miner-address STR] [--profile prototype|mainnet]
                   mine blocks onto a chain JSON file (created if missing), offline
  node, export     not implemented yet (milestones M3–M5)
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	var err error
	switch cmd, args := os.Args[1], os.Args[2:]; cmd {
	case "vectors":
		err = runVectors(args)
	case "verify":
		err = runVerify(args)
	case "mine":
		err = runMine(args)
	case "node", "export":
		err = fmt.Errorf("%s: not implemented yet", cmd)
	case "-h", "--help", "help":
		fmt.Print(usage)
		return
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s", cmd, usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func runVectors(args []string) error {
	fs := flag.NewFlagSet("vectors", flag.ExitOnError)
	verbose := fs.Bool("v", false, "print every vector, not just failures")
	fs.Parse(args)
	path := "reference/test_vectors.json"
	if fs.NArg() > 0 {
		path = fs.Arg(0)
	}
	v, err := conformance.Load(path)
	if err != nil {
		return err
	}
	results := conformance.Run(v)
	failed := 0
	for _, r := range results {
		switch {
		case r.Err != nil:
			failed++
			fmt.Printf("FAIL  %-15s %s: %v\n", r.Section, r.Name, r.Err)
		case *verbose:
			fmt.Printf("ok    %-15s %s\n", r.Section, r.Name)
		}
	}
	fmt.Printf("%d/%d vectors passed\n", len(results)-failed, len(results))
	if failed > 0 {
		return fmt.Errorf("%d vectors failed", failed)
	}
	return nil
}

func runVerify(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: canary verify FILE.json")
	}
	p, blocks, err := chainjson.Load(args[0])
	if err != nil {
		return err
	}
	work, err := consensus.ValidateChain(p, blocks)
	if err != nil {
		return err
	}
	fmt.Printf("valid chain, cumulative work %s\n", work)
	return nil
}

func runMine(args []string) error {
	fset := flag.NewFlagSet("mine", flag.ExitOnError)
	chainPath := fset.String("chain", "", "chain JSON file (required)")
	blocks := fset.Int("blocks", 10, "number of blocks to mine")
	threads := fset.Int("threads", runtime.NumCPU(), "rho worker goroutines")
	minerAddr := fset.String("miner-address", "miner-address", "miner identity in the coinbase")
	profile := fset.String("profile", "prototype", "params for a new chain file: prototype or mainnet")
	epoch := fset.Int64("epoch", 0, "override epoch for a new chain file")
	tau := fset.Int64("tau", 0, "override tau for a new chain file")
	genesisBits := fset.Uint("genesis-bits", 0, "override genesis bits for a new chain file")
	fset.Parse(args)
	if *chainPath == "" {
		return errors.New("usage: canary mine --chain FILE.json [--blocks N]")
	}

	p, chain, err := chainjson.Load(*chainPath)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		switch *profile {
		case "prototype":
			p = new(consensus.Params)
			*p = consensus.Prototype
		case "mainnet":
			p = new(consensus.Params)
			*p = consensus.Mainnet
		default:
			return fmt.Errorf("unknown profile %q", *profile)
		}
		if *epoch != 0 {
			p.Epoch = *epoch
		}
		if *tau != 0 {
			p.Tau = *tau
		}
		if *genesisBits != 0 {
			p.GenesisBits = uint32(*genesisBits)
		}
		if err := p.Validate(); err != nil {
			return err
		}
	case err != nil:
		return err
	default:
		// Refuse to extend a chain that does not validate.
		if _, err := consensus.ValidateChain(p, chain); err != nil {
			return fmt.Errorf("existing chain: %w", err)
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	headers := make(consensus.Headers, len(chain))
	for i, b := range chain {
		headers[i] = b.Header
	}
	for i := 0; i < *blocks; i++ {
		res, err := miner.MineBlock(ctx, p, headers, *minerAddr, *threads, time.Now().Unix())
		if err != nil {
			return err
		}
		chain = append(chain, res.Block)
		headers = append(headers, res.Block.Header)
		if err := chainjson.Save(*chainPath, p, chain); err != nil {
			return err
		}
		h := res.Block.Hash()
		fmt.Fprintf(os.Stderr, "block %4d  bits=%d  ctr=%-5d curve %6.2fs  rho %7.2fs  dps=%-6d hash=%x\n",
			len(chain)-1, res.Block.Header.Bits, res.CurveCtr, res.CurveTime.Seconds(),
			res.RhoTime.Seconds(), res.Rho.DistinguishedPoints, h[:8])
	}
	return nil
}
