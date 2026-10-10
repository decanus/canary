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
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/decanus/canary/internal/chain"
	"github.com/decanus/canary/internal/chainjson"
	"github.com/decanus/canary/internal/conformance"
	"github.com/decanus/canary/internal/consensus"
	"github.com/decanus/canary/internal/miner"
	"github.com/decanus/canary/internal/node"
	"github.com/decanus/canary/internal/p2p"
	"github.com/decanus/canary/internal/wallet"
)

const usage = `usage: canary <command> [args]

commands:
  vectors [FILE]   run the conformance vectors (default reference/test_vectors.json)
  keygen --out FILE
                   create an SLH-DSA key, print its address
  verify FILE      validate a chain JSON file and print its cumulative work
  mine --chain FILE [--blocks N] [--threads N] [--miner-address STR] [--profile prototype|mainnet]
                   mine blocks onto a chain JSON file (created if missing), offline
  export --datadir DIR FILE
                   write a node's active chain as chain JSON (read-only)
  node [--datadir DIR] [--listen ADDRS] [--peers ADDRS] [--mine] [--miner-address STR]
       [--threads N] [--profile prototype|mainnet]
                   run a full node (libp2p networking, optional mining)
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
	case "keygen":
		err = runKeygen(args)
	case "export":
		err = runExport(args)
	case "node":
		err = runNode(args)
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
	fset := flag.NewFlagSet("vectors", flag.ExitOnError)
	verbose := fset.Bool("v", false, "print every vector, not just failures")
	fset.Parse(args)
	path := "reference/test_vectors.json"
	if fset.NArg() > 0 {
		path = fset.Arg(0)
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
	work, state, err := consensus.ValidateChain(p, blocks)
	if err != nil {
		return err
	}
	fmt.Printf("valid chain, cumulative work %s, %d accounts, supply %s\n", work, len(state), state.Supply())
	return nil
}

func runMine(args []string) error {
	fset := flag.NewFlagSet("mine", flag.ExitOnError)
	chainPath := fset.String("chain", "", "chain JSON file (required)")
	count := fset.Int("blocks", 10, "number of blocks to mine")
	threads := fset.Int("threads", runtime.NumCPU(), "rho worker goroutines")
	minerHex := fset.String("miner-address", "", "address (hex) that receives rewards (required)")
	profile := fset.String("profile", "prototype", "params for a new chain file: prototype or mainnet")
	epoch := fset.Int64("epoch", 0, "override epoch for a new chain file")
	tau := fset.Int64("tau", 0, "override tau for a new chain file")
	genesisBits := fset.Uint("genesis-bits", 0, "override genesis bits for a new chain file")
	fset.Parse(args)
	if *chainPath == "" || *minerHex == "" {
		return errors.New("usage: canary mine --chain FILE.json --miner-address ADDR [--blocks N]")
	}
	minerAddr, err := wallet.ParseAddress(*minerHex)
	if err != nil {
		return err
	}

	p, blocks, err := chainjson.Load(*chainPath)
	var state consensus.State
	switch {
	case errors.Is(err, fs.ErrNotExist):
		if p, err = profileParams(*profile); err != nil {
			return err
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
		state = consensus.State{}
	case err != nil:
		return err
	default:
		// Refuse to extend a chain that does not validate.
		if _, state, err = consensus.ValidateChain(p, blocks); err != nil {
			return fmt.Errorf("existing chain: %w", err)
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	headers := make(consensus.Headers, len(blocks))
	for i, b := range blocks {
		headers[i] = b.Header
	}
	for i := 0; i < *count; i++ {
		res, err := miner.MineBlock(ctx, p, headers, state, minerAddr, nil, *threads, time.Now().Unix())
		if err != nil {
			return err
		}
		if state, _, err = consensus.ValidateBlock(p, headers, state, res.Block, nil); err != nil {
			return err
		}
		blocks = append(blocks, res.Block)
		headers = append(headers, res.Block.Header)
		if err := chainjson.Save(*chainPath, p, blocks); err != nil {
			return err
		}
		h := res.Block.Hash()
		fmt.Fprintf(os.Stderr, "block %4d  bits=%d  ctr=%-5d curve %6.2fs  rho %7.2fs  dps=%-6d hash=%x\n",
			len(blocks)-1, res.Block.Header.Bits, res.CurveCtr, res.CurveTime.Seconds(),
			res.RhoTime.Seconds(), res.Rho.DistinguishedPoints, h[:8])
	}
	return nil
}

func profileParams(name string) (*consensus.Params, error) {
	var p consensus.Params
	switch name {
	case "prototype":
		p = consensus.Prototype
	case "mainnet":
		p = consensus.Mainnet
	default:
		return nil, fmt.Errorf("unknown profile %q", name)
	}
	return &p, nil
}

func runExport(args []string) error {
	fset := flag.NewFlagSet("export", flag.ExitOnError)
	datadir := fset.String("datadir", "", "node data directory (required)")
	fset.Parse(args)
	if *datadir == "" || fset.NArg() != 1 {
		return errors.New("usage: canary export --datadir DIR FILE.json")
	}
	m, err := chain.OpenReadOnly(*datadir)
	if err != nil {
		return err
	}
	blocks := m.ActiveBlocks()
	if err := chainjson.Save(fset.Arg(0), m.Params(), blocks); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "exported %d blocks\n", len(blocks))
	return nil
}

func runNode(args []string) error {
	fset := flag.NewFlagSet("node", flag.ExitOnError)
	profile := fset.String("profile", "prototype", "network: prototype or mainnet")
	datadir := fset.String("datadir", "", "data directory (default ~/.canary/<profile>)")
	listen := fset.String("listen", "", "comma-separated listen multiaddrs (default TCP and QUIC on the profile's port)")
	peers := fset.String("peers", "", "comma-separated peer multiaddrs ending in /p2p/<id>")
	mine := fset.Bool("mine", false, "mine blocks")
	minerHex := fset.String("miner-address", "", "address (hex) that receives rewards (required with --mine)")
	threads := fset.Int("threads", runtime.NumCPU(), "rho worker goroutines")
	fset.Parse(args)

	var minerAddr consensus.Address
	if *mine {
		var err error
		if minerAddr, err = wallet.ParseAddress(*minerHex); err != nil {
			return fmt.Errorf("--miner-address: %w (create one with canary keygen)", err)
		}
	}
	p, err := profileParams(*profile)
	if err != nil {
		return err
	}
	if *datadir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return err
		}
		*datadir = filepath.Join(home, ".canary", p.Network)
	}
	listenAddrs := splitList(*listen)
	if len(listenAddrs) == 0 {
		listenAddrs = []string{
			fmt.Sprintf("/ip4/0.0.0.0/tcp/%d", p.P2PPort),
			fmt.Sprintf("/ip4/0.0.0.0/udp/%d/quic-v1", p.P2PPort),
		}
	}

	n, err := node.Open(node.Config{
		DataDir:      *datadir,
		Params:       p,
		P2P:          p2p.Config{Listen: listenAddrs, Peers: splitList(*peers)},
		Mine:         *mine,
		MinerAddress: minerAddr,
		Threads:      *threads,
	})
	if err != nil {
		return err
	}
	defer n.Close()
	fmt.Fprintf(os.Stderr, "canary %s node, datadir %s, %d blocks\n", p.Network, *datadir, n.Chain.Height())
	for _, a := range n.P2P.Addrs() {
		fmt.Fprintf(os.Stderr, "listening on %s\n", a)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return n.Run(ctx)
}

func splitList(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out
}

func runKeygen(args []string) error {
	fset := flag.NewFlagSet("keygen", flag.ExitOnError)
	out := fset.String("out", "", "file to write the private key to (required; must not exist)")
	fset.Parse(args)
	if *out == "" {
		return errors.New("usage: canary keygen --out FILE")
	}
	k, err := wallet.Generate()
	if err != nil {
		return err
	}
	if err := k.Save(*out); err != nil {
		return err
	}
	a := k.Address()
	fmt.Printf("%x\n", a)
	return nil
}
