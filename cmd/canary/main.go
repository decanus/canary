// Command canary is the Canary node, miner and conformance tool.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/decanus/canary/internal/chainjson"
	"github.com/decanus/canary/internal/conformance"
	"github.com/decanus/canary/internal/consensus"
)

const usage = `usage: canary <command> [args]

commands:
  vectors [FILE]   run the conformance vectors (default reference/test_vectors.json)
  verify FILE      validate a chain JSON file and print its cumulative work
  node, mine, export  not implemented yet (milestones M2–M5)
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
	case "node", "mine", "export":
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
