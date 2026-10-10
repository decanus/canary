package conformance

import (
	"context"
	"math/big"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/decanus/canary/internal/chainjson"
	"github.com/decanus/canary/internal/consensus"
	"github.com/decanus/canary/internal/miner"
	"github.com/decanus/canary/internal/wallet"
)

// TestPythonVerifiesGoChain mines a small chain in Go with a Go-signed transfer and checks that
// the Python reference accepts it with the same supply.
func TestPythonVerifiesGoChain(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not found")
	}
	p := consensus.Prototype
	p.GenesisBits, p.MinBits, p.Epoch = 24, 20, 1000
	alice, err := wallet.Generate()
	if err != nil {
		t.Fatal(err)
	}
	bob := consensus.Address{0xb0}

	var headers consensus.Headers
	var blocks []*consensus.Block
	st := consensus.State{}
	now := time.Now().Unix()
	for i := 0; i < 3; i++ {
		var transfers []*consensus.Transfer
		if i == 2 {
			tx := &consensus.Transfer{To: bob, Amount: big.NewInt(1000), Fee: big.NewInt(3), Nonce: 0}
			if err := alice.SignTransfer(tx, headers[0].Hash()); err != nil {
				t.Fatal(err)
			}
			transfers = append(transfers, tx)
		}
		res, err := miner.MineBlock(context.Background(), &p, headers, st, alice.Address(), transfers, 2, now+int64(i))
		if err != nil {
			t.Fatal(err)
		}
		if st, _, err = consensus.ValidateBlock(&p, headers, st, res.Block, nil); err != nil {
			t.Fatal(err)
		}
		headers = append(headers, res.Block.Header)
		blocks = append(blocks, res.Block)
	}
	if st.Get(bob).Balance.Int64() != 1000 {
		t.Fatalf("bob balance %s", st.Get(bob).Balance)
	}

	path := filepath.Join(t.TempDir(), "chain.json")
	if err := chainjson.Save(path, &p, blocks); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(python, "../../reference/canary.py", "verify", path).CombinedOutput()
	if err != nil {
		t.Fatalf("python verify: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "supply "+st.Supply().String()) {
		t.Fatalf("python output %q, want supply %s", out, st.Supply())
	}
}
