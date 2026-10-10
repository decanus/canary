package chainjson

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/decanus/canary/internal/consensus"
)

func TestLoadDefaultsMissingParams(t *testing.T) {
	path := filepath.Join(t.TempDir(), "c.json")
	if err := os.WriteFile(path, []byte(`{"params": {"tau": 5}, "blocks": []}`), 0o644); err != nil {
		t.Fatal(err)
	}
	p, _, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	want := consensus.Prototype
	want.Tau = 5
	if !p.SameConsensus(&want) {
		t.Fatalf("got %+v, want reference defaults with tau=5", *p)
	}
}

func TestSaveRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "c.json")
	p := consensus.Prototype
	if err := Save(path, &p, nil); err != nil {
		t.Fatal(err)
	}
	if err := Save(path, &p, nil); err != nil { // overwrite in place
		t.Fatal(err)
	}
	if _, _, err := Load(path); err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(filepath.Dir(path))
	if len(entries) != 1 {
		t.Fatalf("temporary files left behind: %d entries", len(entries))
	}
}
