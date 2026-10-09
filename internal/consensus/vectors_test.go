package consensus_test

import (
	"testing"

	"github.com/decanus/canary/internal/conformance"
)

const vectorsPath = "../../reference/test_vectors.json"

func TestVectors(t *testing.T) {
	v, err := conformance.Load(vectorsPath)
	if err != nil {
		t.Fatal(err)
	}
	results := conformance.Run(v)
	if len(results) == 0 {
		t.Fatal("no vectors ran")
	}
	for _, r := range results {
		if r.Err != nil {
			t.Errorf("%s %s: %v", r.Section, r.Name, r.Err)
		}
	}
}
