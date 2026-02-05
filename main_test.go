package main

import (
	"sort"
	"testing"
)

func TestGetSortedAlgoNames(t *testing.T) {
	names := getSortedAlgoNames()
	if len(names) == 0 {
		t.Fatal("expected non-empty algorithm list")
	}

	// Check if sorted
	isSorted := sort.SliceIsSorted(names, func(i, j int) bool {
		return names[i] < names[j]
	})

	if !isSorted {
		t.Errorf("expected algorithm names to be sorted, got: %v", names)
	}

	// Check for some known algos
	expected := []string{"md5", "sha256", "blake3"}
	for _, exp := range expected {
		found := false
		for _, name := range names {
			if name == exp {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected to find %s in algorithm list", exp)
		}
	}
}
