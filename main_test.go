package main

import (
	"encoding/json"
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

func TestRunHashCommandJSONOutput(t *testing.T) {
	root := t.TempDir()

	out, err := captureStdout(t, func() error {
		return runHashCommand([]string{"-remove", "-output", "json", root})
	})
	if err != nil {
		t.Fatalf("runHashCommand json: %v", err)
	}

	var payload hashRunOutput
	if err := json.Unmarshal([]byte(out), &payload); err != nil {
		t.Fatalf("unmarshal hash json payload: %v\noutput=%s", err, out)
	}
	if payload.Operation != "remove" {
		t.Fatalf("expected operation=remove, got %q", payload.Operation)
	}
	if payload.Root != root {
		t.Fatalf("expected root=%q, got %q", root, payload.Root)
	}
}
