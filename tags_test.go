package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestRunTagsSetAndGetJSONOutput(t *testing.T) {
	root := t.TempDir()
	filePath := filepath.Join(root, "sample.txt")
	if err := os.WriteFile(filePath, []byte("sample"), 0o644); err != nil {
		t.Fatalf("write sample file: %v", err)
	}
	requireTagsXattrWritable(t, filePath)

	setOut, err := captureStdout(t, func() error {
		return runTagsSetCommand([]string{"-output", "json", "-tags", "music;work,music", filePath})
	})
	if err != nil {
		t.Fatalf("runTagsSetCommand json: %v", err)
	}

	var setPayload tagsCommandOutput
	if err := json.Unmarshal([]byte(setOut), &setPayload); err != nil {
		t.Fatalf("unmarshal set output: %v\noutput=%s", err, setOut)
	}
	if setPayload.Operation != "set" {
		t.Fatalf("expected operation=set, got %q", setPayload.Operation)
	}
	if setPayload.Count != 2 {
		t.Fatalf("expected count=2, got %d", setPayload.Count)
	}
	if strings.Join(setPayload.Tags, ",") != "music,work" {
		t.Fatalf("unexpected set tags: %v", setPayload.Tags)
	}

	getOut, err := captureStdout(t, func() error {
		return runTagsGetCommand([]string{"-output", "json", filePath})
	})
	if err != nil {
		t.Fatalf("runTagsGetCommand json: %v", err)
	}

	var getPayload tagsCommandOutput
	if err := json.Unmarshal([]byte(getOut), &getPayload); err != nil {
		t.Fatalf("unmarshal get output: %v\noutput=%s", err, getOut)
	}
	if getPayload.Operation != "get" {
		t.Fatalf("expected operation=get, got %q", getPayload.Operation)
	}
	if strings.Join(getPayload.Tags, ",") != "music,work" {
		t.Fatalf("unexpected get tags: %v", getPayload.Tags)
	}
}

func TestRunTagsAddRemoveClearRoundTrip(t *testing.T) {
	root := t.TempDir()
	filePath := filepath.Join(root, "roundtrip.txt")
	if err := os.WriteFile(filePath, []byte("roundtrip"), 0o644); err != nil {
		t.Fatalf("write roundtrip file: %v", err)
	}
	requireTagsXattrWritable(t, filePath)

	if err := runTagsSetCommand([]string{"-tags", "music,work", filePath}); err != nil {
		t.Fatalf("seed tags via set: %v", err)
	}

	addOut, err := captureStdout(t, func() error {
		return runTagsAddCommand([]string{"-output", "json", "-tags", "archive,music", filePath})
	})
	if err != nil {
		t.Fatalf("runTagsAddCommand json: %v", err)
	}
	var addPayload tagsCommandOutput
	if err := json.Unmarshal([]byte(addOut), &addPayload); err != nil {
		t.Fatalf("unmarshal add output: %v\noutput=%s", err, addOut)
	}
	if strings.Join(addPayload.Tags, ",") != "archive,music,work" {
		t.Fatalf("unexpected add result tags: %v", addPayload.Tags)
	}

	removeOut, err := captureStdout(t, func() error {
		return runTagsRemoveCommand([]string{"-output", "json", "-tags", "work", filePath})
	})
	if err != nil {
		t.Fatalf("runTagsRemoveCommand json: %v", err)
	}
	var removePayload tagsCommandOutput
	if err := json.Unmarshal([]byte(removeOut), &removePayload); err != nil {
		t.Fatalf("unmarshal remove output: %v\noutput=%s", err, removeOut)
	}
	if strings.Join(removePayload.Tags, ",") != "archive,music" {
		t.Fatalf("unexpected remove result tags: %v", removePayload.Tags)
	}

	clearOut, err := captureStdout(t, func() error {
		return runTagsClearCommand([]string{"-output", "json", filePath})
	})
	if err != nil {
		t.Fatalf("runTagsClearCommand json: %v", err)
	}
	var clearPayload tagsCommandOutput
	if err := json.Unmarshal([]byte(clearOut), &clearPayload); err != nil {
		t.Fatalf("unmarshal clear output: %v\noutput=%s", err, clearOut)
	}
	if clearPayload.Count != 0 || len(clearPayload.Tags) != 0 {
		t.Fatalf("expected clear to remove all tags, payload=%+v", clearPayload)
	}

	getOut, err := captureStdout(t, func() error {
		return runTagsGetCommand([]string{"-output", "json", filePath})
	})
	if err != nil {
		t.Fatalf("runTagsGetCommand after clear: %v", err)
	}
	var getPayload tagsCommandOutput
	if err := json.Unmarshal([]byte(getOut), &getPayload); err != nil {
		t.Fatalf("unmarshal get output after clear: %v\noutput=%s", err, getOut)
	}
	if getPayload.Count != 0 || len(getPayload.Tags) != 0 {
		t.Fatalf("expected no tags after clear, got=%+v", getPayload)
	}
}

func TestRunTagsGetRejectsInvalidOutputMode(t *testing.T) {
	path := t.TempDir()
	err := runTagsGetCommand([]string{"-output", "yaml", path})
	if err == nil {
		t.Fatal("expected invalid output mode error")
	}
	if !strings.Contains(err.Error(), "unsupported output mode") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRunTagsSetRequiresTags(t *testing.T) {
	path := t.TempDir()
	err := runTagsSetCommand([]string{path})
	if err == nil {
		t.Fatal("expected missing tags error")
	}
	if !strings.Contains(err.Error(), "at least one tag is required") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func requireTagsXattrWritable(t *testing.T, path string) {
	t.Helper()

	if err := setXattr(path, snapshotXDGTagsKey, []byte("probe")); err != nil {
		t.Skipf("xattr tags not writable on this filesystem: %v", err)
	}
	if err := removeXattr(path, snapshotXDGTagsKey); err != nil && err != syscall.ENODATA && err != syscall.ENOENT {
		t.Skipf("xattr tags cleanup failed on this filesystem: %v", err)
	}
}
