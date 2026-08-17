package output

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestNewTightensExistingOutputPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits are not meaningful on Windows")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "aquatone_results.jsonl")
	if err := os.WriteFile(path, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	writer, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("result mode is %o, want 600", got)
	}
}
