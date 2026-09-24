package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadConfig(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "enroll.conf")
	_ = os.WriteFile(p, []byte("# dropped by MDM\nserver = https://api.nexus.example.com\r\ntoken=nxe_abc\n"), 0o600)
	server, token, err := readConfig(p)
	if err != nil || server != "https://api.nexus.example.com" || token != "nxe_abc" {
		t.Fatalf("got %q %q %v", server, token, err)
	}
	_ = os.WriteFile(p, []byte("server=https://x\n"), 0o600)
	if _, _, err := readConfig(p); err == nil {
		t.Fatal("missing token accepted")
	}
}
