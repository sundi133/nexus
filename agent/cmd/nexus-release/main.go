// nexus-release signs agent releases (DEV-07). It runs in the release
// pipeline, which is the only place the private release key exists.
//
//	nexus-release keygen --out DIR
//	nexus-release sign --key release.key --version 1.2.0 --dir dist/releases/1.2.0 [--notes "…"]
//
// `sign` signs every nexus-agent-<os>-<arch>[.exe] in DIR and writes DIR/release.json.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"time"

	"github.com/votal-ai/nexus/agent/internal/release"
)

var artifactName = regexp.MustCompile(`^nexus-agent-(darwin|windows|linux)-(amd64|arm64)(\.exe)?$`)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: nexus-release keygen|sign …")
		os.Exit(2)
	}
	fs := flag.NewFlagSet(os.Args[1], flag.ExitOnError)
	var err error
	switch os.Args[1] {
	case "keygen":
		out := fs.String("out", ".", "directory for release.key and release.pub")
		_ = fs.Parse(os.Args[2:])
		err = keygen(*out)
	case "sign":
		keyFile := fs.String("key", "", "private release key file")
		version := fs.String("version", "", "release version, e.g. 1.2.0")
		dir := fs.String("dir", "", "directory holding the release binaries")
		notes := fs.String("notes", "", "release notes shown to admins")
		_ = fs.Parse(os.Args[2:])
		err = sign(*keyFile, *version, *dir, *notes)
	default:
		err = fmt.Errorf("unknown command %q", os.Args[1])
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func keygen(out string) error {
	if _, err := os.Stat(filepath.Join(out, "release.key")); err == nil {
		return errors.New("release.key already exists; refusing to overwrite a release key")
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(out, 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(out, "release.key"), []byte(base64.StdEncoding.EncodeToString(priv.Seed())+"\n"), 0o600); err != nil {
		return err
	}
	b64 := base64.StdEncoding.EncodeToString(pub)
	if err := os.WriteFile(filepath.Join(out, "release.pub"), []byte(b64+"\n"), 0o644); err != nil {
		return err
	}
	fmt.Printf("Release key %s\nPublic key (build agents with it): %s\n", release.KeyID(pub), b64)
	return nil
}

func loadKey(path string) (ed25519.PrivateKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	seed, err := base64.StdEncoding.DecodeString(string(trimNL(raw)))
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, errors.New("release key file is not a base64 Ed25519 seed")
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

func trimNL(b []byte) []byte {
	for len(b) > 0 && (b[len(b)-1] == '\n' || b[len(b)-1] == '\r') {
		b = b[:len(b)-1]
	}
	return b
}

func sign(keyFile, version, dir, notes string) error {
	if keyFile == "" || version == "" || dir == "" {
		return errors.New("--key, --version and --dir are required")
	}
	if release.Compare(version, "0.0.0") < 0 {
		return fmt.Errorf("version %q isn't MAJOR.MINOR.PATCH", version)
	}
	priv, err := loadKey(keyFile)
	if err != nil {
		return err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	m := release.Manifest{Version: version, PublishedAt: time.Now().UTC().Format(time.RFC3339), Notes: notes}
	for _, e := range entries {
		match := artifactName.FindStringSubmatch(e.Name())
		if e.IsDir() || match == nil {
			continue
		}
		sum, size, err := hashFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return err
		}
		kid, sig := release.Sign(priv, version, match[1], match[2], sum, size)
		m.Artifacts = append(m.Artifacts, release.Artifact{OS: match[1], Arch: match[2], File: e.Name(), SHA256: sum, Size: size, KeyID: kid, Signature: sig})
	}
	if len(m.Artifacts) == 0 {
		return fmt.Errorf("no nexus-agent-<os>-<arch> binaries in %s", dir)
	}
	sort.Slice(m.Artifacts, func(i, j int) bool { return m.Artifacts[i].File < m.Artifacts[j].File })
	data, _ := json.MarshalIndent(m, "", "  ")
	if err := os.WriteFile(filepath.Join(dir, "release.json"), append(data, '\n'), 0o644); err != nil {
		return err
	}
	fmt.Printf("Signed %d artifacts for %s\n", len(m.Artifacts), version)
	return nil
}

func hashFile(path string) (string, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	return hex.EncodeToString(h.Sum(nil)), n, err
}
