package satdevents

import (
	"bufio"
	"os"
	"strings"
	"testing"
)

// TestVersionMatchesWorkspace makes "the Go SDK's version is the node's
// version" a checked fact: Version must equal [workspace.package] version in
// the repository's Cargo.toml, suffix included. A release cut or dev-cycle bump
// that moves one without the other fails here.
func TestVersionMatchesWorkspace(t *testing.T) {
	f, err := os.Open("../../Cargo.toml")
	if os.IsNotExist(err) {
		// The module was fetched on its own (the module proxy serves only this
		// subtree), so there is no workspace to compare against.
		t.Skip("not inside the satd repository")
	}
	if err != nil {
		t.Fatalf("reading the workspace manifest: %v", err)
	}
	defer func() { _ = f.Close() }()

	inSection := false
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(line, "[") {
			inSection = line == "[workspace.package]"
			continue
		}
		if !inSection || !strings.HasPrefix(line, "version") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok || strings.TrimSpace(key) != "version" {
			continue
		}
		workspace := strings.Trim(strings.TrimSpace(value), `"`)
		if workspace != Version {
			t.Fatalf("satdevents.Version = %q, workspace version = %q; bump clients/go/version.go with Cargo.toml",
				Version, workspace)
		}
		return
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	t.Fatal("no version under [workspace.package] in ../../Cargo.toml")
}
