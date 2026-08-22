package ui

import (
	"io/fs"
	"strings"
	"testing"
)

func TestAssetsAreEmbeddedAndSelfContained(t *testing.T) {
	for _, name := range []string{"index.html", "app.css", "app.js"} {
		contents, err := fs.ReadFile(Files, name)
		if err != nil || len(contents) == 0 {
			t.Fatalf("asset %s = %d bytes/%v", name, len(contents), err)
		}
		text := string(contents)
		if strings.Contains(text, "http://") || strings.Contains(text, "https://") || strings.Contains(text, "//cdn") {
			t.Fatalf("asset %s contains a remote URL", name)
		}
	}
	html, _ := fs.ReadFile(Files, "index.html")
	if strings.Contains(string(html), "<style") || strings.Contains(string(html), "<script>") {
		t.Fatal("index contains inline style or script")
	}
}

func TestPageFlowHasSafeManagementControls(t *testing.T) {
	html, _ := fs.ReadFile(Files, "index.html")
	page := string(html)
	for _, id := range []string{"login-form", "device-form", "device-list", "audit-list", "password-form", "logout-button"} {
		if !strings.Contains(page, `id="`+id+`"`) {
			t.Fatalf("page missing %s", id)
		}
	}
	javascript, _ := fs.ReadFile(Files, "app.js")
	script := string(javascript)
	for _, operation := range []string{"/session", "/devices", "/status", "/expiry", "/device-events", "/me/password"} {
		if !strings.Contains(script, operation) {
			t.Fatalf("script missing flow %s", operation)
		}
	}
	if !strings.Contains(script, ".textContent") || strings.Contains(script, ".innerHTML") || strings.Contains(script, "credential_fingerprint") {
		t.Fatal("script does not use safe text rendering")
	}
}
