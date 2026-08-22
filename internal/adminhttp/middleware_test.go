package adminhttp

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSecurityMiddlewareSetsHeadersAndRecovers(t *testing.T) {
	handler, err := securityMiddleware(bytes.NewReader(bytes.Repeat([]byte{0x31}, 64)), http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic("sensitive panic detail")
	}))
	if err != nil {
		t.Fatalf("securityMiddleware(): %v", err)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest("GET", "/livez", nil))
	if response.Code != http.StatusInternalServerError || response.Body.String() != `{"error":"operation_failed"}`+"\n" {
		t.Fatalf("response = %d/%q", response.Code, response.Body.String())
	}
	for name, want := range map[string]string{
		"Content-Security-Policy": "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
		"X-Content-Type-Options":  "nosniff",
		"Referrer-Policy":         "no-referrer",
		"Cache-Control":           "no-store",
	} {
		if got := response.Header().Get(name); got != want {
			t.Fatalf("%s = %q, want %q", name, got, want)
		}
	}
	if response.Header().Get("X-Request-ID") == "" {
		t.Fatal("missing X-Request-ID")
	}
}

func TestProxyMetadataIsTrustedOnlyFromLoopback(t *testing.T) {
	request := httptest.NewRequest("POST", "http://admin.example.test/api/admin/v1/session", nil)
	request.RemoteAddr = "127.0.0.1:1234"
	request.Header.Set("X-Forwarded-Proto", "https")
	request.Header.Set("X-Real-IP", "192.0.2.40")
	if !isSecureRequest(request) {
		t.Fatal("loopback proxy HTTPS was rejected")
	}
	if got, err := clientIP(request); err != nil || got.String() != "192.0.2.40" {
		t.Fatalf("clientIP(loopback proxy) = %v/%v", got, err)
	}
	request.RemoteAddr = "198.51.100.10:1234"
	if isSecureRequest(request) {
		t.Fatal("untrusted proxy HTTPS header was accepted")
	}
	if got, err := clientIP(request); err != nil || got.String() != "198.51.100.10" {
		t.Fatalf("clientIP(untrusted proxy) = %v/%v", got, err)
	}
}

func TestSameOriginRequiresExactHTTPSOrigin(t *testing.T) {
	request := httptest.NewRequest("POST", "http://admin.example.test/api/admin/v1/session", nil)
	request.Host = "admin.example.test"
	request.Header.Set("Origin", "https://admin.example.test")
	if !sameOrigin(request) {
		t.Fatal("sameOrigin() rejected exact origin")
	}
	request.Header.Set("Origin", "https://other.example.test")
	if sameOrigin(request) {
		t.Fatal("sameOrigin() accepted another origin")
	}
}
