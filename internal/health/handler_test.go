package health_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/1622359590/ai-wechat/internal/health"
)

func TestLiveAndReadyEndpoints(t *testing.T) {
	ready := false
	handler := health.NewHandler(func() bool { return ready })

	assertStatus(t, handler, "/livez", http.StatusOK)
	assertStatus(t, handler, "/readyz", http.StatusServiceUnavailable)
	ready = true
	assertStatus(t, handler, "/readyz", http.StatusOK)
	assertStatus(t, handler, "/missing", http.StatusNotFound)
}

func assertStatus(t *testing.T, handler http.Handler, path string, want int) {
	t.Helper()
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, path, nil))
	if got := recorder.Code; got != want {
		t.Fatalf("%s status = %d, want %d", path, got, want)
	}
	if recorder.Body.String() != "" {
		t.Fatalf("%s returned a response body", path)
	}
}
