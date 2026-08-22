package adminhttp

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDecodeJSONRejectsUnknownTrailingAndOversizedBodies(t *testing.T) {
	for _, test := range []struct {
		name string
		body string
	}{
		{name: "unknown", body: `{"name":"ok","extra":true}`},
		{name: "trailing", body: `{"name":"ok"}{"name":"again"}`},
		{name: "oversized", body: `{"name":"` + strings.Repeat("a", 17*1024) + `"}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest("POST", "/", strings.NewReader(test.body))
			request.Header.Set("Content-Type", "application/json")
			response := httptest.NewRecorder()
			var input struct {
				Name string `json:"name"`
			}
			if err := decodeJSON(response, request, &input); err == nil {
				t.Fatal("decodeJSON() accepted invalid body")
			}
		})
	}
}

func TestDecodeJSONRequiresJSONContentType(t *testing.T) {
	request := httptest.NewRequest("POST", "/", strings.NewReader(`{"name":"ok"}`))
	request.Header.Set("Content-Type", "text/plain")
	if err := decodeJSON(httptest.NewRecorder(), request, &struct{}{}); err == nil {
		t.Fatal("decodeJSON() accepted text/plain")
	}
}
