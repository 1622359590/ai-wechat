package deploy_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestAdminWebLifecycle(t *testing.T) {
	address := requiredEnvironment(t, "SMOKE_ADMIN_ADDRESS")
	username := requiredEnvironment(t, "SMOKE_ADMIN_USERNAME")
	password := requiredEnvironment(t, "SMOKE_ADMIN_PASSWORD")
	newPassword := requiredEnvironment(t, "SMOKE_ADMIN_NEW_PASSWORD")
	credential := requiredEnvironment(t, "SMOKE_ADMIN_DEVICE")

	login := adminRequest(t, address, http.MethodPost, "/api/admin/v1/session", map[string]string{"username": username, "password": password}, "", "")
	assertAdminStatus(t, login, http.StatusOK)
	assertSecurityHeaders(t, login.header)
	session := login.cookie
	csrf := login.csrf
	if session == "" || csrf == "" || strings.Contains(login.body, session) {
		t.Fatal("login did not separate Session cookie and CSRF response")
	}

	added := adminRequest(t, address, http.MethodPost, "/api/admin/v1/devices", map[string]string{
		"credential": credential, "label": "smoke-admin-device", "status": "active", "expires_at": "never",
	}, session, csrf)
	assertAdminStatus(t, added, http.StatusCreated)
	var device struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal([]byte(added.body), &device); err != nil || device.ID == "" || strings.Contains(added.body, credential) {
		t.Fatalf("unsafe add response: %v/%s", err, added.body)
	}

	listed := adminRequest(t, address, http.MethodGet, "/api/admin/v1/devices", nil, session, "")
	assertAdminStatus(t, listed, http.StatusOK)
	if !strings.Contains(listed.body, device.ID) || strings.Contains(listed.body, credential) || strings.Contains(listed.body, "fingerprint") {
		t.Fatalf("unsafe device list: %s", listed.body)
	}
	for _, operation := range []struct {
		path string
		body map[string]string
	}{
		{path: "/api/admin/v1/devices/" + device.ID + "/status", body: map[string]string{"status": "disabled"}},
		{path: "/api/admin/v1/devices/" + device.ID + "/status", body: map[string]string{"status": "active"}},
		{path: "/api/admin/v1/devices/" + device.ID + "/expiry", body: map[string]string{"expires_at": "2030-01-01T00:00:00Z"}},
	} {
		result := adminRequest(t, address, http.MethodPut, operation.path, operation.body, session, csrf)
		assertAdminStatus(t, result, http.StatusNoContent)
	}
	events := adminRequest(t, address, http.MethodGet, "/api/admin/v1/device-events", nil, session, "")
	assertAdminStatus(t, events, http.StatusOK)
	if !strings.Contains(events.body, device.ID) || strings.Contains(events.body, credential) {
		t.Fatalf("unsafe audit response: %s", events.body)
	}

	changed := adminRequest(t, address, http.MethodPut, "/api/admin/v1/me/password", map[string]string{
		"current_password": password, "new_password": newPassword,
	}, session, csrf)
	assertAdminStatus(t, changed, http.StatusOK)
	oldSession := session
	session, csrf = changed.cookie, changed.csrf
	if session == "" || session == oldSession || csrf == "" {
		t.Fatal("password change did not rotate Session and CSRF")
	}
	assertAdminStatus(t, adminRequest(t, address, http.MethodGet, "/api/admin/v1/devices", nil, oldSession, ""), http.StatusUnauthorized)
	assertAdminStatus(t, adminRequest(t, address, http.MethodDelete, "/api/admin/v1/session", nil, session, csrf), http.StatusNoContent)
	assertAdminStatus(t, adminRequest(t, address, http.MethodGet, "/api/admin/v1/devices", nil, session, ""), http.StatusUnauthorized)
}

func TestAdminWebPersistsAfterRestart(t *testing.T) {
	address := requiredEnvironment(t, "SMOKE_ADMIN_ADDRESS")
	login := adminRequest(t, address, http.MethodPost, "/api/admin/v1/session", map[string]string{
		"username": requiredEnvironment(t, "SMOKE_ADMIN_USERNAME"), "password": requiredEnvironment(t, "SMOKE_ADMIN_NEW_PASSWORD"),
	}, "", "")
	assertAdminStatus(t, login, http.StatusOK)
	listed := adminRequest(t, address, http.MethodGet, "/api/admin/v1/devices", nil, login.cookie, "")
	assertAdminStatus(t, listed, http.StatusOK)
	if !strings.Contains(listed.body, "smoke-admin-device") {
		t.Fatalf("persisted device missing: %s", listed.body)
	}
}

type adminResponse struct {
	status int
	body   string
	header http.Header
	cookie string
	csrf   string
}

func adminRequest(t *testing.T, address, method, path string, body any, session, csrf string) adminResponse {
	t.Helper()
	var contents io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		contents = bytes.NewReader(encoded)
	}
	request, err := http.NewRequest(method, address+path, contents)
	if err != nil {
		t.Fatal(err)
	}
	request.Host = "admin.example.test"
	request.Header.Set("X-Forwarded-Proto", "https")
	request.Header.Set("X-Real-IP", "192.0.2.80")
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if method != http.MethodGet {
		request.Header.Set("Origin", "https://admin.example.test")
	}
	if session != "" {
		request.AddCookie(&http.Cookie{Name: "__Host-ai_wechat_admin", Value: session})
	}
	if csrf != "" {
		request.Header.Set("X-CSRF-Token", csrf)
	}
	response, err := (&http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}).Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	responseBody, err := io.ReadAll(io.LimitReader(response.Body, 64*1024))
	if err != nil {
		t.Fatal(err)
	}
	result := adminResponse{status: response.StatusCode, body: string(responseBody), header: response.Header}
	for _, cookie := range response.Cookies() {
		if cookie.Name == "__Host-ai_wechat_admin" && cookie.MaxAge >= 0 {
			result.cookie = cookie.Value
		}
	}
	var decoded struct {
		CSRF string `json:"csrf_token"`
	}
	if json.Unmarshal(responseBody, &decoded) == nil {
		result.csrf = decoded.CSRF
	}
	return result
}

func assertAdminStatus(t *testing.T, response adminResponse, want int) {
	t.Helper()
	if response.status != want {
		t.Fatalf("admin response status = %d, want %d; body=%s", response.status, want, response.body)
	}
}

func assertSecurityHeaders(t *testing.T, header http.Header) {
	t.Helper()
	for _, name := range []string{"Content-Security-Policy", "X-Content-Type-Options", "Referrer-Policy", "Cache-Control"} {
		if header.Get(name) == "" {
			t.Fatalf("missing security header %s", name)
		}
	}
}
