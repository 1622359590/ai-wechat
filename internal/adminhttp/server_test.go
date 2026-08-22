package adminhttp

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/1622359590/ai-wechat/internal/adminauth"
	"github.com/1622359590/ai-wechat/internal/devices"
)

func TestSessionLoginUsesSecureCookieAndSafeResponse(t *testing.T) {
	handler, auth, _ := newHTTPTestHandler(t)
	response := performRequest(handler, "POST", "/api/admin/v1/session", `{"username":"ADMIN_01","password":"correct horse battery"}`, nil, "csrf-token")
	if response.Code != http.StatusOK {
		t.Fatalf("login response = %d/%s", response.Code, response.Body.String())
	}
	cookies := response.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("cookies = %#v", cookies)
	}
	cookie := cookies[0]
	if cookie.Name != sessionCookieName || cookie.Value != "session-token" || !cookie.Secure || !cookie.HttpOnly || cookie.SameSite != http.SameSiteStrictMode || cookie.Path != "/" || cookie.Domain != "" {
		t.Fatalf("session cookie = %#v", cookie)
	}
	if auth.loginUsername != "ADMIN_01" || auth.loginIP.String() != "192.0.2.50" || !allBytesZero(auth.loginPassword) {
		t.Fatalf("login input = %q/%v/%v", auth.loginUsername, auth.loginIP, auth.loginPassword)
	}
	if strings.Contains(response.Body.String(), "session-token") || !strings.Contains(response.Body.String(), "csrf-token") {
		t.Fatalf("unsafe login response = %q", response.Body.String())
	}
}

func TestExplicitContainerProxyTrustAcceptsForwardedMetadata(t *testing.T) {
	auth := &fakeAuthService{}
	handler, err := New(Config{
		Auth: auth, Devices: &fakeDeviceService{}, Ready: func(context.Context) error { return nil },
		Random: bytes.NewReader(bytes.Repeat([]byte{0x42}, 128)), TrustProxy: true,
	})
	if err != nil {
		t.Fatalf("New(): %v", err)
	}
	request := httptest.NewRequest(http.MethodPost, "http://admin.example.test/api/admin/v1/session", strings.NewReader(`{"username":"admin_01","password":"correct horse battery"}`))
	request.RemoteAddr = "172.20.0.1:54321"
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", "https://admin.example.test")
	request.Header.Set("X-Forwarded-Proto", "https")
	request.Header.Set("X-Real-IP", "192.0.2.60")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || auth.loginIP.String() != "192.0.2.60" {
		t.Fatalf("container proxy response/IP = %d/%v", response.Code, auth.loginIP)
	}
}

func TestProtectedRoutesRequireSessionCSRFAndActor(t *testing.T) {
	handler, _, deviceService := newHTTPTestHandler(t)
	unauthenticated := performRequest(handler, "GET", "/api/admin/v1/devices", "", nil, "")
	if unauthenticated.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated status = %d", unauthenticated.Code)
	}
	cookie := &http.Cookie{Name: sessionCookieName, Value: "session-token"}
	withoutCSRF := performRequest(handler, "POST", "/api/admin/v1/devices", `{"credential":"synthetic-device","label":"sales","status":"active","expires_at":"never"}`, cookie, "")
	if withoutCSRF.Code != http.StatusForbidden {
		t.Fatalf("missing CSRF status = %d/%s", withoutCSRF.Code, withoutCSRF.Body.String())
	}
	added := performRequest(handler, "POST", "/api/admin/v1/devices", `{"credential":"synthetic-device","label":"sales","status":"active","expires_at":"never"}`, cookie, "csrf-token")
	if added.Code != http.StatusCreated {
		t.Fatalf("add status = %d/%s", added.Code, added.Body.String())
	}
	if deviceService.actor.Type != "admin_web" || deviceService.actor.AdminUserID != string(testAdminID) || deviceService.credential != "synthetic-device" {
		t.Fatalf("managed add = actor %#v credential %q", deviceService.actor, deviceService.credential)
	}
}

func TestVersionedRoutesDispatchSafeOperations(t *testing.T) {
	handler, auth, deviceService := newHTTPTestHandler(t)
	cookie := &http.Cookie{Name: sessionCookieName, Value: "session-token"}
	tests := []struct {
		name   string
		method string
		path   string
		body   string
		csrf   string
		status int
		call   string
	}{
		{name: "me", method: "GET", path: "/api/admin/v1/me", status: 200, call: "refresh-csrf"},
		{name: "password", method: "PUT", path: "/api/admin/v1/me/password", body: `{"current_password":"correct horse battery","new_password":"replacement password"}`, csrf: "csrf-token", status: 200, call: "change-password"},
		{name: "devices", method: "GET", path: "/api/admin/v1/devices", status: 200, call: "list"},
		{name: "disable", method: "PUT", path: "/api/admin/v1/devices/00000000-0000-0000-0000-000000000091/status", body: `{"status":"disabled"}`, csrf: "csrf-token", status: 204, call: "disable"},
		{name: "enable", method: "PUT", path: "/api/admin/v1/devices/00000000-0000-0000-0000-000000000091/status", body: `{"status":"active"}`, csrf: "csrf-token", status: 204, call: "enable"},
		{name: "expiry", method: "PUT", path: "/api/admin/v1/devices/00000000-0000-0000-0000-000000000091/expiry", body: `{"expires_at":"never"}`, csrf: "csrf-token", status: 204, call: "expiry"},
		{name: "events", method: "GET", path: "/api/admin/v1/device-events", status: 200, call: "events"},
		{name: "logout", method: "DELETE", path: "/api/admin/v1/session", csrf: "csrf-token", status: 204, call: "logout"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			auth.call, deviceService.call = "", ""
			response := performRequest(handler, test.method, test.path, test.body, cookie, test.csrf)
			if response.Code != test.status {
				t.Fatalf("response = %d/%s", response.Code, response.Body.String())
			}
			got := deviceService.call
			if got == "" {
				got = auth.call
			}
			if got != test.call {
				t.Fatalf("call = %q, want %q", got, test.call)
			}
		})
	}
}

func TestAPIRejectsMethodsOriginsAndInternalErrors(t *testing.T) {
	handler, auth, _ := newHTTPTestHandler(t)
	cookie := &http.Cookie{Name: sessionCookieName, Value: "session-token"}
	method := performRequest(handler, "PATCH", "/api/admin/v1/devices", "", cookie, "csrf-token")
	if method.Code != http.StatusMethodNotAllowed || method.Header().Get("Allow") == "" {
		t.Fatalf("method response = %d allow=%q", method.Code, method.Header().Get("Allow"))
	}
	badOriginRequest := httptest.NewRequest("POST", "http://admin.example.test/api/admin/v1/session", strings.NewReader(`{"username":"admin_01","password":"correct horse battery"}`))
	badOriginRequest.RemoteAddr = "127.0.0.1:1234"
	badOriginRequest.Header.Set("X-Forwarded-Proto", "https")
	badOriginRequest.Header.Set("Origin", "https://other.example.test")
	badOriginRequest.Header.Set("Content-Type", "application/json")
	badOrigin := httptest.NewRecorder()
	handler.ServeHTTP(badOrigin, badOriginRequest)
	if badOrigin.Code != http.StatusForbidden {
		t.Fatalf("cross-origin response = %d/%s", badOrigin.Code, badOrigin.Body.String())
	}
	auth.loginErr = errors.New("database detail must not escape")
	failed := performRequest(handler, "POST", "/api/admin/v1/session", `{"username":"admin_01","password":"correct horse battery"}`, nil, "")
	if failed.Code != http.StatusUnauthorized || strings.Contains(failed.Body.String(), "database") {
		t.Fatalf("login failure = %d/%q", failed.Code, failed.Body.String())
	}
}

func TestExpiredOrInvalidSessionUsesUniformFailure(t *testing.T) {
	handler, auth, _ := newHTTPTestHandler(t)
	auth.authenticateErr = adminauth.ErrAuthenticationFailed
	response := performRequest(handler, "GET", "/api/admin/v1/devices", "", &http.Cookie{Name: sessionCookieName, Value: "expired-session"}, "")
	if response.Code != http.StatusUnauthorized || response.Body.String() != `{"error":"authentication_required"}`+"\n" {
		t.Fatalf("invalid session response = %d/%q", response.Code, response.Body.String())
	}
}

func TestHealthAndMIMETypes(t *testing.T) {
	handler, _, _ := newHTTPTestHandler(t)
	for _, path := range []string{"/livez", "/readyz"} {
		request := httptest.NewRequest("GET", path, nil)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusOK || !strings.HasPrefix(response.Header().Get("Content-Type"), "text/plain") {
			t.Fatalf("%s = %d/%q", path, response.Code, response.Header().Get("Content-Type"))
		}
	}
	api := performRequest(handler, "GET", "/api/admin/v1/devices", "", &http.Cookie{Name: sessionCookieName, Value: "session-token"}, "")
	if api.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("API content type = %q", api.Header().Get("Content-Type"))
	}
}

func TestPageAssetsUseExplicitMIMETypes(t *testing.T) {
	handler, _, _ := newHTTPTestHandler(t)
	for path, wantType := range map[string]string{
		"/":        "text/html; charset=utf-8",
		"/app.css": "text/css; charset=utf-8",
		"/app.js":  "text/javascript; charset=utf-8",
	} {
		response := performRequest(handler, "GET", path, "", nil, "")
		if response.Code != http.StatusOK || response.Header().Get("Content-Type") != wantType {
			t.Fatalf("asset %s = %d/%q", path, response.Code, response.Header().Get("Content-Type"))
		}
	}
}

func newHTTPTestHandler(t *testing.T) (http.Handler, *fakeAuthService, *fakeDeviceService) {
	t.Helper()
	auth := &fakeAuthService{}
	devicesService := &fakeDeviceService{}
	handler, err := New(Config{
		Auth:    auth,
		Devices: devicesService,
		Ready:   func(context.Context) error { return nil },
		Random:  bytes.NewReader(bytes.Repeat([]byte{0x41}, 1024)),
		Now:     func() time.Time { return time.Date(2026, 8, 22, 10, 0, 0, 0, time.UTC) },
	})
	if err != nil {
		t.Fatalf("New(): %v", err)
	}
	return handler, auth, devicesService
}

func performRequest(handler http.Handler, method, path, body string, cookie *http.Cookie, csrf string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, "http://admin.example.test"+path, strings.NewReader(body))
	request.Host = "admin.example.test"
	request.RemoteAddr = "127.0.0.1:1234"
	request.Header.Set("X-Forwarded-Proto", "https")
	request.Header.Set("X-Real-IP", "192.0.2.50")
	if body != "" {
		request.Header.Set("Content-Type", "application/json")
	}
	if method != http.MethodGet && method != http.MethodHead {
		request.Header.Set("Origin", "https://admin.example.test")
	}
	if cookie != nil {
		request.AddCookie(cookie)
	}
	if csrf != "" {
		request.Header.Set("X-CSRF-Token", csrf)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

const testAdminID adminauth.ID = "00000000-0000-0000-0000-000000000081"

type fakeAuthService struct {
	call            string
	loginUsername   string
	loginPassword   []byte
	loginIP         net.IP
	loginErr        error
	authenticateErr error
}

func (service *fakeAuthService) Login(_ context.Context, username string, password []byte, ip net.IP) (adminauth.LoginResult, error) {
	service.call, service.loginUsername, service.loginPassword, service.loginIP = "login", username, password, ip
	defer clear(password)
	if service.loginErr != nil {
		return adminauth.LoginResult{}, service.loginErr
	}
	return adminauth.LoginResult{User: adminauth.User{ID: testAdminID, Username: "Admin_01", Status: adminauth.StatusActive, PasswordVersion: 1}, SessionToken: "session-token", CSRFToken: "csrf-token", ExpiresAt: time.Now().Add(time.Hour)}, nil
}
func (service *fakeAuthService) Authenticate(context.Context, string) (adminauth.User, error) {
	if service.authenticateErr != nil {
		return adminauth.User{}, service.authenticateErr
	}
	return adminauth.User{ID: testAdminID, Username: "Admin_01", Status: adminauth.StatusActive, PasswordVersion: 1}, nil
}
func (service *fakeAuthService) VerifyCSRF(_ context.Context, _, csrf string) error {
	if csrf != "csrf-token" {
		return adminauth.ErrAuthenticationFailed
	}
	return nil
}
func (service *fakeAuthService) RefreshCSRF(context.Context, string) (string, error) {
	service.call = "refresh-csrf"
	return "new-csrf-token", nil
}
func (service *fakeAuthService) Logout(context.Context, string) error {
	service.call = "logout"
	return nil
}
func (service *fakeAuthService) ChangePassword(context.Context, string, []byte, []byte) (adminauth.LoginResult, error) {
	service.call = "change-password"
	return adminauth.LoginResult{User: adminauth.User{ID: testAdminID, Username: "Admin_01"}, SessionToken: "rotated-session", CSRFToken: "rotated-csrf", ExpiresAt: time.Now().Add(time.Hour)}, nil
}

type fakeDeviceService struct {
	call       string
	actor      devices.AdminActor
	credential string
}

func (service *fakeDeviceService) AddAs(_ context.Context, credential, label string, status devices.Status, expiry string, actor devices.AdminActor) (devices.Device, error) {
	service.call, service.actor, service.credential = "add", actor, credential
	return devices.Device{ID: "00000000-0000-0000-0000-000000000091", Label: label, Status: status}, nil
}
func (service *fakeDeviceService) List(context.Context) ([]devices.Device, error) {
	service.call = "list"
	return []devices.Device{{ID: "00000000-0000-0000-0000-000000000091", Label: "sales", Status: devices.StatusActive}}, nil
}
func (service *fakeDeviceService) EnableAs(_ context.Context, _ devices.ID, actor devices.AdminActor) error {
	service.call, service.actor = "enable", actor
	return nil
}
func (service *fakeDeviceService) DisableAs(_ context.Context, _ devices.ID, actor devices.AdminActor) error {
	service.call, service.actor = "disable", actor
	return nil
}
func (service *fakeDeviceService) SetExpiryAs(_ context.Context, _ devices.ID, _ string, actor devices.AdminActor) error {
	service.call, service.actor = "expiry", actor
	return nil
}
func (service *fakeDeviceService) ListEvents(context.Context) ([]devices.AdminEvent, error) {
	service.call = "events"
	return []devices.AdminEvent{{ID: 1, DeviceID: "00000000-0000-0000-0000-000000000091", Action: "created", ActorType: "admin_web", AdminUserID: string(testAdminID), ReasonCode: "manual_add"}}, nil
}

func allBytesZero(contents []byte) bool {
	for _, value := range contents {
		if value != 0 {
			return false
		}
	}
	return true
}
