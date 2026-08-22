package adminhttp

import (
	"context"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/1622359590/ai-wechat/internal/adminauth"
	"github.com/1622359590/ai-wechat/internal/deviceadmin"
	"github.com/1622359590/ai-wechat/internal/devices"
)

const (
	apiPrefix         = "/api/admin/v1"
	sessionCookieName = "__Host-ai_wechat_admin"
)

type AuthService interface {
	Login(context.Context, string, []byte, net.IP) (adminauth.LoginResult, error)
	Authenticate(context.Context, string) (adminauth.User, error)
	VerifyCSRF(context.Context, string, string) error
	RefreshCSRF(context.Context, string) (string, error)
	Logout(context.Context, string) error
	ChangePassword(context.Context, string, []byte, []byte) (adminauth.LoginResult, error)
}

type DeviceService interface {
	AddAs(context.Context, string, string, devices.Status, string, devices.AdminActor) (devices.Device, error)
	List(context.Context) ([]devices.Device, error)
	EnableAs(context.Context, devices.ID, devices.AdminActor) error
	DisableAs(context.Context, devices.ID, devices.AdminActor) error
	SetExpiryAs(context.Context, devices.ID, string, devices.AdminActor) error
	ListEvents(context.Context) ([]devices.AdminEvent, error)
}

type Config struct {
	Auth    AuthService
	Devices DeviceService
	Ready   func(context.Context) error
	Random  io.Reader
	Now     func() time.Time
}

type server struct {
	auth    AuthService
	devices DeviceService
	ready   func(context.Context) error
	now     func() time.Time
}

func New(config Config) (http.Handler, error) {
	if config.Auth == nil || config.Devices == nil || config.Ready == nil {
		return nil, errors.New("administration HTTP configuration is invalid")
	}
	if config.Random == nil {
		config.Random = rand.Reader
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	service := &server{auth: config.Auth, devices: config.Devices, ready: config.Ready, now: config.Now}
	return securityMiddleware(config.Random, http.HandlerFunc(service.serveHTTP))
}

func (service *server) serveHTTP(response http.ResponseWriter, request *http.Request) {
	if request.URL.Path == "/livez" || request.URL.Path == "/readyz" {
		service.health(response, request)
		return
	}
	if !strings.HasPrefix(request.URL.Path, apiPrefix) {
		writeError(response, http.StatusNotFound, "not_found")
		return
	}
	if !isSecureRequest(request) {
		writeError(response, http.StatusBadRequest, "request_rejected")
		return
	}
	if request.Method != http.MethodGet && request.Method != http.MethodHead && !sameOrigin(request) {
		writeError(response, http.StatusForbidden, "request_rejected")
		return
	}

	switch request.URL.Path {
	case apiPrefix + "/session":
		service.session(response, request)
	case apiPrefix + "/me":
		service.me(response, request)
	case apiPrefix + "/me/password":
		service.password(response, request)
	case apiPrefix + "/devices":
		service.deviceCollection(response, request)
	case apiPrefix + "/device-events":
		service.events(response, request)
	default:
		if strings.HasPrefix(request.URL.Path, apiPrefix+"/devices/") {
			service.deviceMember(response, request)
			return
		}
		writeError(response, http.StatusNotFound, "not_found")
	}
}

func (service *server) health(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		methodNotAllowed(response, http.MethodGet)
		return
	}
	if request.URL.Path == "/readyz" && service.ready(request.Context()) != nil {
		response.Header().Set("Content-Type", "text/plain; charset=utf-8")
		response.WriteHeader(http.StatusServiceUnavailable)
		_, _ = response.Write([]byte("not ready\n"))
		return
	}
	response.Header().Set("Content-Type", "text/plain; charset=utf-8")
	response.WriteHeader(http.StatusOK)
	_, _ = response.Write([]byte("ok\n"))
}

func (service *server) session(response http.ResponseWriter, request *http.Request) {
	switch request.Method {
	case http.MethodPost:
		var input struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}
		if decodeJSON(response, request, &input) != nil {
			writeError(response, http.StatusBadRequest, "invalid_request")
			return
		}
		ip, err := clientIP(request)
		if err != nil {
			writeError(response, http.StatusBadRequest, "request_rejected")
			return
		}
		password := []byte(input.Password)
		input.Password = ""
		result, err := service.auth.Login(request.Context(), input.Username, password, ip)
		clear(password)
		if err != nil {
			if errors.Is(err, adminauth.ErrRateLimited) {
				writeError(response, http.StatusTooManyRequests, "authentication_failed")
				return
			}
			writeError(response, http.StatusUnauthorized, "authentication_failed")
			return
		}
		setSessionCookie(response, result.SessionToken, result.ExpiresAt)
		writeJSON(response, http.StatusOK, loginView(result))
	case http.MethodDelete:
		_, token, ok := service.authorizeMutation(response, request)
		if !ok {
			return
		}
		if err := service.auth.Logout(request.Context(), token); err != nil {
			writeError(response, http.StatusUnauthorized, "authentication_required")
			return
		}
		clearSessionCookie(response, service.now())
		response.WriteHeader(http.StatusNoContent)
	default:
		methodNotAllowed(response, http.MethodPost+", "+http.MethodDelete)
	}
}

func (service *server) me(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		methodNotAllowed(response, http.MethodGet)
		return
	}
	user, token, ok := service.authorize(response, request)
	if !ok {
		return
	}
	csrfToken, err := service.auth.RefreshCSRF(request.Context(), token)
	if err != nil {
		writeError(response, http.StatusUnauthorized, "authentication_required")
		return
	}
	writeJSON(response, http.StatusOK, map[string]any{"user": userViewOf(user), "csrf_token": csrfToken})
}

func (service *server) password(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPut {
		methodNotAllowed(response, http.MethodPut)
		return
	}
	_, token, ok := service.authorizeMutation(response, request)
	if !ok {
		return
	}
	var input struct {
		Current string `json:"current_password"`
		New     string `json:"new_password"`
	}
	if decodeJSON(response, request, &input) != nil {
		writeError(response, http.StatusBadRequest, "invalid_request")
		return
	}
	currentPassword, newPassword := []byte(input.Current), []byte(input.New)
	input.Current, input.New = "", ""
	result, err := service.auth.ChangePassword(request.Context(), token, currentPassword, newPassword)
	clear(currentPassword)
	clear(newPassword)
	if err != nil {
		writeServiceError(response, err)
		return
	}
	setSessionCookie(response, result.SessionToken, result.ExpiresAt)
	writeJSON(response, http.StatusOK, loginView(result))
}

func (service *server) deviceCollection(response http.ResponseWriter, request *http.Request) {
	switch request.Method {
	case http.MethodGet:
		if _, _, ok := service.authorize(response, request); !ok {
			return
		}
		listed, err := service.devices.List(request.Context())
		if err != nil {
			writeServiceError(response, err)
			return
		}
		views := make([]deviceView, 0, len(listed))
		for _, device := range listed {
			views = append(views, deviceViewOf(device))
		}
		writeJSON(response, http.StatusOK, map[string]any{"devices": views})
	case http.MethodPost:
		user, _, ok := service.authorizeMutation(response, request)
		if !ok {
			return
		}
		var input struct {
			Credential string         `json:"credential"`
			Label      string         `json:"label"`
			Status     devices.Status `json:"status"`
			ExpiresAt  string         `json:"expires_at"`
		}
		if decodeJSON(response, request, &input) != nil {
			writeError(response, http.StatusBadRequest, "invalid_request")
			return
		}
		credential := input.Credential
		input.Credential = ""
		device, err := service.devices.AddAs(request.Context(), credential, input.Label, input.Status, input.ExpiresAt, webActor(user))
		credential = ""
		if err != nil {
			writeServiceError(response, err)
			return
		}
		writeJSON(response, http.StatusCreated, deviceViewOf(device))
	default:
		methodNotAllowed(response, http.MethodGet+", "+http.MethodPost)
	}
}

func (service *server) deviceMember(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPut {
		methodNotAllowed(response, http.MethodPut)
		return
	}
	remainder := strings.TrimPrefix(request.URL.Path, apiPrefix+"/devices/")
	parts := strings.Split(remainder, "/")
	if len(parts) != 2 || parts[0] == "" {
		writeError(response, http.StatusNotFound, "not_found")
		return
	}
	user, _, ok := service.authorizeMutation(response, request)
	if !ok {
		return
	}
	id := devices.ID(parts[0])
	actor := webActor(user)
	var err error
	switch parts[1] {
	case "status":
		var input struct {
			Status devices.Status `json:"status"`
		}
		if decodeJSON(response, request, &input) != nil {
			writeError(response, http.StatusBadRequest, "invalid_request")
			return
		}
		if input.Status == devices.StatusActive {
			err = service.devices.EnableAs(request.Context(), id, actor)
		} else if input.Status == devices.StatusDisabled {
			err = service.devices.DisableAs(request.Context(), id, actor)
		} else {
			err = deviceadmin.ErrInvalidInput
		}
	case "expiry":
		var input struct {
			ExpiresAt string `json:"expires_at"`
		}
		if decodeJSON(response, request, &input) != nil {
			writeError(response, http.StatusBadRequest, "invalid_request")
			return
		}
		err = service.devices.SetExpiryAs(request.Context(), id, input.ExpiresAt, actor)
	default:
		writeError(response, http.StatusNotFound, "not_found")
		return
	}
	if err != nil {
		writeServiceError(response, err)
		return
	}
	response.WriteHeader(http.StatusNoContent)
}

func (service *server) events(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		methodNotAllowed(response, http.MethodGet)
		return
	}
	if _, _, ok := service.authorize(response, request); !ok {
		return
	}
	events, err := service.devices.ListEvents(request.Context())
	if err != nil {
		writeServiceError(response, err)
		return
	}
	views := make([]eventView, 0, len(events))
	for _, event := range events {
		views = append(views, eventViewOf(event))
	}
	writeJSON(response, http.StatusOK, map[string]any{"events": views})
}

func (service *server) authorize(response http.ResponseWriter, request *http.Request) (adminauth.User, string, bool) {
	cookie, err := request.Cookie(sessionCookieName)
	if err != nil || cookie.Value == "" {
		writeError(response, http.StatusUnauthorized, "authentication_required")
		return adminauth.User{}, "", false
	}
	user, err := service.auth.Authenticate(request.Context(), cookie.Value)
	if err != nil {
		writeError(response, http.StatusUnauthorized, "authentication_required")
		return adminauth.User{}, "", false
	}
	return user, cookie.Value, true
}

func (service *server) authorizeMutation(response http.ResponseWriter, request *http.Request) (adminauth.User, string, bool) {
	user, token, ok := service.authorize(response, request)
	if !ok {
		return adminauth.User{}, "", false
	}
	if err := service.auth.VerifyCSRF(request.Context(), token, request.Header.Get("X-CSRF-Token")); err != nil {
		writeError(response, http.StatusForbidden, "request_rejected")
		return adminauth.User{}, "", false
	}
	return user, token, true
}

type userView struct {
	ID       string `json:"id"`
	Username string `json:"username"`
}

type deviceView struct {
	ID                  string     `json:"id"`
	Label               string     `json:"label"`
	Status              string     `json:"status"`
	ExpiresAt           *time.Time `json:"expires_at"`
	LastAuthenticatedAt *time.Time `json:"last_authenticated_at"`
}

type eventView struct {
	ID          int64     `json:"id"`
	DeviceID    string    `json:"device_id"`
	Action      string    `json:"action"`
	ActorType   string    `json:"actor_type"`
	AdminUserID string    `json:"admin_user_id,omitempty"`
	ReasonCode  string    `json:"reason_code"`
	CreatedAt   time.Time `json:"created_at"`
}

func userViewOf(user adminauth.User) userView {
	return userView{ID: string(user.ID), Username: user.Username}
}

func loginView(result adminauth.LoginResult) map[string]any {
	return map[string]any{"user": userViewOf(result.User), "csrf_token": result.CSRFToken, "expires_at": result.ExpiresAt}
}

func deviceViewOf(device devices.Device) deviceView {
	return deviceView{ID: string(device.ID), Label: device.Label, Status: string(device.Status), ExpiresAt: device.AuthExpiresAt, LastAuthenticatedAt: device.LastAuthenticatedAt}
}

func eventViewOf(event devices.AdminEvent) eventView {
	return eventView{ID: event.ID, DeviceID: string(event.DeviceID), Action: event.Action, ActorType: event.ActorType, AdminUserID: event.AdminUserID, ReasonCode: event.ReasonCode, CreatedAt: event.CreatedAt}
}

func webActor(user adminauth.User) devices.AdminActor {
	return devices.AdminActor{Type: "admin_web", AdminUserID: string(user.ID)}
}

func setSessionCookie(response http.ResponseWriter, token string, expiresAt time.Time) {
	http.SetCookie(response, &http.Cookie{Name: sessionCookieName, Value: token, Path: "/", Expires: expiresAt, Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode})
}

func clearSessionCookie(response http.ResponseWriter, now time.Time) {
	http.SetCookie(response, &http.Cookie{Name: sessionCookieName, Path: "/", Expires: now.Add(-time.Hour), MaxAge: -1, Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode})
}

func methodNotAllowed(response http.ResponseWriter, allow string) {
	response.Header().Set("Allow", allow)
	writeError(response, http.StatusMethodNotAllowed, "method_not_allowed")
}

func writeServiceError(response http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, devices.ErrInvalidInput), errors.Is(err, deviceadmin.ErrInvalidInput), errors.Is(err, adminauth.ErrInvalidInput):
		writeError(response, http.StatusBadRequest, "invalid_request")
	case errors.Is(err, devices.ErrAlreadyExists):
		writeError(response, http.StatusConflict, "already_exists")
	case errors.Is(err, devices.ErrNotFound):
		writeError(response, http.StatusNotFound, "not_found")
	case errors.Is(err, adminauth.ErrAuthenticationFailed):
		writeError(response, http.StatusUnauthorized, "authentication_required")
	case errors.Is(err, adminauth.ErrUnavailable):
		writeError(response, http.StatusServiceUnavailable, "temporarily_unavailable")
	default:
		writeError(response, http.StatusInternalServerError, "operation_failed")
	}
}
