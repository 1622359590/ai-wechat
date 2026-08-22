package adminhttp

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
)

const contentSecurityPolicy = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"

func securityMiddleware(random io.Reader, next http.Handler) (http.Handler, error) {
	if next == nil {
		return nil, errors.New("administration HTTP handler is invalid")
	}
	if random == nil {
		random = rand.Reader
	}
	var randomMu sync.Mutex
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Content-Security-Policy", contentSecurityPolicy)
		response.Header().Set("X-Content-Type-Options", "nosniff")
		response.Header().Set("Referrer-Policy", "no-referrer")
		response.Header().Set("Cache-Control", "no-store")
		requestIDBytes := make([]byte, 16)
		randomMu.Lock()
		_, err := io.ReadFull(random, requestIDBytes)
		randomMu.Unlock()
		if err != nil {
			clear(requestIDBytes)
			writeError(response, http.StatusInternalServerError, "operation_failed")
			return
		}
		response.Header().Set("X-Request-ID", base64.RawURLEncoding.EncodeToString(requestIDBytes))
		clear(requestIDBytes)
		defer func() {
			if recover() != nil {
				writeError(response, http.StatusInternalServerError, "operation_failed")
			}
		}()
		next.ServeHTTP(response, request)
	}), nil
}

func isSecureRequest(request *http.Request) bool {
	return isSecureRequestWithProxy(request, false)
}

func isSecureRequestWithProxy(request *http.Request, trustProxy bool) bool {
	if request.TLS != nil {
		return true
	}
	return (trustProxy || remoteIsLoopback(request)) && len(request.Header.Values("X-Forwarded-Proto")) == 1 && request.Header.Get("X-Forwarded-Proto") == "https"
}

func clientIP(request *http.Request) (net.IP, error) {
	return clientIPWithProxy(request, false)
}

func clientIPWithProxy(request *http.Request, trustProxy bool) (net.IP, error) {
	if trustProxy || remoteIsLoopback(request) {
		values := request.Header.Values("X-Real-IP")
		if len(values) == 1 && !strings.Contains(values[0], ",") {
			if parsed := net.ParseIP(values[0]); parsed != nil {
				return parsed, nil
			}
			return nil, errors.New("invalid proxy client address")
		}
		if len(values) > 0 {
			return nil, errors.New("invalid proxy client address")
		}
	}
	host, _, err := net.SplitHostPort(request.RemoteAddr)
	if err != nil {
		return nil, errors.New("invalid remote address")
	}
	parsed := net.ParseIP(host)
	if parsed == nil {
		return nil, errors.New("invalid remote address")
	}
	return parsed, nil
}

func remoteIsLoopback(request *http.Request) bool {
	host, _, err := net.SplitHostPort(request.RemoteAddr)
	if err != nil {
		return false
	}
	address := net.ParseIP(host)
	return address != nil && address.IsLoopback()
}

func sameOrigin(request *http.Request) bool {
	values := request.Header.Values("Origin")
	if len(values) != 1 {
		return false
	}
	origin, err := url.Parse(values[0])
	if err != nil || origin.Scheme != "https" || origin.Host != request.Host || origin.User != nil || origin.Path != "" || origin.RawQuery != "" || origin.Fragment != "" {
		return false
	}
	return true
}
