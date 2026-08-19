// Package health exposes body-free liveness and readiness endpoints.
package health

import "net/http"

type Handler struct {
	ready func() bool
}

func NewHandler(ready func() bool) *Handler {
	return &Handler{ready: ready}
}

func (handler *Handler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		writer.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	switch request.URL.Path {
	case "/livez":
		writer.WriteHeader(http.StatusOK)
	case "/readyz":
		if handler.ready() {
			writer.WriteHeader(http.StatusOK)
		} else {
			writer.WriteHeader(http.StatusServiceUnavailable)
		}
	default:
		writer.WriteHeader(http.StatusNotFound)
	}
}
