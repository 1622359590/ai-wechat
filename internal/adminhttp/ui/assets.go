package ui

import (
	"embed"
	"net/http"
)

// Files contains the dependency-free administration console.
//
//go:embed index.html app.css app.js
var Files embed.FS

func Handler() http.Handler {
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		var name, contentType string
		switch request.URL.Path {
		case "/":
			name, contentType = "index.html", "text/html; charset=utf-8"
		case "/app.css":
			name, contentType = "app.css", "text/css; charset=utf-8"
		case "/app.js":
			name, contentType = "app.js", "text/javascript; charset=utf-8"
		default:
			http.NotFound(response, request)
			return
		}
		contents, err := Files.ReadFile(name)
		if err != nil {
			http.Error(response, "asset unavailable", http.StatusInternalServerError)
			return
		}
		response.Header().Set("Content-Type", contentType)
		response.WriteHeader(http.StatusOK)
		_, _ = response.Write(contents)
	})
}
