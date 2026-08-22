package main

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLoadConfigRequiresLoopbackAndSecureProxy(t *testing.T) {
	valid := map[string]string{
		"ADMIN_HTTP_ADDRESS":       "127.0.0.1:18181",
		"ADMIN_DATABASE_DSN_FILE":  "/synthetic/database",
		"ADMIN_DEVICE_PEPPER_FILE": "/synthetic/pepper",
		"ADMIN_TRUST_HTTPS_PROXY":  "true",
	}
	getenv := func(key string) string { return valid[key] }
	config, err := loadConfig(getenv)
	if err != nil || config.address != "127.0.0.1:18181" {
		t.Fatalf("loadConfig(valid) = %#v/%v", config, err)
	}
	for name, mutate := range map[string]func(map[string]string){
		"public address": func(values map[string]string) { values["ADMIN_HTTP_ADDRESS"] = "0.0.0.0:18181" },
		"hostname":       func(values map[string]string) { values["ADMIN_HTTP_ADDRESS"] = "localhost:18181" },
		"missing DSN":    func(values map[string]string) { delete(values, "ADMIN_DATABASE_DSN_FILE") },
		"missing pepper": func(values map[string]string) { delete(values, "ADMIN_DEVICE_PEPPER_FILE") },
		"proxy disabled": func(values map[string]string) { values["ADMIN_TRUST_HTTPS_PROXY"] = "false" },
	} {
		t.Run(name, func(t *testing.T) {
			values := make(map[string]string, len(valid))
			for key, value := range valid {
				values[key] = value
			}
			mutate(values)
			if _, err := loadConfig(func(key string) string { return values[key] }); err == nil {
				t.Fatal("loadConfig() accepted unsafe configuration")
			}
		})
	}
}

func TestOpenProductionRuntimeRejectsUnsafeFilesAndUnavailableDatabase(t *testing.T) {
	directory := t.TempDir()
	unsafeDSN := filepath.Join(directory, "unsafe-dsn")
	pepper := filepath.Join(directory, "pepper")
	if err := os.WriteFile(unsafeDSN, []byte("postgres://synthetic-host/database"), 0o644); err != nil {
		t.Fatalf("write unsafe DSN: %v", err)
	}
	if err := os.WriteFile(pepper, bytes.Repeat([]byte{0x31}, 32), 0o600); err != nil {
		t.Fatalf("write pepper: %v", err)
	}
	config := webConfig{address: "127.0.0.1:18181", databaseDSNFile: unsafeDSN, pepperFile: pepper, trustHTTPSProxy: true}
	if _, closeRuntime, err := openProductionRuntime(context.Background(), config); err == nil {
		closeRuntime()
		t.Fatal("openProductionRuntime() accepted unsafe DSN file")
	}
	if err := os.Chmod(unsafeDSN, 0o600); err != nil {
		t.Fatalf("chmod DSN: %v", err)
	}
	if err := os.WriteFile(unsafeDSN, []byte("postgres://127.0.0.1:1/unavailable?sslmode=disable"), 0o600); err != nil {
		t.Fatalf("rewrite DSN: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()
	if _, closeRuntime, err := openProductionRuntime(ctx, config); err == nil {
		closeRuntime()
		t.Fatal("openProductionRuntime() accepted unavailable database")
	}
}

func TestServeShutsDownAfterContextCancellation(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen(): %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	var logs bytes.Buffer
	result := make(chan error, 1)
	go func() {
		result <- serve(ctx, listener, http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
			response.WriteHeader(http.StatusNoContent)
		}), &logs)
	}()
	response, err := http.Get("http://" + listener.Addr().String())
	if err != nil {
		t.Fatalf("GET running server: %v", err)
	}
	_ = response.Body.Close()
	cancel()
	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("serve() after cancellation: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("serve() did not shut down")
	}
	if !strings.Contains(logs.String(), listener.Addr().String()) || strings.Contains(logs.String(), "postgres") {
		t.Fatalf("startup log = %q", logs.String())
	}
}

func TestRunReportsOnlyGenericConfigurationError(t *testing.T) {
	secretPath := "/sensitive/local/path"
	values := map[string]string{
		"ADMIN_HTTP_ADDRESS":       "127.0.0.1:18181",
		"ADMIN_DATABASE_DSN_FILE":  secretPath,
		"ADMIN_DEVICE_PEPPER_FILE": "/synthetic/pepper",
		"ADMIN_TRUST_HTTPS_PROXY":  "true",
	}
	var output bytes.Buffer
	err := run(context.Background(), func(key string) string { return values[key] }, &output,
		func(context.Context, webConfig) (http.Handler, func(), error) {
			return nil, func() {}, io.ErrUnexpectedEOF
		})
	if err == nil || err.Error() != "administration startup failed" || strings.Contains(output.String()+err.Error(), secretPath) {
		t.Fatalf("run() error/output = %v/%q", err, output.String())
	}
}
