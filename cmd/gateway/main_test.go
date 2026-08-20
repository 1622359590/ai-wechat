package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/1622359590/ai-wechat/internal/deviceauth"
	"github.com/1622359590/ai-wechat/internal/gateway"
)

func TestLoadConfigUsesSafeDefaults(t *testing.T) {
	config, err := loadConfig(func(string) string { return "" })
	if err != nil {
		t.Fatalf("load defaults: %v", err)
	}
	if config.tcpAddress != ":19090" || config.healthAddress != ":18080" {
		t.Fatalf("default addresses = %q/%q", config.tcpAddress, config.healthAddress)
	}
	if config.authMode != "deny-all" {
		t.Fatalf("default auth mode = %q, want deny-all", config.authMode)
	}
	if config.maxBodyBytes != 1024*1024 {
		t.Fatalf("default max body = %d", config.maxBodyBytes)
	}
	if config.unauthenticatedReadTimeout != 10*time.Second || config.authenticatedReadTimeout != 90*time.Second || config.writeTimeout != 10*time.Second {
		t.Fatalf("default timeouts = %v/%v/%v", config.unauthenticatedReadTimeout, config.authenticatedReadTimeout, config.writeTimeout)
	}
	if config.maxUnauthenticatedConnections != 50 || config.maxUnauthenticatedPerIP != 5 || config.maxAuthenticatedConnections != 150 {
		t.Fatalf("default connection limits = %d/%d/%d, want 50/5/150", config.maxUnauthenticatedConnections, config.maxUnauthenticatedPerIP, config.maxAuthenticatedConnections)
	}
	if config.pairingStateFile != "" || config.pairingEnrollment || len(config.pairingAllowedCIDRs) != 0 {
		t.Fatal("default configuration enabled pairing")
	}
}

func TestLoadConfigRejectsInvalidConnectionLimits(t *testing.T) {
	keys := []string{
		"GATEWAY_MAX_UNAUTHENTICATED_CONNECTIONS",
		"GATEWAY_MAX_UNAUTHENTICATED_PER_IP",
		"GATEWAY_MAX_AUTHENTICATED_CONNECTIONS",
	}
	for _, key := range keys {
		for _, value := range []string{"0", "-1", "invalid", "9223372036854775808"} {
			t.Run(key+"="+value, func(t *testing.T) {
				if _, err := loadConfig(mapEnvironment(map[string]string{key: value})); err == nil {
					t.Fatal("invalid connection limit was accepted")
				}
			})
		}
	}
}

func TestLoadConfigAcceptsPositiveConnectionLimits(t *testing.T) {
	result, err := loadConfig(mapEnvironment(map[string]string{
		"GATEWAY_MAX_UNAUTHENTICATED_CONNECTIONS": "60",
		"GATEWAY_MAX_UNAUTHENTICATED_PER_IP":      "6",
		"GATEWAY_MAX_AUTHENTICATED_CONNECTIONS":   "160",
	}))
	if err != nil {
		t.Fatalf("load connection limits: %v", err)
	}
	if result.maxUnauthenticatedConnections != 60 || result.maxUnauthenticatedPerIP != 6 || result.maxAuthenticatedConnections != 160 {
		t.Fatalf("connection limits = %d/%d/%d, want 60/6/160", result.maxUnauthenticatedConnections, result.maxUnauthenticatedPerIP, result.maxAuthenticatedConnections)
	}
}

func TestConfiguredAuthenticatorDefaultsToDenyAll(t *testing.T) {
	runtime, err := configureAuthentication(context.Background(), config{authMode: "deny-all"})
	if err != nil {
		t.Fatalf("configure default authenticator: %v", err)
	}
	defer runtime.Close()
	if _, ok := runtime.authenticator.(gateway.DenyAllAuthenticator); !ok || runtime.mode != "deny-all" {
		t.Fatalf("default authenticator/mode = %T/%q", runtime.authenticator, runtime.mode)
	}
}

func TestLoadConfigRequiresExplicitCompleteAuthenticationMode(t *testing.T) {
	directory := t.TempDir()
	dsnFile := writeMainSecret(t, directory, "database.txt", []byte("postgres://synthetic-host/device?sslmode=require"), 0o600)
	pepperFile := writeMainSecret(t, directory, "pepper.bin", bytes.Repeat([]byte{0x51}, 32), 0o400)
	stateFile := filepath.Join(pairingStateRoot, "credential.json")

	tests := []struct {
		name      string
		values    map[string]string
		wantMode  string
		wantError bool
	}{
		{name: "explicit deny", values: map[string]string{"GATEWAY_AUTH_MODE": "deny-all"}, wantMode: "deny-all"},
		{name: "complete registry", values: map[string]string{"GATEWAY_AUTH_MODE": "device-registry", "GATEWAY_DEVICE_DATABASE_DSN_FILE": dsnFile, "GATEWAY_DEVICE_PEPPER_FILE": pepperFile}, wantMode: "device-registry"},
		{name: "unknown mode", values: map[string]string{"GATEWAY_AUTH_MODE": "unknown"}, wantError: true},
		{name: "registry missing DSN", values: map[string]string{"GATEWAY_AUTH_MODE": "device-registry", "GATEWAY_DEVICE_PEPPER_FILE": pepperFile}, wantError: true},
		{name: "registry missing pepper", values: map[string]string{"GATEWAY_AUTH_MODE": "device-registry", "GATEWAY_DEVICE_DATABASE_DSN_FILE": dsnFile}, wantError: true},
		{name: "registry mixed with pairing", values: map[string]string{"GATEWAY_AUTH_MODE": "device-registry", "GATEWAY_DEVICE_DATABASE_DSN_FILE": dsnFile, "GATEWAY_DEVICE_PEPPER_FILE": pepperFile, "GATEWAY_PAIRING_STATE_FILE": stateFile}, wantError: true},
		{name: "deny mixed with registry", values: map[string]string{"GATEWAY_AUTH_MODE": "deny-all", "GATEWAY_DEVICE_DATABASE_DSN_FILE": dsnFile}, wantError: true},
		{name: "pairing mixed with registry", values: map[string]string{"GATEWAY_AUTH_MODE": "pairing", "GATEWAY_PAIRING_STATE_FILE": stateFile, "GATEWAY_DEVICE_DATABASE_DSN_FILE": dsnFile, "GATEWAY_DEVICE_PEPPER_FILE": pepperFile}, wantError: true},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			result, err := loadConfig(mapEnvironment(testCase.values))
			if testCase.wantError {
				if err == nil {
					t.Fatal("invalid authentication configuration was accepted")
				}
				return
			}
			if err != nil || result.authMode != testCase.wantMode {
				t.Fatalf("load auth config = mode %q, error %v", result.authMode, err)
			}
		})
	}
}

func TestConfigureRegistryRejectsUnsafeFilesAndUnavailableDatabase(t *testing.T) {
	directory := t.TempDir()
	pepperFile := writeMainSecret(t, directory, "pepper.bin", bytes.Repeat([]byte{0x52}, 32), 0o600)
	unsafeDSN := writeMainSecret(t, directory, "unsafe-database.txt", []byte("postgres://127.0.0.1:1/unavailable?sslmode=disable"), 0o644)
	if _, err := configureAuthentication(context.Background(), config{authMode: "device-registry", deviceDatabaseDSNFile: unsafeDSN, devicePepperFile: pepperFile}); err == nil {
		t.Fatal("unsafe DSN file was accepted")
	} else if strings.Contains(err.Error(), unsafeDSN) {
		t.Fatalf("unsafe-file error exposed path: %v", err)
	}

	safeDSN := writeMainSecret(t, directory, "database.txt", []byte("postgres://127.0.0.1:1/unavailable?sslmode=disable"), 0o600)
	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()
	if _, err := configureAuthentication(ctx, config{authMode: "device-registry", deviceDatabaseDSNFile: safeDSN, devicePepperFile: pepperFile}); err == nil {
		t.Fatal("unavailable registry database was accepted")
	} else if strings.Contains(err.Error(), "127.0.0.1") || strings.Contains(err.Error(), safeDSN) {
		t.Fatalf("database error exposed connection material: %v", err)
	}
}

func TestConfigureRegistryBuildsRuntimeWithoutMigratingSchema(t *testing.T) {
	dsn := os.Getenv("TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("TEST_POSTGRES_DSN is not set")
	}
	directory := t.TempDir()
	dsnFile := writeMainSecret(t, directory, "database.txt", []byte(dsn), 0o600)
	pepperFile := writeMainSecret(t, directory, "pepper.bin", bytes.Repeat([]byte{0x53}, 32), 0o600)

	runtime, err := configureAuthentication(context.Background(), config{
		authMode:              "device-registry",
		deviceDatabaseDSNFile: dsnFile,
		devicePepperFile:      pepperFile,
	})
	if err != nil {
		t.Fatalf("configure registry runtime: %v", err)
	}
	defer runtime.Close()
	if _, ok := runtime.authenticator.(*deviceauth.Authenticator); !ok || runtime.mode != "device-registry" || runtime.registryDSN == "" {
		t.Fatalf("registry runtime = authenticator %T, mode %q, DSN present %v", runtime.authenticator, runtime.mode, runtime.registryDSN != "")
	}
	var schemaCreated bool
	if err := runtime.pool.QueryRow(context.Background(), "SELECT to_regclass('schema_migrations') IS NOT NULL").Scan(&schemaCreated); err != nil {
		t.Fatalf("inspect schema state: %v", err)
	}
	if schemaCreated {
		t.Fatal("registry startup mutated the database schema")
	}
}

func TestRegistryStartupMessageContainsOnlyModeAndAddresses(t *testing.T) {
	message := startupMessage(config{tcpAddress: ":19090", healthAddress: ":18080"}, "device-registry")
	if message != "gateway started tcp=:19090 health=:18080 auth=device-registry" {
		t.Fatalf("startup message = %q", message)
	}
}

func TestLoadConfigRejectsInvalidOrUnsafeFrameLimits(t *testing.T) {
	for _, value := range []string{"0", "invalid", "16777217"} {
		_, err := loadConfig(func(key string) string {
			if key == "GATEWAY_MAX_BODY_BYTES" {
				return value
			}
			return ""
		})
		if err == nil {
			t.Fatalf("max body %q was accepted", value)
		}
	}
}

func TestLoadConfigAcceptsCompletePairingConfiguration(t *testing.T) {
	values := map[string]string{
		"GATEWAY_AUTH_MODE":             "pairing",
		"GATEWAY_PAIRING_STATE_FILE":    filepath.Join(pairingStateRoot, "credential.json"),
		"GATEWAY_PAIRING_ENABLED":       "true",
		"GATEWAY_PAIRING_ALLOWED_CIDRS": "192.0.2.8/32, 2001:db8::/128",
	}
	result, err := loadConfig(mapEnvironment(values))
	if err != nil {
		t.Fatalf("load pairing config: %v", err)
	}
	if result.pairingStateFile != values["GATEWAY_PAIRING_STATE_FILE"] || !result.pairingEnrollment {
		t.Fatal("complete pairing configuration was not retained")
	}
	if len(result.pairingAllowedCIDRs) != 2 || result.pairingAllowedCIDRs[0].String() != "192.0.2.8/32" || result.pairingAllowedCIDRs[1].String() != "2001:db8::/128" {
		t.Fatalf("allowed CIDRs = %v", result.pairingAllowedCIDRs)
	}
}

func TestLoadConfigAcceptsLockedPairingStateWithoutEnrollment(t *testing.T) {
	stateFile := filepath.Join(pairingStateRoot, "credential.json")
	result, err := loadConfig(mapEnvironment(map[string]string{"GATEWAY_AUTH_MODE": "pairing", "GATEWAY_PAIRING_STATE_FILE": stateFile}))
	if err != nil {
		t.Fatalf("load locked config: %v", err)
	}
	if result.pairingStateFile != stateFile || result.pairingEnrollment || len(result.pairingAllowedCIDRs) != 0 {
		t.Fatal("locked configuration was not retained")
	}
}

func TestLoadConfigRejectsPartialOrUnsafePairingConfiguration(t *testing.T) {
	validStateFile := filepath.Join(pairingStateRoot, "credential.json")
	tests := []struct {
		name   string
		values map[string]string
	}{
		{name: "invalid boolean", values: map[string]string{"GATEWAY_PAIRING_ENABLED": "sometimes"}},
		{name: "enabled missing state", values: map[string]string{"GATEWAY_PAIRING_ENABLED": "true", "GATEWAY_PAIRING_ALLOWED_CIDRS": "192.0.2.8/32"}},
		{name: "enabled missing CIDR", values: map[string]string{"GATEWAY_AUTH_MODE": "pairing", "GATEWAY_PAIRING_ENABLED": "true", "GATEWAY_PAIRING_STATE_FILE": validStateFile}},
		{name: "malformed CIDR", values: map[string]string{"GATEWAY_AUTH_MODE": "pairing", "GATEWAY_PAIRING_ENABLED": "true", "GATEWAY_PAIRING_STATE_FILE": validStateFile, "GATEWAY_PAIRING_ALLOWED_CIDRS": "not-a-cidr"}},
		{name: "CIDR without enrollment", values: map[string]string{"GATEWAY_AUTH_MODE": "pairing", "GATEWAY_PAIRING_STATE_FILE": validStateFile, "GATEWAY_PAIRING_ALLOWED_CIDRS": "192.0.2.8/32"}},
		{name: "state outside root", values: map[string]string{"GATEWAY_AUTH_MODE": "pairing", "GATEWAY_PAIRING_STATE_FILE": "/tmp/credential.json"}},
		{name: "state is root", values: map[string]string{"GATEWAY_AUTH_MODE": "pairing", "GATEWAY_PAIRING_STATE_FILE": pairingStateRoot}},
		{name: "relative state", values: map[string]string{"GATEWAY_AUTH_MODE": "pairing", "GATEWAY_PAIRING_STATE_FILE": "deploy/state/credential.json"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := loadConfig(mapEnvironment(test.values)); err == nil {
				t.Fatal("unsafe pairing configuration was accepted")
			}
		})
	}
}

func mapEnvironment(values map[string]string) func(string) string {
	return func(key string) string { return values[key] }
}

func writeMainSecret(t *testing.T, directory, name string, contents []byte, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(directory, name)
	if err := os.WriteFile(path, contents, mode); err != nil {
		t.Fatalf("write secret fixture: %v", err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatalf("chmod secret fixture: %v", err)
	}
	return path
}
