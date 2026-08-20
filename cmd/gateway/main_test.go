package main

import (
	"path/filepath"
	"testing"
	"time"

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
	authenticator, mode, err := configuredAuthenticator(config{})
	if err != nil {
		t.Fatalf("configure default authenticator: %v", err)
	}
	if _, ok := authenticator.(gateway.DenyAllAuthenticator); !ok || mode != "deny-all" {
		t.Fatalf("default authenticator/mode = %T/%q", authenticator, mode)
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
	result, err := loadConfig(mapEnvironment(map[string]string{"GATEWAY_PAIRING_STATE_FILE": stateFile}))
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
		{name: "enabled missing CIDR", values: map[string]string{"GATEWAY_PAIRING_ENABLED": "true", "GATEWAY_PAIRING_STATE_FILE": validStateFile}},
		{name: "malformed CIDR", values: map[string]string{"GATEWAY_PAIRING_ENABLED": "true", "GATEWAY_PAIRING_STATE_FILE": validStateFile, "GATEWAY_PAIRING_ALLOWED_CIDRS": "not-a-cidr"}},
		{name: "CIDR without enrollment", values: map[string]string{"GATEWAY_PAIRING_STATE_FILE": validStateFile, "GATEWAY_PAIRING_ALLOWED_CIDRS": "192.0.2.8/32"}},
		{name: "state outside root", values: map[string]string{"GATEWAY_PAIRING_STATE_FILE": "/tmp/credential.json"}},
		{name: "state is root", values: map[string]string{"GATEWAY_PAIRING_STATE_FILE": pairingStateRoot}},
		{name: "relative state", values: map[string]string{"GATEWAY_PAIRING_STATE_FILE": "deploy/state/credential.json"}},
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
