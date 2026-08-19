package main

import (
	"testing"
	"time"
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
