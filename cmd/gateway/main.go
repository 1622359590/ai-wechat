package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/1622359590/ai-wechat/internal/gateway"
	"github.com/1622359590/ai-wechat/internal/health"
	"github.com/1622359590/ai-wechat/internal/pairing"
	"github.com/1622359590/ai-wechat/internal/protocol"
	"github.com/1622359590/ai-wechat/internal/server"
	"github.com/1622359590/ai-wechat/proto/schema"
)

const (
	hardMaxBodyBytes = 16 * 1024 * 1024
	pairingStateRoot = "/var/lib/ai-wechat/pairing"
)

type config struct {
	tcpAddress                    string
	healthAddress                 string
	maxBodyBytes                  uint32
	unauthenticatedReadTimeout    time.Duration
	authenticatedReadTimeout      time.Duration
	writeTimeout                  time.Duration
	maxUnauthenticatedConnections int
	maxUnauthenticatedPerIP       int
	maxAuthenticatedConnections   int
	pairingStateFile              string
	pairingEnrollment             bool
	pairingAllowedCIDRs           []*net.IPNet
}

func main() {
	if len(os.Args) == 2 && os.Args[1] == "healthcheck" {
		if err := runHealthcheck(); err != nil {
			log.Print(err)
			os.Exit(1)
		}
		return
	}
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	config, err := loadConfig(os.Getenv)
	if err != nil {
		return err
	}
	files, err := schema.Load()
	if err != nil {
		return fmt.Errorf("load protocol schema: %w", err)
	}
	codec, err := protocol.NewCodec(files)
	if err != nil {
		return fmt.Errorf("create protocol codec: %w", err)
	}
	authenticator, authMode, err := configuredAuthenticator(config)
	if err != nil {
		return err
	}
	handler := gateway.NewHandler(codec, authenticator, gateway.NoopResponder{})
	service := server.New(server.Config{
		MaxBodyBytes:                  config.maxBodyBytes,
		UnauthenticatedReadTimeout:    config.unauthenticatedReadTimeout,
		AuthenticatedReadTimeout:      config.authenticatedReadTimeout,
		WriteTimeout:                  config.writeTimeout,
		MaxUnauthenticatedConnections: config.maxUnauthenticatedConnections,
		MaxUnauthenticatedPerIP:       config.maxUnauthenticatedPerIP,
		MaxAuthenticatedConnections:   config.maxAuthenticatedConnections,
	}, handler)

	tcpListener, err := net.Listen("tcp", config.tcpAddress)
	if err != nil {
		return fmt.Errorf("listen TCP: %w", err)
	}
	healthServer := &http.Server{
		Addr:              config.healthAddress,
		Handler:           health.NewHandler(service.Ready),
		ReadHeaderTimeout: 2 * time.Second,
		ReadTimeout:       3 * time.Second,
		WriteTimeout:      3 * time.Second,
		IdleTimeout:       30 * time.Second,
	}

	errorsChannel := make(chan error, 2)
	go func() { errorsChannel <- service.Serve(tcpListener) }()
	go func() {
		err := healthServer.ListenAndServe()
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		errorsChannel <- err
	}()
	log.Printf("gateway started tcp=%s health=%s auth=%s", config.tcpAddress, config.healthAddress, authMode)

	signalContext, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	select {
	case <-signalContext.Done():
	case err := <-errorsChannel:
		if err != nil {
			return err
		}
	}

	shutdownContext, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := healthServer.Shutdown(shutdownContext); err != nil {
		return fmt.Errorf("shutdown health server: %w", err)
	}
	if err := service.Shutdown(shutdownContext); err != nil {
		return fmt.Errorf("shutdown TCP server: %w", err)
	}
	return nil
}

func loadConfig(getenv func(string) string) (config, error) {
	result := config{
		tcpAddress:                    valueOrDefault(getenv("GATEWAY_TCP_ADDRESS"), ":19090"),
		healthAddress:                 valueOrDefault(getenv("GATEWAY_HEALTH_ADDRESS"), ":18080"),
		maxBodyBytes:                  1024 * 1024,
		unauthenticatedReadTimeout:    10 * time.Second,
		authenticatedReadTimeout:      90 * time.Second,
		writeTimeout:                  10 * time.Second,
		maxUnauthenticatedConnections: 50,
		maxUnauthenticatedPerIP:       5,
		maxAuthenticatedConnections:   150,
	}
	if value := getenv("GATEWAY_MAX_BODY_BYTES"); value != "" {
		parsed, err := strconv.ParseUint(value, 10, 32)
		if err != nil || parsed == 0 || parsed > hardMaxBodyBytes {
			return config{}, fmt.Errorf("GATEWAY_MAX_BODY_BYTES must be between 1 and %d", hardMaxBodyBytes)
		}
		result.maxBodyBytes = uint32(parsed)
	}
	connectionLimits := []struct {
		key    string
		target *int
	}{
		{key: "GATEWAY_MAX_UNAUTHENTICATED_CONNECTIONS", target: &result.maxUnauthenticatedConnections},
		{key: "GATEWAY_MAX_UNAUTHENTICATED_PER_IP", target: &result.maxUnauthenticatedPerIP},
		{key: "GATEWAY_MAX_AUTHENTICATED_CONNECTIONS", target: &result.maxAuthenticatedConnections},
	}
	for _, limit := range connectionLimits {
		value := getenv(limit.key)
		if value == "" {
			continue
		}
		parsed, err := strconv.ParseInt(value, 10, strconv.IntSize)
		if err != nil || parsed < 1 {
			return config{}, fmt.Errorf("%s must be a positive integer", limit.key)
		}
		*limit.target = int(parsed)
	}

	enabledValue := getenv("GATEWAY_PAIRING_ENABLED")
	if enabledValue != "" {
		parsed, err := strconv.ParseBool(enabledValue)
		if err != nil {
			return config{}, errors.New("GATEWAY_PAIRING_ENABLED must be true or false")
		}
		result.pairingEnrollment = parsed
	}
	result.pairingStateFile = getenv("GATEWAY_PAIRING_STATE_FILE")
	allowedCIDRsValue := getenv("GATEWAY_PAIRING_ALLOWED_CIDRS")

	if result.pairingStateFile == "" {
		if result.pairingEnrollment || allowedCIDRsValue != "" {
			return config{}, errors.New("pairing enrollment requires GATEWAY_PAIRING_STATE_FILE and GATEWAY_PAIRING_ALLOWED_CIDRS")
		}
		return result, nil
	}
	if err := validatePairingStatePath(result.pairingStateFile); err != nil {
		return config{}, err
	}
	if !result.pairingEnrollment {
		if allowedCIDRsValue != "" {
			return config{}, errors.New("GATEWAY_PAIRING_ALLOWED_CIDRS requires pairing enrollment")
		}
		return result, nil
	}
	if allowedCIDRsValue == "" {
		return config{}, errors.New("pairing enrollment requires GATEWAY_PAIRING_ALLOWED_CIDRS")
	}
	for _, value := range strings.Split(allowedCIDRsValue, ",") {
		value = strings.TrimSpace(value)
		if value == "" {
			return config{}, errors.New("GATEWAY_PAIRING_ALLOWED_CIDRS contains an empty CIDR")
		}
		_, network, err := net.ParseCIDR(value)
		if err != nil {
			return config{}, errors.New("GATEWAY_PAIRING_ALLOWED_CIDRS contains an invalid CIDR")
		}
		result.pairingAllowedCIDRs = append(result.pairingAllowedCIDRs, network)
	}
	return result, nil
}

func validatePairingStatePath(stateFile string) error {
	if !filepath.IsAbs(stateFile) || filepath.Clean(stateFile) != stateFile {
		return errors.New("GATEWAY_PAIRING_STATE_FILE must be a clean absolute path")
	}
	relative, err := filepath.Rel(pairingStateRoot, stateFile)
	if err != nil || relative == "." || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return fmt.Errorf("GATEWAY_PAIRING_STATE_FILE must be below %s", pairingStateRoot)
	}
	return nil
}

func configuredAuthenticator(config config) (gateway.Authenticator, string, error) {
	if config.pairingStateFile == "" {
		return gateway.DenyAllAuthenticator{}, "deny-all", nil
	}
	authenticator, err := pairing.New(pairing.Config{
		StateFile:    config.pairingStateFile,
		Enrollment:   config.pairingEnrollment,
		AllowedCIDRs: config.pairingAllowedCIDRs,
	})
	if err != nil {
		return nil, "", fmt.Errorf("configure device pairing: %w", err)
	}
	mode := "locked"
	if config.pairingEnrollment {
		mode = "pairing"
	}
	return authenticator, mode, nil
}

func valueOrDefault(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}

func runHealthcheck() error {
	address := valueOrDefault(os.Getenv("GATEWAY_HEALTHCHECK_URL"), "http://127.0.0.1:18080/readyz")
	client := &http.Client{Timeout: 2 * time.Second}
	response, err := client.Get(address)
	if err != nil {
		return fmt.Errorf("healthcheck request failed: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("healthcheck status is %d", response.StatusCode)
	}
	return nil
}
