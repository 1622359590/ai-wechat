package main

import (
	"context"
	"crypto/rand"
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

	"github.com/1622359590/ai-wechat/internal/deviceauth"
	"github.com/1622359590/ai-wechat/internal/devices"
	devicepostgres "github.com/1622359590/ai-wechat/internal/devices/postgres"
	"github.com/1622359590/ai-wechat/internal/gateway"
	"github.com/1622359590/ai-wechat/internal/health"
	"github.com/1622359590/ai-wechat/internal/pairing"
	"github.com/1622359590/ai-wechat/internal/protocol"
	"github.com/1622359590/ai-wechat/internal/ratelimit"
	"github.com/1622359590/ai-wechat/internal/securefile"
	"github.com/1622359590/ai-wechat/internal/server"
	"github.com/1622359590/ai-wechat/proto/schema"
	"github.com/jackc/pgx/v5/pgxpool"
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
	authMode                      string
	deviceDatabaseDSNFile         string
	devicePepperFile              string
	pairingStateFile              string
	pairingEnrollment             bool
	pairingAllowedCIDRs           []*net.IPNet
}

type authenticationRuntime struct {
	authenticator gateway.Authenticator
	mode          string
	registryDSN   string
	pool          *pgxpool.Pool
}

func (runtime *authenticationRuntime) Close() {
	if runtime != nil && runtime.pool != nil {
		runtime.pool.Close()
	}
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
	signalContext, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	startupContext, cancelStartup := context.WithTimeout(signalContext, 5*time.Second)
	authentication, err := configureAuthentication(startupContext, config)
	cancelStartup()
	if err != nil {
		return err
	}
	defer authentication.Close()
	handler := gateway.NewHandler(codec, authentication.authenticator, gateway.NoopResponder{})
	service := server.New(server.Config{
		MaxBodyBytes:                  config.maxBodyBytes,
		UnauthenticatedReadTimeout:    config.unauthenticatedReadTimeout,
		AuthenticatedReadTimeout:      config.authenticatedReadTimeout,
		WriteTimeout:                  config.writeTimeout,
		MaxUnauthenticatedConnections: config.maxUnauthenticatedConnections,
		MaxUnauthenticatedPerIP:       config.maxUnauthenticatedPerIP,
		MaxAuthenticatedConnections:   config.maxAuthenticatedConnections,
	}, handler)
	var adminListener *devicepostgres.AdminEventListener
	if authentication.registryDSN != "" {
		listenerContext, cancelListenerStartup := context.WithTimeout(signalContext, 5*time.Second)
		adminListener, err = devicepostgres.NewAdminEventListener(listenerContext, authentication.registryDSN, service.DisconnectDevice)
		cancelListenerStartup()
		if err != nil {
			return errors.New("configure device admin event listener failed")
		}
		defer adminListener.Close()
	}

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

	errorsChannel := make(chan error, 3)
	go func() { errorsChannel <- service.Serve(tcpListener) }()
	go func() {
		err := healthServer.ListenAndServe()
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		errorsChannel <- err
	}()
	if adminListener != nil {
		go func() { errorsChannel <- adminListener.Run(signalContext) }()
	}
	log.Print(startupMessage(config, authentication.mode))

	var runError error
	select {
	case <-signalContext.Done():
	case err := <-errorsChannel:
		if err != nil {
			runError = err
		}
	}
	stop()

	shutdownContext, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := healthServer.Shutdown(shutdownContext); err != nil {
		return fmt.Errorf("shutdown health server: %w", err)
	}
	if err := service.Shutdown(shutdownContext); err != nil {
		return fmt.Errorf("shutdown TCP server: %w", err)
	}
	return runError
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
		authMode:                      "deny-all",
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

	if value := getenv("GATEWAY_AUTH_MODE"); value != "" {
		result.authMode = value
	}
	result.deviceDatabaseDSNFile = getenv("GATEWAY_DEVICE_DATABASE_DSN_FILE")
	result.devicePepperFile = getenv("GATEWAY_DEVICE_PEPPER_FILE")
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
	pairingConfigured := enabledValue != "" || result.pairingStateFile != "" || allowedCIDRsValue != ""
	registryConfigured := result.deviceDatabaseDSNFile != "" || result.devicePepperFile != ""

	switch result.authMode {
	case "deny-all":
		if pairingConfigured || registryConfigured {
			return config{}, errors.New("deny-all mode cannot include pairing or device registry settings")
		}
		return result, nil
	case "pairing":
		if registryConfigured {
			return config{}, errors.New("pairing mode cannot include device registry settings")
		}
		if result.pairingStateFile == "" {
			return config{}, errors.New("pairing mode requires GATEWAY_PAIRING_STATE_FILE")
		}
	case "device-registry":
		if pairingConfigured {
			return config{}, errors.New("device registry mode cannot include pairing settings")
		}
		if result.deviceDatabaseDSNFile == "" || result.devicePepperFile == "" {
			return config{}, errors.New("device registry mode requires both secret files")
		}
		return result, nil
	default:
		return config{}, errors.New("GATEWAY_AUTH_MODE is invalid")
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

func configureAuthentication(ctx context.Context, config config) (*authenticationRuntime, error) {
	switch config.authMode {
	case "deny-all":
		return &authenticationRuntime{authenticator: gateway.DenyAllAuthenticator{}, mode: "deny-all"}, nil
	case "pairing":
		authenticator, err := pairing.New(pairing.Config{
			StateFile:    config.pairingStateFile,
			Enrollment:   config.pairingEnrollment,
			AllowedCIDRs: config.pairingAllowedCIDRs,
		})
		if err != nil {
			return nil, fmt.Errorf("configure device pairing: %w", err)
		}
		return &authenticationRuntime{authenticator: authenticator, mode: "pairing"}, nil
	case "device-registry":
		dsn, err := securefile.ReadText(config.deviceDatabaseDSNFile, 16*1024)
		if err != nil {
			return nil, errors.New("read device registry configuration failed")
		}
		pepper, err := securefile.ReadExact(config.devicePepperFile, 32)
		if err != nil {
			return nil, errors.New("read device fingerprint configuration failed")
		}
		fingerprinter, err := devices.NewFingerprinter(pepper)
		clear(pepper)
		if err != nil {
			return nil, errors.New("configure device fingerprinting failed")
		}
		pool, err := devicepostgres.Open(ctx, dsn)
		if err != nil {
			return nil, errors.New("connect device registry failed")
		}
		limiterKey := make([]byte, 32)
		if _, err := rand.Read(limiterKey); err != nil {
			pool.Close()
			return nil, errors.New("initialize authentication limiter failed")
		}
		limiter, err := ratelimit.NewAuth(ratelimit.Config{
			AttemptsPerMinute: 20,
			Burst:             5,
			MaximumBackoff:    15 * time.Minute,
			Key:               limiterKey,
		})
		clear(limiterKey)
		if err != nil {
			pool.Close()
			return nil, errors.New("configure authentication limiter failed")
		}
		authenticator, err := deviceauth.New(devicepostgres.NewRepository(pool), fingerprinter, limiter, nil, nil)
		if err != nil {
			pool.Close()
			return nil, errors.New("configure device authentication failed")
		}
		return &authenticationRuntime{authenticator: authenticator, mode: "device-registry", registryDSN: dsn, pool: pool}, nil
	default:
		return nil, errors.New("authentication mode is invalid")
	}
}

func startupMessage(config config, authMode string) string {
	return fmt.Sprintf("gateway started tcp=%s health=%s auth=%s", config.tcpAddress, config.healthAddress, authMode)
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
