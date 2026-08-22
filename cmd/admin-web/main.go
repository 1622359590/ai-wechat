package main

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/1622359590/ai-wechat/internal/adminauth"
	adminpostgres "github.com/1622359590/ai-wechat/internal/adminauth/postgres"
	"github.com/1622359590/ai-wechat/internal/adminhttp"
	"github.com/1622359590/ai-wechat/internal/deviceadmin"
	"github.com/1622359590/ai-wechat/internal/devices"
	devicepostgres "github.com/1622359590/ai-wechat/internal/devices/postgres"
	"github.com/1622359590/ai-wechat/internal/securefile"
)

type webConfig struct {
	address         string
	databaseDSNFile string
	pepperFile      string
	trustHTTPSProxy bool
	containerBind   bool
}

type runtimeOpener func(context.Context, webConfig) (http.Handler, func(), error)

func main() {
	if len(os.Args) == 2 && os.Args[1] == "healthcheck" {
		address := os.Getenv("ADMIN_HEALTHCHECK_URL")
		if address == "" {
			address = "http://127.0.0.1:18181/livez"
		}
		if err := runHealthcheck(address); err != nil {
			os.Exit(1)
		}
		return
	}
	signalContext, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := run(signalContext, os.Getenv, os.Stdout, openProductionRuntime); err != nil {
		log.Fatal(err)
	}
}

func loadConfig(getenv func(string) string) (webConfig, error) {
	result := webConfig{
		address:         getenv("ADMIN_HTTP_ADDRESS"),
		databaseDSNFile: getenv("ADMIN_DATABASE_DSN_FILE"),
		pepperFile:      getenv("ADMIN_DEVICE_PEPPER_FILE"),
	}
	if result.address == "" {
		result.address = "127.0.0.1:18181"
	}
	host, portText, err := net.SplitHostPort(result.address)
	port, portErr := strconv.ParseUint(portText, 10, 16)
	containerBind := getenv("ADMIN_CONTAINER_BIND") == "true"
	loopbackBind := false
	if address := net.ParseIP(host); address != nil {
		loopbackBind = address.IsLoopback()
	}
	if err != nil || portErr != nil || port == 0 || (!loopbackBind && !(host == "" && containerBind)) || result.databaseDSNFile == "" || result.pepperFile == "" {
		return webConfig{}, errors.New("administration configuration is invalid")
	}
	if getenv("ADMIN_TRUST_HTTPS_PROXY") != "true" {
		return webConfig{}, errors.New("trusted HTTPS proxy is required")
	}
	result.trustHTTPSProxy = true
	result.containerBind = containerBind
	return result, nil
}

func runHealthcheck(address string) error {
	client := &http.Client{
		Timeout: 2 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("healthcheck redirect rejected")
		},
	}
	request, err := http.NewRequest(http.MethodGet, address, nil)
	if err != nil {
		return errors.New("healthcheck configuration invalid")
	}
	response, err := client.Do(request)
	if err != nil {
		return errors.New("healthcheck failed")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return errors.New("healthcheck failed")
	}
	return nil
}

func run(ctx context.Context, getenv func(string) string, output io.Writer, open runtimeOpener) error {
	config, err := loadConfig(getenv)
	if err != nil || open == nil {
		return errors.New("administration startup failed")
	}
	handler, closeRuntime, err := open(ctx, config)
	if err != nil {
		return errors.New("administration startup failed")
	}
	defer closeRuntime()
	listener, err := net.Listen("tcp", config.address)
	if err != nil {
		return errors.New("administration startup failed")
	}
	if err := serve(ctx, listener, handler, output); err != nil {
		return errors.New("administration server failed")
	}
	return nil
}

func serve(ctx context.Context, listener net.Listener, handler http.Handler, output io.Writer) error {
	server := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 3 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 * 1024,
	}
	_, _ = fmt.Fprintf(output, "admin web listening on %s mode=trusted-https-proxy\n", listener.Addr().String())
	serveResult := make(chan error, 1)
	go func() {
		err := server.Serve(listener)
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		serveResult <- err
	}()
	select {
	case err := <-serveResult:
		return err
	case <-ctx.Done():
		shutdownContext, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownContext); err != nil {
			return errors.New("administration shutdown failed")
		}
		return <-serveResult
	}
}

func openProductionRuntime(ctx context.Context, config webConfig) (http.Handler, func(), error) {
	dsn, err := securefile.ReadText(config.databaseDSNFile, 16*1024)
	if err != nil {
		return nil, func() {}, errors.New("invalid database configuration")
	}
	pepper, err := securefile.ReadExact(config.pepperFile, 32)
	if err != nil {
		return nil, func() {}, errors.New("invalid fingerprint configuration")
	}
	fingerprinter, err := devices.NewFingerprinter(pepper)
	clear(pepper)
	if err != nil {
		return nil, func() {}, errors.New("invalid fingerprint configuration")
	}
	pool, err := devicepostgres.Open(ctx, dsn)
	if err != nil {
		return nil, func() {}, errors.New("database unavailable")
	}
	if err := devicepostgres.Migrate(ctx, pool); err != nil {
		pool.Close()
		return nil, func() {}, errors.New("database migration failed")
	}
	hasher, err := adminauth.NewPasswordHasher(adminauth.ProductionPasswordParams, rand.Reader)
	if err != nil {
		pool.Close()
		return nil, func() {}, errors.New("authentication unavailable")
	}
	limiter, err := adminauth.NewLoginLimiter(rand.Reader)
	if err != nil {
		pool.Close()
		return nil, func() {}, errors.New("authentication unavailable")
	}
	authService, err := adminauth.NewService(adminpostgres.NewRepository(pool), hasher, limiter, nil, rand.Reader)
	if err != nil {
		pool.Close()
		return nil, func() {}, errors.New("authentication unavailable")
	}
	deviceService, err := deviceadmin.New(devicepostgres.NewRepository(pool), fingerprinter, nil)
	if err != nil {
		pool.Close()
		return nil, func() {}, errors.New("device administration unavailable")
	}
	handler, err := adminhttp.New(adminhttp.Config{
		Auth: authService, Devices: deviceService, Ready: pool.Ping, Random: rand.Reader,
		TrustProxy: config.containerBind,
	})
	if err != nil {
		pool.Close()
		return nil, func() {}, errors.New("HTTP administration unavailable")
	}
	return handler, pool.Close, nil
}
