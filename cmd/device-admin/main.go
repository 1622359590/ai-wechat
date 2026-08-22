package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/1622359590/ai-wechat/internal/deviceadmin"
	"github.com/1622359590/ai-wechat/internal/devices"
	devicepostgres "github.com/1622359590/ai-wechat/internal/devices/postgres"
	"github.com/1622359590/ai-wechat/internal/securefile"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/term"
)

type adminOperations interface {
	Migrate(context.Context) error
	Add(context.Context, string, string, devices.Status, string) (devices.Device, error)
	List(context.Context) ([]devices.Device, error)
	Enable(context.Context, devices.ID) error
	Disable(context.Context, devices.ID) error
	SetExpiry(context.Context, devices.ID, string) error
}

type adminOpener func(context.Context, string, string) (adminOperations, func(), error)

type productionAdmin struct {
	service *deviceadmin.Service
	pool    *pgxpool.Pool
}

func main() {
	os.Exit(run(context.Background(), os.Args[1:], os.Stdin, os.Stdout, os.Stderr, openProductionAdmin))
}

func run(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer, open adminOpener) int {
	if len(args) == 0 || !validCommand(args[0]) {
		_, _ = io.WriteString(stderr, "invalid command\n")
		return 2
	}
	command := args[0]
	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	databaseDSNFile := flags.String("database-dsn-file", "", "")
	pepperFile := flags.String("pepper-file", "", "")
	label := flags.String("label", "", "")
	status := flags.String("status", string(devices.StatusActive), "")
	expiry := flags.String("expiry", "never", "")
	deviceID := flags.String("id", "", "")
	if err := flags.Parse(args[1:]); err != nil || flags.NArg() != 0 || *databaseDSNFile == "" || *pepperFile == "" || !validCommandFlags(command, *deviceID) {
		_, _ = io.WriteString(stderr, "invalid arguments\n")
		return 2
	}

	operations, closeRuntime, err := open(ctx, *databaseDSNFile, *pepperFile)
	if err != nil {
		_, _ = io.WriteString(stderr, "configuration failed\n")
		return 1
	}
	defer closeRuntime()

	switch command {
	case "migrate":
		err = operations.Migrate(ctx)
		if err == nil {
			_, _ = io.WriteString(stdout, "migration complete\n")
		}
	case "add":
		var credential string
		credential, err = readCredential(stdin, stderr)
		if err != nil {
			_, _ = io.WriteString(stderr, "invalid credential input\n")
			return 2
		}
		var device devices.Device
		device, err = operations.Add(ctx, credential, *label, devices.Status(*status), *expiry)
		if err == nil {
			_, _ = fmt.Fprintf(stdout, "device added id=%s\n", device.ID)
		}
	case "list":
		var listed []devices.Device
		listed, err = operations.List(ctx)
		if err == nil {
			_, _ = io.WriteString(stdout, "id\tlabel\tstatus\texpires_at\tlast_authenticated_at\n")
			for _, device := range listed {
				_, _ = fmt.Fprintf(stdout, "%s\t%s\t%s\t%s\t%s\n", device.ID, strconv.Quote(device.Label), device.Status, formatTime(device.AuthExpiresAt), formatTime(device.LastAuthenticatedAt))
			}
		}
	case "enable":
		err = operations.Enable(ctx, devices.ID(*deviceID))
	case "disable":
		err = operations.Disable(ctx, devices.ID(*deviceID))
	case "set-expiry":
		err = operations.SetExpiry(ctx, devices.ID(*deviceID), *expiry)
	}
	if err != nil {
		_, _ = io.WriteString(stderr, "operation failed\n")
		return 1
	}
	return 0
}

func validCommand(command string) bool {
	switch command {
	case "migrate", "add", "list", "enable", "disable", "set-expiry":
		return true
	default:
		return false
	}
}

func validCommandFlags(command, deviceID string) bool {
	switch command {
	case "enable", "disable", "set-expiry":
		return deviceID != ""
	default:
		return deviceID == ""
	}
}

func readCredential(stdin io.Reader, stderr io.Writer) (string, error) {
	if file, ok := stdin.(*os.File); ok && term.IsTerminal(int(file.Fd())) {
		_, _ = io.WriteString(stderr, "Credential: ")
		contents, err := term.ReadPassword(int(file.Fd()))
		_, _ = io.WriteString(stderr, "\n")
		if err != nil || len(contents) == 0 || len(contents) > 4096 || !utf8.Valid(contents) {
			return "", errors.New("invalid credential input")
		}
		return string(contents), nil
	}
	contents, err := io.ReadAll(io.LimitReader(stdin, 4098))
	if err != nil || len(contents) < 2 || len(contents) > 4097 || contents[len(contents)-1] != '\n' || bytesCount(contents, '\n') != 1 || bytesCount(contents, '\r') != 0 {
		return "", errors.New("invalid credential input")
	}
	credential := string(contents[:len(contents)-1])
	if credential == "" || !utf8.ValidString(credential) {
		return "", errors.New("invalid credential input")
	}
	return credential, nil
}

func bytesCount(contents []byte, target byte) int {
	return strings.Count(string(contents), string([]byte{target}))
}

func formatTime(value *time.Time) string {
	if value == nil {
		return "never"
	}
	return value.UTC().Format(time.RFC3339)
}

func openProductionAdmin(ctx context.Context, databaseDSNFile, pepperFile string) (adminOperations, func(), error) {
	dsn, err := securefile.ReadText(databaseDSNFile, 16*1024)
	if err != nil {
		return nil, func() {}, errors.New("invalid database configuration")
	}
	pepper, err := securefile.ReadExact(pepperFile, 32)
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
	service, err := deviceadmin.New(devicepostgres.NewRepository(pool), fingerprinter, nil)
	if err != nil {
		pool.Close()
		return nil, func() {}, errors.New("administration unavailable")
	}
	runtime := &productionAdmin{service: service, pool: pool}
	return runtime, pool.Close, nil
}

func (admin *productionAdmin) Migrate(ctx context.Context) error {
	return devicepostgres.Migrate(ctx, admin.pool)
}
func (admin *productionAdmin) Add(ctx context.Context, credential, label string, status devices.Status, expiry string) (devices.Device, error) {
	return admin.service.Add(ctx, credential, label, status, expiry)
}
func (admin *productionAdmin) List(ctx context.Context) ([]devices.Device, error) {
	return admin.service.List(ctx)
}
func (admin *productionAdmin) Enable(ctx context.Context, id devices.ID) error {
	return admin.service.Enable(ctx, id)
}
func (admin *productionAdmin) Disable(ctx context.Context, id devices.ID) error {
	return admin.service.Disable(ctx, id)
}
func (admin *productionAdmin) SetExpiry(ctx context.Context, id devices.ID, expiry string) error {
	return admin.service.SetExpiry(ctx, id, expiry)
}
