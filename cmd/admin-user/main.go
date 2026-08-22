package main

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/1622359590/ai-wechat/internal/adminauth"
	adminpostgres "github.com/1622359590/ai-wechat/internal/adminauth/postgres"
	devicepostgres "github.com/1622359590/ai-wechat/internal/devices/postgres"
	"github.com/1622359590/ai-wechat/internal/securefile"
	"golang.org/x/term"
)

type userOperations interface {
	Create(context.Context, string, []byte) (adminauth.User, error)
	Reset(context.Context, string, []byte) error
}

type userOpener func(context.Context, string) (userOperations, func(), error)
type passwordSource func() ([]byte, []byte, error)

type productionUserOperations struct {
	repository *adminpostgres.Repository
	hasher     *adminauth.PasswordHasher
}

func main() {
	os.Exit(run(context.Background(), os.Args[1:], os.Stdout, os.Stderr, openProductionUserOperations,
		func() ([]byte, []byte, error) { return readTerminalPasswords(os.Stdin, os.Stderr) }))
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer, open userOpener, readPasswords passwordSource) int {
	if len(args) == 0 || (args[0] != "create" && args[0] != "reset-password") {
		_, _ = io.WriteString(stderr, "invalid arguments\n")
		return 2
	}
	command := args[0]
	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	databaseDSNFile := flags.String("database-dsn-file", "", "")
	username := flags.String("username", "", "")
	if err := flags.Parse(args[1:]); err != nil || flags.NArg() != 0 || *databaseDSNFile == "" || *username == "" || open == nil || readPasswords == nil {
		_, _ = io.WriteString(stderr, "invalid arguments\n")
		return 2
	}
	if _, err := adminauth.NormalizeUsername(*username); err != nil {
		_, _ = io.WriteString(stderr, "invalid arguments\n")
		return 2
	}
	password, confirmation, err := readPasswords()
	if err != nil || len(password) < 12 || len(password) > 128 || len(password) != len(confirmation) || subtle.ConstantTimeCompare(password, confirmation) != 1 {
		clear(password)
		clear(confirmation)
		_, _ = io.WriteString(stderr, "invalid password input\n")
		return 2
	}
	clear(confirmation)
	defer clear(password)

	operations, closeOperations, err := open(ctx, *databaseDSNFile)
	if err != nil {
		_, _ = io.WriteString(stderr, "configuration failed\n")
		return 1
	}
	defer closeOperations()
	if command == "create" {
		user, err := operations.Create(ctx, *username, password)
		if err == nil {
			_, _ = fmt.Fprintf(stdout, "administrator created id=%s\n", user.ID)
			return 0
		}
	} else if err := operations.Reset(ctx, *username, password); err == nil {
		_, _ = io.WriteString(stdout, "administrator password reset\n")
		return 0
	}
	_, _ = io.WriteString(stderr, "operation failed\n")
	return 1
}

func readTerminalPasswords(input *os.File, prompt io.Writer) ([]byte, []byte, error) {
	if input == nil || !term.IsTerminal(int(input.Fd())) {
		return nil, nil, errors.New("password input requires a terminal")
	}
	_, _ = io.WriteString(prompt, "Password: ")
	password, err := term.ReadPassword(int(input.Fd()))
	_, _ = io.WriteString(prompt, "\nRepeat password: ")
	if err != nil {
		clear(password)
		return nil, nil, errors.New("password input failed")
	}
	confirmation, confirmationErr := term.ReadPassword(int(input.Fd()))
	_, _ = io.WriteString(prompt, "\n")
	if confirmationErr != nil {
		clear(password)
		clear(confirmation)
		return nil, nil, errors.New("password input failed")
	}
	return password, confirmation, nil
}

func openProductionUserOperations(ctx context.Context, databaseDSNFile string) (userOperations, func(), error) {
	dsn, err := securefile.ReadText(databaseDSNFile, 16*1024)
	if err != nil {
		return nil, func() {}, errors.New("invalid database configuration")
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
		return nil, func() {}, errors.New("password service unavailable")
	}
	return &productionUserOperations{repository: adminpostgres.NewRepository(pool), hasher: hasher}, pool.Close, nil
}

func (operations *productionUserOperations) Create(ctx context.Context, username string, password []byte) (adminauth.User, error) {
	defer clear(password)
	normalized, err := adminauth.NormalizeUsername(username)
	if err != nil {
		return adminauth.User{}, err
	}
	passwordHash, err := operations.hasher.Hash(password)
	if err != nil {
		return adminauth.User{}, err
	}
	return operations.repository.CreateUser(ctx, username, normalized, passwordHash, time.Now().UTC())
}

func (operations *productionUserOperations) Reset(ctx context.Context, username string, password []byte) error {
	defer clear(password)
	normalized, err := adminauth.NormalizeUsername(username)
	if err != nil {
		return err
	}
	passwordHash, err := operations.hasher.Hash(password)
	if err != nil {
		return err
	}
	return operations.repository.ResetPassword(ctx, normalized, passwordHash, time.Now().UTC())
}
