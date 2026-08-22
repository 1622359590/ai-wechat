package main

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/1622359590/ai-wechat/internal/devices"
	devicepostgres "github.com/1622359590/ai-wechat/internal/devices/postgres"
	"github.com/1622359590/ai-wechat/internal/legacyimport"
	"github.com/1622359590/ai-wechat/internal/legacyimport/postgrestarget"
	"github.com/1622359590/ai-wechat/internal/securefile"
	"github.com/go-sql-driver/mysql"
	"github.com/jackc/pgx/v5/pgxpool"
)

type importConfig struct {
	legacyDSNFile   string
	databaseDSNFile string
	pepperFile      string
	queryFile       string
	dryRun          bool
}

type importExecutor func(context.Context, importConfig) (legacyimport.Summary, error)

func main() {
	os.Exit(run(context.Background(), os.Args[1:], os.Stdout, os.Stderr, executeProduction))
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer, execute importExecutor) int {
	flags := flag.NewFlagSet("device-import", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	config := importConfig{}
	flags.StringVar(&config.legacyDSNFile, "legacy-dsn-file", "", "")
	flags.StringVar(&config.databaseDSNFile, "database-dsn-file", "", "")
	flags.StringVar(&config.pepperFile, "pepper-file", "", "")
	flags.StringVar(&config.queryFile, "query-file", "", "")
	flags.BoolVar(&config.dryRun, "dry-run", false, "")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 ||
		config.legacyDSNFile == "" || config.databaseDSNFile == "" || config.pepperFile == "" || config.queryFile == "" {
		_, _ = io.WriteString(stderr, "invalid arguments\n")
		return 2
	}

	summary, err := execute(ctx, config)
	_, _ = fmt.Fprintf(stdout, "total=%d imported=%d duplicates=%d rejected=%d dry_run=%t\n",
		summary.Total, summary.Imported, summary.Duplicates, summary.Rejected, summary.DryRun)
	if err != nil {
		_, _ = io.WriteString(stderr, "import failed\n")
		return 1
	}
	return 0
}

func executeProduction(ctx context.Context, config importConfig) (legacyimport.Summary, error) {
	summary := legacyimport.Summary{DryRun: config.dryRun}
	legacyDSN, err := securefile.ReadText(config.legacyDSNFile, 16*1024)
	if err != nil {
		return summary, errors.New("legacy database configuration is invalid")
	}
	databaseDSN, err := securefile.ReadText(config.databaseDSNFile, 16*1024)
	if err != nil {
		return summary, errors.New("device database configuration is invalid")
	}
	pepper, err := securefile.ReadExact(config.pepperFile, 32)
	if err != nil {
		return summary, errors.New("fingerprint configuration is invalid")
	}
	queryBytes, err := securefile.ReadBytes(config.queryFile, 64*1024)
	if err != nil || !utf8.Valid(queryBytes) || bytes.IndexByte(queryBytes, 0) >= 0 || strings.TrimSpace(string(queryBytes)) == "" {
		clear(pepper)
		clear(queryBytes)
		return summary, errors.New("legacy query configuration is invalid")
	}
	query := string(queryBytes)
	clear(queryBytes)
	fingerprinter, err := devices.NewFingerprinter(pepper)
	clear(pepper)
	if err != nil {
		return summary, errors.New("fingerprint configuration is invalid")
	}

	mysqlDSN, err := hardenedMySQLDSN(legacyDSN)
	if err != nil {
		return summary, errors.New("legacy database configuration is invalid")
	}
	source, err := sql.Open("mysql", mysqlDSN)
	if err != nil {
		return summary, errors.New("legacy database is unavailable")
	}
	defer source.Close()
	source.SetMaxOpenConns(1)
	source.SetMaxIdleConns(1)

	transaction, err := source.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return summary, sourceFailure(ctx)
	}
	defer transaction.Rollback()
	target := &lazyImportTarget{dsn: databaseDSN}
	defer target.Close()
	committingTarget := &sourceCommitTarget{transaction: transaction, target: target}
	summary, err = legacyimport.Execute(ctx, transaction, query, fingerprinter, committingTarget, config.dryRun, time.Now())
	if err != nil {
		return summary, errors.New("legacy import failed")
	}
	return summary, nil
}

func hardenedMySQLDSN(raw string) (string, error) {
	config, err := mysql.ParseDSN(raw)
	if err != nil {
		return "", err
	}
	config.Timeout = 5 * time.Second
	config.ReadTimeout = 10 * time.Second
	config.WriteTimeout = 10 * time.Second
	config.ParseTime = true
	return config.FormatDSN(), nil
}

type lazyImportTarget struct {
	dsn    string
	pool   *pgxpool.Pool
	target *postgrestarget.Target
}

func (target *lazyImportTarget) open(ctx context.Context) error {
	if target.target != nil {
		return nil
	}
	pool, err := devicepostgres.Open(ctx, target.dsn)
	if err != nil {
		return err
	}
	target.pool = pool
	target.target = postgrestarget.New(devicepostgres.NewRepository(pool))
	return nil
}

func (target *lazyImportTarget) Import(ctx context.Context, records []legacyimport.Record, now time.Time) (legacyimport.Summary, error) {
	if err := target.open(ctx); err != nil {
		return legacyimport.Summary{}, err
	}
	return target.target.Import(ctx, records, now)
}

func (target *lazyImportTarget) Preview(ctx context.Context, records []legacyimport.Record) (legacyimport.Summary, error) {
	if err := target.open(ctx); err != nil {
		return legacyimport.Summary{}, err
	}
	return target.target.Preview(ctx, records)
}

func (target *lazyImportTarget) Close() {
	if target.pool != nil {
		target.pool.Close()
	}
}

type sourceCommitTarget struct {
	transaction *sql.Tx
	target      legacyimport.Target
	committed   bool
}

func (target *sourceCommitTarget) Import(ctx context.Context, records []legacyimport.Record, now time.Time) (legacyimport.Summary, error) {
	if err := target.commit(); err != nil {
		return legacyimport.Summary{}, err
	}
	return target.target.Import(ctx, records, now)
}

func (target *sourceCommitTarget) Preview(ctx context.Context, records []legacyimport.Record) (legacyimport.Summary, error) {
	if err := target.commit(); err != nil {
		return legacyimport.Summary{}, err
	}
	return target.target.Preview(ctx, records)
}

func (target *sourceCommitTarget) commit() error {
	if target.committed {
		return nil
	}
	if err := target.transaction.Commit(); err != nil {
		return err
	}
	target.committed = true
	return nil
}

func sourceFailure(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return errors.New("legacy database is unavailable")
}
