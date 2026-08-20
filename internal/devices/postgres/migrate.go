package postgres

import (
	"context"
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/1622359590/ai-wechat/internal/devices/postgres/migrations"
	"github.com/jackc/pgx/v5/pgxpool"
)

const migrationAdvisoryLock int64 = 0x6169776563686174

type migration struct {
	version int64
	sql     string
}

func Open(ctx context.Context, dsn string) (*pgxpool.Pool, error) {
	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("parse device registry configuration: %w", err)
	}
	config.MaxConns = 10
	config.MinConns = 1
	config.MaxConnIdleTime = 5 * time.Minute
	config.MaxConnLifetime = time.Hour

	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		return nil, fmt.Errorf("open device registry: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("connect to device registry: %w", err)
	}
	return pool, nil
}

func Migrate(ctx context.Context, pool *pgxpool.Pool) error {
	return migrate(ctx, pool, migrations.Files)
}

func migrate(ctx context.Context, pool *pgxpool.Pool, migrationFS fs.FS) error {
	migrationsToApply, err := readMigrations(migrationFS)
	if err != nil {
		return err
	}
	if len(migrationsToApply) == 0 {
		return fmt.Errorf("load device registry migrations: no migrations found")
	}

	tx, err := pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin device registry migration: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock($1)", migrationAdvisoryLock); err != nil {
		return fmt.Errorf("lock device registry migrations: %w", err)
	}
	if _, err := tx.Exec(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		version bigint PRIMARY KEY,
		applied_at timestamptz NOT NULL DEFAULT now()
	)`); err != nil {
		return fmt.Errorf("create device registry migration table: %w", err)
	}

	latestBinaryVersion := migrationsToApply[len(migrationsToApply)-1].version
	var latestDatabaseVersion int64
	if err := tx.QueryRow(ctx, "SELECT COALESCE(max(version), 0) FROM schema_migrations").Scan(&latestDatabaseVersion); err != nil {
		return fmt.Errorf("read device registry migration version: %w", err)
	}
	if latestDatabaseVersion > latestBinaryVersion {
		return fmt.Errorf("device registry schema is newer than this binary")
	}

	for _, item := range migrationsToApply {
		var applied bool
		if err := tx.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM schema_migrations WHERE version = $1)", item.version).Scan(&applied); err != nil {
			return fmt.Errorf("check device registry migration %d: %w", item.version, err)
		}
		if applied {
			continue
		}
		if _, err := tx.Exec(ctx, item.sql); err != nil {
			return fmt.Errorf("apply device registry migration %d: %w", item.version, err)
		}
		if _, err := tx.Exec(ctx, "INSERT INTO schema_migrations (version) VALUES ($1)", item.version); err != nil {
			return fmt.Errorf("record device registry migration %d: %w", item.version, err)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit device registry migrations: %w", err)
	}
	return nil
}

func readMigrations(migrationFS fs.FS) ([]migration, error) {
	entries, err := fs.ReadDir(migrationFS, "migrations")
	if err != nil {
		entries, err = fs.ReadDir(migrationFS, ".")
		if err != nil {
			return nil, fmt.Errorf("read device registry migrations: %w", err)
		}
	}

	result := make([]migration, 0, len(entries))
	versions := make(map[int64]struct{}, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".sql") {
			continue
		}
		separator := strings.IndexByte(entry.Name(), '_')
		if separator <= 0 {
			return nil, fmt.Errorf("invalid device registry migration filename")
		}
		version, err := strconv.ParseInt(entry.Name()[:separator], 10, 64)
		if err != nil || version <= 0 {
			return nil, fmt.Errorf("invalid device registry migration version")
		}
		if _, exists := versions[version]; exists {
			return nil, fmt.Errorf("duplicate device registry migration version")
		}
		versions[version] = struct{}{}

		filename := entry.Name()
		if _, err := fs.Stat(migrationFS, "migrations/"+filename); err == nil {
			filename = path.Join("migrations", filename)
		}
		contents, err := fs.ReadFile(migrationFS, filename)
		if err != nil {
			return nil, fmt.Errorf("read device registry migration: %w", err)
		}
		result = append(result, migration{version: version, sql: string(contents)})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].version < result[j].version })
	return result, nil
}
