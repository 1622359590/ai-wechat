package legacyimport

import (
	"context"
	"database/sql"
	"errors"
	"time"
	"unicode/utf8"

	"github.com/1622359590/ai-wechat/internal/devices"
)

var (
	ErrInvalidSource     = errors.New("legacy authorization source is invalid")
	ErrSourceUnavailable = errors.New("legacy authorization source is unavailable")
	ErrTargetUnavailable = errors.New("device registry import target is unavailable")
)

type Record struct {
	Fingerprint   devices.Fingerprint
	Status        devices.Status
	AuthExpiresAt *time.Time
}

type Summary struct {
	Total      int
	Imported   int
	Duplicates int
	Rejected   int
	DryRun     bool
}

type Target interface {
	Import(context.Context, []Record, time.Time) (Summary, error)
	Preview(context.Context, []Record) (Summary, error)
}

type Queryer interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}

func Execute(ctx context.Context, source Queryer, query string, fingerprinter *devices.Fingerprinter, target Target, dryRun bool, now time.Time) (Summary, error) {
	summary := Summary{DryRun: dryRun}
	if err := ctx.Err(); err != nil {
		return summary, err
	}
	if source == nil || query == "" || fingerprinter == nil || target == nil {
		return summary, ErrInvalidSource
	}
	rows, err := source.QueryContext(ctx, query)
	if err != nil {
		return summary, sourceError(ctx)
	}
	defer rows.Close()
	columns, err := rows.Columns()
	if err != nil {
		return summary, sourceError(ctx)
	}
	wantColumns := []string{"credential", "status", "auth_expires_at"}
	if len(columns) != len(wantColumns) {
		return summary, ErrInvalidSource
	}
	for index := range wantColumns {
		if columns[index] != wantColumns[index] {
			return summary, ErrInvalidSource
		}
	}

	records := make([]Record, 0)
	for rows.Next() {
		summary.Total++
		var credential []byte
		var statusText string
		var expiryValue any
		if err := rows.Scan(&credential, &statusText, &expiryValue); err != nil {
			summary.Rejected++
			continue
		}
		validCredential := len(credential) > 0 && len(credential) <= 4096 && utf8.Valid(credential)
		fingerprint := fingerprinter.Sum(string(credential))
		clear(credential)
		status := devices.Status(statusText)
		validStatus := status == devices.StatusActive || status == devices.StatusDisabled
		expiresAt, validExpiry := importExpiry(expiryValue)
		if !validCredential || !validStatus || !validExpiry {
			summary.Rejected++
			continue
		}
		records = append(records, Record{Fingerprint: fingerprint, Status: status, AuthExpiresAt: expiresAt})
	}
	if err := rows.Err(); err != nil {
		return summary, sourceError(ctx)
	}
	if summary.Rejected != 0 {
		return summary, ErrInvalidSource
	}

	var targetSummary Summary
	if dryRun {
		targetSummary, err = target.Preview(ctx, records)
	} else {
		targetSummary, err = target.Import(ctx, records, now)
	}
	if err != nil {
		if ctx.Err() != nil {
			return summary, ctx.Err()
		}
		return summary, ErrTargetUnavailable
	}
	summary.Imported = targetSummary.Imported
	summary.Duplicates = targetSummary.Duplicates
	return summary, nil
}

func importExpiry(value any) (*time.Time, bool) {
	switch typed := value.(type) {
	case nil:
		return nil, true
	case time.Time:
		return &typed, true
	default:
		return nil, false
	}
}

func sourceError(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return ErrSourceUnavailable
}
