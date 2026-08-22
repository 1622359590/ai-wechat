package postgrestarget

import (
	"context"
	"time"

	devicepostgres "github.com/1622359590/ai-wechat/internal/devices/postgres"
	"github.com/1622359590/ai-wechat/internal/legacyimport"
)

type Target struct {
	repository *devicepostgres.Repository
}

func New(repository *devicepostgres.Repository) *Target {
	return &Target{repository: repository}
}

func (target *Target) Import(ctx context.Context, records []legacyimport.Record, now time.Time) (legacyimport.Summary, error) {
	summary, err := target.repository.ImportDevices(ctx, convert(records), now)
	return legacyimport.Summary{Total: summary.Total, Imported: summary.Imported, Duplicates: summary.Duplicates}, err
}

func (target *Target) Preview(ctx context.Context, records []legacyimport.Record) (legacyimport.Summary, error) {
	summary, err := target.repository.PreviewImport(ctx, convert(records))
	return legacyimport.Summary{Total: summary.Total, Imported: summary.Imported, Duplicates: summary.Duplicates}, err
}

func convert(records []legacyimport.Record) []devicepostgres.ImportRecord {
	result := make([]devicepostgres.ImportRecord, len(records))
	for index, record := range records {
		result[index] = devicepostgres.ImportRecord{
			Fingerprint:   record.Fingerprint,
			Status:        record.Status,
			AuthExpiresAt: record.AuthExpiresAt,
		}
	}
	return result
}
