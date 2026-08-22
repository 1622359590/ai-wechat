package devices

import "time"

type ID string

type Status string

const (
	StatusActive   Status = "active"
	StatusDisabled Status = "disabled"

	DefaultTenantID = "00000000-0000-0000-0000-000000000001"
)

type Device struct {
	ID                  ID
	TenantID            string
	Label               string
	Status              Status
	AuthExpiresAt       *time.Time
	LastAuthenticatedAt *time.Time
}

type AdminActor struct {
	Type        string
	AdminUserID string
}

type AdminEvent struct {
	ID          int64
	DeviceID    ID
	Action      string
	ActorType   string
	AdminUserID string
	ReasonCode  string
	CreatedAt   time.Time
}
