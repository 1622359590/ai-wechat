package adminauth

import (
	"errors"
	"strings"
	"time"
)

type ID string

type Status string

const (
	StatusActive   Status = "active"
	StatusDisabled Status = "disabled"
)

var (
	ErrInvalidInput = errors.New("administrator input is invalid")
	ErrInvalidHash  = errors.New("administrator password hash is invalid")
)

type User struct {
	ID              ID
	Username        string
	Status          Status
	PasswordVersion int64
	LastLoginAt     *time.Time
}

func NormalizeUsername(value string) (string, error) {
	if len(value) < 3 || len(value) > 64 {
		return "", ErrInvalidInput
	}
	for index := 0; index < len(value); index++ {
		character := value[index]
		if (character >= 'a' && character <= 'z') ||
			(character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') ||
			character == '.' || character == '_' || character == '-' {
			continue
		}
		return "", ErrInvalidInput
	}
	return strings.ToLower(value), nil
}
