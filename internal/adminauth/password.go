package adminauth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"io"
	"strings"

	"golang.org/x/crypto/argon2"
)

const (
	minimumPasswordBytes = 12
	maximumPasswordBytes = 128
	minimumMemoryKiB     = 64
	maximumMemoryKiB     = 1024 * 1024
	maximumIterations    = 10
	maximumParallelism   = 16
)

var ProductionPasswordParams = PasswordParams{
	MemoryKiB:   64 * 1024,
	Iterations:  3,
	Parallelism: 2,
	SaltBytes:   16,
	KeyBytes:    32,
}

type PasswordParams struct {
	MemoryKiB   uint32
	Iterations  uint32
	Parallelism uint8
	SaltBytes   uint32
	KeyBytes    uint32
}

type PasswordHasher struct {
	params PasswordParams
	random io.Reader
}

func NewPasswordHasher(params PasswordParams, random io.Reader) (*PasswordHasher, error) {
	if !validParams(params) {
		return nil, ErrInvalidInput
	}
	if random == nil {
		random = rand.Reader
	}
	return &PasswordHasher{params: params, random: random}, nil
}

func (hasher *PasswordHasher) Hash(password []byte) (string, error) {
	if hasher == nil || !validPassword(password) {
		return "", ErrInvalidInput
	}
	salt := make([]byte, hasher.params.SaltBytes)
	if _, err := io.ReadFull(hasher.random, salt); err != nil {
		return "", errorsWithoutDetails("generate password salt")
	}
	key := argon2.IDKey(password, salt, hasher.params.Iterations, hasher.params.MemoryKiB, hasher.params.Parallelism, hasher.params.KeyBytes)
	encoded := fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version,
		hasher.params.MemoryKiB,
		hasher.params.Iterations,
		hasher.params.Parallelism,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key),
	)
	clear(key)
	clear(salt)
	return encoded, nil
}

func (hasher *PasswordHasher) Verify(encoded string, password []byte) (bool, error) {
	if hasher == nil || !validPassword(password) {
		return false, ErrInvalidInput
	}
	params, salt, expected, err := parseHash(encoded)
	if err != nil {
		return false, err
	}
	actual := argon2.IDKey(password, salt, params.Iterations, params.MemoryKiB, params.Parallelism, params.KeyBytes)
	verified := subtle.ConstantTimeCompare(actual, expected) == 1
	clear(actual)
	clear(expected)
	clear(salt)
	return verified, nil
}

func parseHash(encoded string) (PasswordParams, []byte, []byte, error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" || parts[2] != fmt.Sprintf("v=%d", argon2.Version) {
		return PasswordParams{}, nil, nil, ErrInvalidHash
	}
	var memory, iterations uint32
	var parallelism uint8
	if count, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &iterations, &parallelism); err != nil || count != 3 {
		return PasswordParams{}, nil, nil, ErrInvalidHash
	}
	salt, err := base64.RawStdEncoding.Strict().DecodeString(parts[4])
	if err != nil {
		return PasswordParams{}, nil, nil, ErrInvalidHash
	}
	key, err := base64.RawStdEncoding.Strict().DecodeString(parts[5])
	if err != nil {
		clear(salt)
		return PasswordParams{}, nil, nil, ErrInvalidHash
	}
	params := PasswordParams{
		MemoryKiB:   memory,
		Iterations:  iterations,
		Parallelism: parallelism,
		SaltBytes:   uint32(len(salt)),
		KeyBytes:    uint32(len(key)),
	}
	if !validParams(params) {
		clear(salt)
		clear(key)
		return PasswordParams{}, nil, nil, ErrInvalidHash
	}
	return params, salt, key, nil
}

func validParams(params PasswordParams) bool {
	return params.MemoryKiB >= minimumMemoryKiB && params.MemoryKiB <= maximumMemoryKiB &&
		params.Iterations >= 1 && params.Iterations <= maximumIterations &&
		params.Parallelism >= 1 && params.Parallelism <= maximumParallelism &&
		params.SaltBytes == 16 && params.KeyBytes == 32
}

func validPassword(password []byte) bool {
	return len(password) >= minimumPasswordBytes && len(password) <= maximumPasswordBytes
}

func errorsWithoutDetails(operation string) error {
	return fmt.Errorf("%s failed", operation)
}
