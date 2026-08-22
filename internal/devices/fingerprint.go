package devices

import (
	"crypto/hmac"
	"crypto/sha256"
	"errors"
)

var errInvalidPepper = errors.New("device fingerprint pepper must be exactly 32 bytes")

type Fingerprint [sha256.Size]byte

type Fingerprinter struct {
	pepper [sha256.Size]byte
}

func NewFingerprinter(pepper []byte) (*Fingerprinter, error) {
	if len(pepper) != sha256.Size {
		return nil, errInvalidPepper
	}

	fingerprinter := &Fingerprinter{}
	copy(fingerprinter.pepper[:], pepper)
	return fingerprinter, nil
}

func (fingerprinter *Fingerprinter) Sum(credential string) Fingerprint {
	digest := hmac.New(sha256.New, fingerprinter.pepper[:])
	_, _ = digest.Write([]byte(credential))

	var fingerprint Fingerprint
	copy(fingerprint[:], digest.Sum(nil))
	return fingerprint
}

func (fingerprint Fingerprint) Bytes() []byte {
	result := make([]byte, len(fingerprint))
	copy(result, fingerprint[:])
	return result
}
