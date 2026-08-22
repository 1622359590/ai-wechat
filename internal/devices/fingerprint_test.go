package devices

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"strconv"
	"testing"
)

func TestNewFingerprinterRequiresExactly32PepperBytes(t *testing.T) {
	t.Parallel()

	for _, size := range []int{0, 31, 33} {
		size := size
		t.Run(strconv.Itoa(size), func(t *testing.T) {
			t.Parallel()

			if _, err := NewFingerprinter(make([]byte, size)); err == nil {
				t.Fatalf("NewFingerprinter() accepted %d-byte pepper", size)
			}
		})
	}

	if _, err := NewFingerprinter(make([]byte, sha256.Size)); err != nil {
		t.Fatalf("NewFingerprinter() rejected 32-byte pepper: %v", err)
	}
}

func TestFingerprinterUsesHMACSHA256OverExactCredentialBytes(t *testing.T) {
	t.Parallel()

	pepper := bytes.Repeat([]byte{0x3a}, sha256.Size)
	fingerprinter, err := NewFingerprinter(pepper)
	if err != nil {
		t.Fatalf("NewFingerprinter(): %v", err)
	}

	credential := " synthetic-device-A\n"
	wantMAC := hmac.New(sha256.New, pepper)
	_, _ = wantMAC.Write([]byte(credential))

	got := fingerprinter.Sum(credential).Bytes()
	if !bytes.Equal(got, wantMAC.Sum(nil)) {
		t.Fatalf("Sum() = %x, want %x", got, wantMAC.Sum(nil))
	}
	if bytes.Equal(got, fingerprinter.Sum("synthetic-device-A\n").Bytes()) {
		t.Fatal("Sum() ignored the credential's leading space")
	}
	if bytes.Equal(got, fingerprinter.Sum(" synthetic-device-a\n").Bytes()) {
		t.Fatal("Sum() ignored the credential's exact case")
	}
}

func TestFingerprinterCopiesPepperInput(t *testing.T) {
	t.Parallel()

	pepper := bytes.Repeat([]byte{0x61}, sha256.Size)
	original := append([]byte(nil), pepper...)
	fingerprinter, err := NewFingerprinter(pepper)
	if err != nil {
		t.Fatalf("NewFingerprinter(): %v", err)
	}

	pepper[0] = 0x62
	wantMAC := hmac.New(sha256.New, original)
	_, _ = wantMAC.Write([]byte("synthetic-device-B"))

	got := fingerprinter.Sum("synthetic-device-B").Bytes()
	if !bytes.Equal(got, wantMAC.Sum(nil)) {
		t.Fatalf("Sum() changed after caller mutated pepper: got %x, want %x", got, wantMAC.Sum(nil))
	}
}
