package adminauth

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestNormalizeUsername(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name  string
		input string
		want  string
	}{
		{name: "lowercase", input: "Admin_01", want: "admin_01"},
		{name: "minimum", input: "A-1", want: "a-1"},
		{name: "maximum", input: strings.Repeat("Z", 64), want: strings.Repeat("z", 64)},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := NormalizeUsername(test.input)
			if err != nil {
				t.Fatalf("NormalizeUsername(%q): %v", test.input, err)
			}
			if got != test.want {
				t.Fatalf("NormalizeUsername(%q) = %q, want %q", test.input, got, test.want)
			}
		})
	}

	for _, input := range []string{"", "ab", strings.Repeat("a", 65), "admin user", "管理员", "admin/one", "admin@one"} {
		t.Run("reject_"+input, func(t *testing.T) {
			if _, err := NormalizeUsername(input); !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("NormalizeUsername(%q) error = %v, want ErrInvalidInput", input, err)
			}
		})
	}
}

func TestPasswordHasherHashesAndVerifiesPasswords(t *testing.T) {
	t.Parallel()

	hasher, err := NewPasswordHasher(testPasswordParams(), bytes.NewReader(bytes.Repeat([]byte{0x2a}, 16)))
	if err != nil {
		t.Fatalf("NewPasswordHasher(): %v", err)
	}
	encoded, err := hasher.Hash([]byte("correct horse battery"))
	if err != nil {
		t.Fatalf("Hash(): %v", err)
	}
	const prefix = "$argon2id$v=19$m=64,t=1,p=1$KioqKioqKioqKioqKioqKg$"
	if !strings.HasPrefix(encoded, prefix) {
		t.Fatalf("Hash() prefix = %q, want %q", encoded, prefix)
	}
	verified, err := hasher.Verify(encoded, []byte("correct horse battery"))
	if err != nil || !verified {
		t.Fatalf("Verify(correct) = %v, %v, want true, nil", verified, err)
	}
	verified, err = hasher.Verify(encoded, []byte("wrong password value"))
	if err != nil || verified {
		t.Fatalf("Verify(wrong) = %v, %v, want false, nil", verified, err)
	}
}

func TestPasswordHasherUsesIndependentRandomSalts(t *testing.T) {
	t.Parallel()

	random := append(bytes.Repeat([]byte{0x11}, 16), bytes.Repeat([]byte{0x22}, 16)...)
	hasher, err := NewPasswordHasher(testPasswordParams(), bytes.NewReader(random))
	if err != nil {
		t.Fatalf("NewPasswordHasher(): %v", err)
	}
	first, err := hasher.Hash([]byte("same password value"))
	if err != nil {
		t.Fatalf("Hash(first): %v", err)
	}
	second, err := hasher.Hash([]byte("same password value"))
	if err != nil {
		t.Fatalf("Hash(second): %v", err)
	}
	if first == second {
		t.Fatal("Hash() reused a password salt")
	}
}

func TestPasswordHasherRejectsInvalidInputs(t *testing.T) {
	t.Parallel()

	for _, params := range []PasswordParams{
		{},
		{MemoryKiB: 63, Iterations: 1, Parallelism: 1, SaltBytes: 16, KeyBytes: 32},
		{MemoryKiB: 64, Iterations: 0, Parallelism: 1, SaltBytes: 16, KeyBytes: 32},
		{MemoryKiB: 64, Iterations: 1, Parallelism: 0, SaltBytes: 16, KeyBytes: 32},
		{MemoryKiB: 64, Iterations: 1, Parallelism: 1, SaltBytes: 15, KeyBytes: 32},
		{MemoryKiB: 64, Iterations: 1, Parallelism: 1, SaltBytes: 16, KeyBytes: 31},
	} {
		if _, err := NewPasswordHasher(params, bytes.NewReader(make([]byte, 32))); !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("NewPasswordHasher(%+v) error = %v, want ErrInvalidInput", params, err)
		}
	}

	hasher, err := NewPasswordHasher(testPasswordParams(), bytes.NewReader(make([]byte, 32)))
	if err != nil {
		t.Fatalf("NewPasswordHasher(): %v", err)
	}
	for _, password := range [][]byte{
		[]byte("short"),
		bytes.Repeat([]byte("x"), 129),
	} {
		if _, err := hasher.Hash(password); !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("Hash(length=%d) error = %v, want ErrInvalidInput", len(password), err)
		}
	}
	for _, encoded := range []string{"", "not-a-hash", "$argon2id$v=18$m=64,t=1,p=1$YQ$Yg", "$argon2id$v=19$m=999999,t=1,p=1$YQ$Yg"} {
		if _, err := hasher.Verify(encoded, []byte("correct horse battery")); !errors.Is(err, ErrInvalidHash) {
			t.Fatalf("Verify(%q) error = %v, want ErrInvalidHash", encoded, err)
		}
	}
}

func testPasswordParams() PasswordParams {
	return PasswordParams{
		MemoryKiB:   64,
		Iterations:  1,
		Parallelism: 1,
		SaltBytes:   16,
		KeyBytes:    32,
	}
}
