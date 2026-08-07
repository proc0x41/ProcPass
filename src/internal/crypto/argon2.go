package crypto

import (
	"crypto/rand"
	"fmt"

	"golang.org/x/crypto/argon2"
)

type Argon2Params struct {
	Memory      uint32
	Iterations  uint32
	Parallelism uint8
	SaltLength  uint32
	KeyLength   uint32
}

// OWASP recommendations for Argon2 parameters
func DefaultArgon2Params() Argon2Params {
	return Argon2Params{
		Memory:      64 * 1024, // 64 MB
		Iterations:  3,
		Parallelism: 4,
		SaltLength:  16, // 16 bytes
		KeyLength:   32, // 32 bytes
	}
}

func GenerateSalt(length uint32) ([]byte, error) {
	salt := make([]byte, length)
	_, err := rand.Read(salt)
	if err != nil {
		return nil, fmt.Errorf("Failure when generating salt: %w", err)
	}
	return salt, nil
}

func DeriveKey(password string, salt []byte, params *Argon2Params) ([]byte, error) {
	if len(password) == 0 {
		return nil, fmt.Errorf("Password cannot be empty")
	}

	key := argon2.IDKey(
		[]byte(password),
		salt,
		params.Iterations,
		params.Memory,
		params.Parallelism,
		params.KeyLength,
	)

	return key, nil
}
