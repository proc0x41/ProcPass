package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"src/internal/storage"
)

func WrapVEK(vek []byte, kek []byte) (*storage.WrappedKey, error) {
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, fmt.Errorf("error when creating cipher for wrap: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("error when creating GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("error when generating nonce: %w", err)
	}

	aad := []byte(storage.AADVEKWrap)
	ciphertext := gcm.Seal(nil, nonce, vek, aad)

	return &storage.WrappedKey{
		Nonce:      nonce,
		Ciphertext: ciphertext,
	}, nil
}

func UnwrapVEK(wrapped *storage.WrappedKey, kek []byte) ([]byte, error) {
	if wrapped == nil {
		return nil, fmt.Errorf("wrapped key is nil")
	}

	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, fmt.Errorf("error when creating cipher for unwrap: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("error when creating GCM: %w", err)
	}

	aad := []byte(storage.AADVEKWrap)
	vek, err := gcm.Open(nil, wrapped.Nonce, wrapped.Ciphertext, aad)
	if err != nil {
		return nil, fmt.Errorf("incorrect master password or corrupted vault: %w", err)
	}

	return vek, nil
}
