package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"src/internal/storage"
)

func Encrypt(plaintext []byte, key []byte) (*storage.EncryptedData, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("Error when creating cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("Error when creating GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("Error when reading nonce: %w", err)
	}

	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)

	return &storage.EncryptedData{
		Ciphertext: ciphertext,
		Nonce:      nonce,
	}, nil
}

func Decrypt(data *storage.EncryptedData, key []byte) ([]byte, error) {
	if data == nil {
		return nil, fmt.Errorf("Payload is nil")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("Error when creating cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("Error when creating GCM: %w", err)
	}

	plaintext, err := gcm.Open(nil, data.Nonce, data.Ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("Error when decrypting: %w", err)
	}

	return plaintext, nil
}
