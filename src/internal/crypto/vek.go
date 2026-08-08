package crypto

import "crypto/rand"

func GenerateVEK() ([]byte, error) {
	vek := make([]byte, 32)
	if _, err := rand.Read(vek); err != nil {
		return nil, err
	}
	return vek, nil
}

func Zeroize(key []byte) {
	for i := range key {
		key[i] = 0
	}
}
