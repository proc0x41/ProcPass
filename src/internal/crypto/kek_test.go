package crypto

import (
	"bytes"
	"testing"
)

func TestWrapUnwrapVEK_HappyPath(t *testing.T) {
	vek := make([]byte, 32)
	for i := range vek {
		vek[i] = byte(i)
	}

	kek := make([]byte, 32)
	for i := range kek {
		kek[i] = byte(i + 100)
	}

	wrapped, err := WrapVEK(vek, kek)
	if err != nil {
		t.Fatalf("WrapVEK failed: %v", err)
	}

	if len(wrapped.Nonce) == 0 {
		t.Fatalf("WrapVEK failed: nonce is nil or empty")
	}

	if len(wrapped.Ciphertext) == 0 {
		t.Fatalf("WrapVEK failed: ciphertext is nil or empty")
	}

	if bytes.Equal(wrapped.Ciphertext, vek) {
		t.Fatalf("WrapVEK failed: ciphertext is equal to VEK")
	}

	recovered, err := UnwrapVEK(wrapped, kek)
	if err != nil {
		t.Fatalf("UnwrapVEK failed: %v", err)
	}

	if !bytes.Equal(recovered, vek) {
		t.Fatalf("Recovered VEK doesn't coincide: expected %x, got %x", vek, recovered)
	}
}

func TestUnwrapVEK_WrongKey(t *testing.T) {
	vek := make([]byte, 32)
	for i := range vek {
		vek[i] = byte(i)
	}

	kek := make([]byte, 32)
	for i := range kek {
		kek[i] = byte(i + 100)
	}

	wrongKEK := make([]byte, 32)
	for i := range wrongKEK {
		wrongKEK[i] = byte(i + 200)
	}

	wrapped, err := WrapVEK(vek, kek)
	if err != nil {
		t.Fatalf("WrapVEK failed: %v", err)
	}

	_, err = UnwrapVEK(wrapped, wrongKEK)
	if err == nil {
		t.Fatalf("UnwrapVEK should've failed with wrong key")
	}
}

func TestUnwrapVEK_TamperedCiphertext(t *testing.T) {
	vek := make([]byte, 32)
	for i := range vek {
		vek[i] = byte(i)
	}

	kek := make([]byte, 32)
	for i := range kek {
		kek[i] = byte(i + 100)
	}

	wrapped, err := WrapVEK(vek, kek)
	if err != nil {
		t.Fatalf("WrapVEK failed: %v", err)
	}

	wrapped.Ciphertext[0] ^= 0xFF

	_, err = UnwrapVEK(wrapped, kek)
	if err == nil {
		t.Fatalf("UnwrapVEK should've failed with tampered ciphertext")
	}
}

func TestUnwrapVEK_TamperedNonce(t *testing.T) {
	vek := make([]byte, 32)
	for i := range vek {
		vek[i] = byte(i)
	}

	kek := make([]byte, 32)
	for i := range kek {
		kek[i] = byte(i + 100)
	}

	wrapped, err := WrapVEK(vek, kek)
	if err != nil {
		t.Fatalf("WrapVEK failed: %v", err)
	}

	wrapped.Nonce[0] ^= 0xFF

	_, err = UnwrapVEK(wrapped, kek)
	if err == nil {
		t.Fatalf("UnwrapVEK should've failed with tampered nonce")
	}
}

func TestUnwrapVEK_NilInput(t *testing.T) {
	kek := make([]byte, 32)
	_, err := UnwrapVEK(nil, kek)
	if err == nil {
		t.Fatalf("UnwrapVEK should've failed with nil input")
	}
}

func TestWrapVEK_DifferentNonces(t *testing.T) {
	vek := make([]byte, 32)
	kek := make([]byte, 32)

	wrapped1, err := WrapVEK(vek, kek)
	if err != nil {
		t.Fatalf("WrapVEK1 failed: %v", err)
	}

	wrapped2, err := WrapVEK(vek, kek)
	if err != nil {
		t.Fatalf("WrapVEK2 failed: %v", err)
	}

	if bytes.Equal(wrapped1.Nonce, wrapped2.Nonce) {
		t.Fatalf("WrapVEK should've generated different nonces")
	}

}
