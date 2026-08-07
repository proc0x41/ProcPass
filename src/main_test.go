package main

import (
	"fmt"
	"os"
	"path/filepath"
	"src/internal/services"
	"testing"
)

func TestVaultFlow(t *testing.T) {
	svc := services.NewVaultService()
	tmpFile := filepath.Join(os.TempDir(), "test.0x41")
	defer os.Remove(tmpFile)

	err := svc.CreateVault(tmpFile, "TESTE123")
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println("Vault Created")

	vault, err := svc.OpenVault(tmpFile, "TESTE123")
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println("Vault Opened")
	fmt.Println(vault)

	_, err = svc.OpenVault(tmpFile, "Teste123")
	if err == nil {
		t.Fatal("Expected error, got nil")
	}
	fmt.Println("Incorrect password rejected")
}
