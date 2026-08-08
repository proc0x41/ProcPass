package services

import (
	"os"
	"path/filepath"
	"testing"

	"src/internal/crypto"
	"src/internal/models"
)

// testKDFParams retorna parâmetros Argon2id reduzidos para testes.
// 16 KB de memória ao invés de 64 MB — rápido e suficiente para validar a lógica.
func testKDFParams() crypto.Argon2Params {
	return crypto.Argon2Params{
		Memory:      16,   // 16 KiB (mínimo do Argon2id)
		Iterations:  1,
		Parallelism: 1,
		SaltLength:  16,
		KeyLength:   32,
	}
}

func TestCreateAndOpenVault(t *testing.T) {
	tempDir := t.TempDir()
	vaultPath := filepath.Join(tempDir, "test.procpass")
	masterPassword := "senha-mestra-forte-123"

	svc := NewVaultService()
	svc.SetKDFParams(testKDFParams())

	// Criar vault
	err := svc.CreateVault(vaultPath, masterPassword)
	if err != nil {
		t.Fatalf("CreateVault falhou: %v", err)
	}

	// Verificar que o arquivo foi criado
	if _, err := os.Stat(vaultPath); os.IsNotExist(err) {
		t.Fatal("arquivo do vault não foi criado")
	}

	// Abrir vault com senha correta
	svc2 := NewVaultService()
	vault, err := svc2.OpenVault(vaultPath, masterPassword)
	if err != nil {
		t.Fatalf("OpenVault falhou: %v", err)
	}

	if vault == nil {
		t.Fatal("vault retornado é nil")
	}

	if len(vault.Entries) != 0 {
		t.Fatalf("vault deveria estar vazio, tem %d entries", len(vault.Entries))
	}
}

func TestOpenVault_WrongPassword(t *testing.T) {
	tempDir := t.TempDir()
	vaultPath := filepath.Join(tempDir, "test.procpass")
	masterPassword := "senha-correta"
	wrongPassword := "senha-errada"

	svc := NewVaultService()
	svc.SetKDFParams(testKDFParams())

	err := svc.CreateVault(vaultPath, masterPassword)
	if err != nil {
		t.Fatalf("CreateVault falhou: %v", err)
	}

	// Tentar abrir com senha errada
	svc2 := NewVaultService()
	_, err = svc2.OpenVault(vaultPath, wrongPassword)
	if err == nil {
		t.Fatal("OpenVault com senha errada deveria ter falhado")
	}
}

func TestCRUDOperations(t *testing.T) {
	tempDir := t.TempDir()
	vaultPath := filepath.Join(tempDir, "test.procpass")
	masterPassword := "senha-mestra"

	svc := NewVaultService()
	svc.SetKDFParams(testKDFParams())

	err := svc.CreateVault(vaultPath, masterPassword)
	if err != nil {
		t.Fatalf("CreateVault falhou: %v", err)
	}

	// Add entry
	entry := models.NewEntry("GitHub", "user@example.com", "secret123", "https://github.com", "minha conta")
	err = svc.AddEntry(*entry)
	if err != nil {
		t.Fatalf("AddEntry falhou: %v", err)
	}

	// Get entries
	entries := svc.GetEntries()
	if len(entries) != 1 {
		t.Fatalf("esperado 1 entry, obtido %d", len(entries))
	}

	if entries[0].Title != "GitHub" {
		t.Fatalf("título incorreto: esperado 'GitHub', obtido '%s'", entries[0].Title)
	}

	// Update entry
	err = svc.UpdateEntry(entries[0].ID, "GitHub Updated", "newuser@example.com", "newsecret", "https://github.com", "nota atualizada")
	if err != nil {
		t.Fatalf("UpdateEntry falhou: %v", err)
	}

	entries = svc.GetEntries()
	if entries[0].Title != "GitHub Updated" {
		t.Fatalf("título não foi atualizado: '%s'", entries[0].Title)
	}

	// Add segunda entry
	entry2 := models.NewEntry("Google", "user@gmail.com", "googlepass", "https://google.com", "")
	err = svc.AddEntry(*entry2)
	if err != nil {
		t.Fatalf("AddEntry falhou: %v", err)
	}

	entries = svc.GetEntries()
	if len(entries) != 2 {
		t.Fatalf("esperado 2 entries, obtido %d", len(entries))
	}

	// Delete entry
	err = svc.DeleteEntry(entries[0].ID)
	if err != nil {
		t.Fatalf("DeleteEntry falhou: %v", err)
	}

	entries = svc.GetEntries()
	if len(entries) != 1 {
		t.Fatalf("esperado 1 entry após delete, obtido %d", len(entries))
	}

	if entries[0].Title != "Google" {
		t.Fatalf("entry errada foi deletada")
	}
}

func TestPersistence(t *testing.T) {
	tempDir := t.TempDir()
	vaultPath := filepath.Join(tempDir, "test.procpass")
	masterPassword := "senha-mestra"

	svc := NewVaultService()
	svc.SetKDFParams(testKDFParams())

	err := svc.CreateVault(vaultPath, masterPassword)
	if err != nil {
		t.Fatalf("CreateVault falhou: %v", err)
	}

	// Adicionar entry
	entry := models.NewEntry("Test", "user", "pass", "", "")
	err = svc.AddEntry(*entry)
	if err != nil {
		t.Fatalf("AddEntry falhou: %v", err)
	}

	// Abrir vault com nova instância do service
	svc2 := NewVaultService()
	vault, err := svc2.OpenVault(vaultPath, masterPassword)
	if err != nil {
		t.Fatalf("OpenVault falhou: %v", err)
	}

	if len(vault.Entries) != 1 {
		t.Fatalf("entry não foi persistida: esperado 1, obtido %d", len(vault.Entries))
	}

	if vault.Entries[0].Title != "Test" {
		t.Fatalf("entry persistida incorreta: '%s'", vault.Entries[0].Title)
	}
}

func TestChangeMasterPassword(t *testing.T) {
	tempDir := t.TempDir()
	vaultPath := filepath.Join(tempDir, "test.procpass")
	oldPassword := "senha-antiga"
	newPassword := "senha-nova"

	svc := NewVaultService()
	svc.SetKDFParams(testKDFParams())

	err := svc.CreateVault(vaultPath, oldPassword)
	if err != nil {
		t.Fatalf("CreateVault falhou: %v", err)
	}

	// Adicionar entry
	entry := models.NewEntry("Test", "user", "pass", "", "")
	err = svc.AddEntry(*entry)
	if err != nil {
		t.Fatalf("AddEntry falhou: %v", err)
	}

	// Trocar senha mestra
	err = svc.ChangeMasterPassword(newPassword)
	if err != nil {
		t.Fatalf("ChangeMasterPassword falhou: %v", err)
	}

	// Tentar abrir com senha antiga deve falhar
	svc2 := NewVaultService()
	_, err = svc2.OpenVault(vaultPath, oldPassword)
	if err == nil {
		t.Fatal("OpenVault com senha antiga deveria ter falhado")
	}

	// Abrir com nova senha deve funcionar
	svc3 := NewVaultService()
	vault, err := svc3.OpenVault(vaultPath, newPassword)
	if err != nil {
		t.Fatalf("OpenVault com nova senha falhou: %v", err)
	}

	// Verificar que a entry ainda existe
	if len(vault.Entries) != 1 {
		t.Fatalf("entry foi perdida após troca de senha: esperado 1, obtido %d", len(vault.Entries))
	}

	if vault.Entries[0].Title != "Test" {
		t.Fatalf("entry corrompida após troca de senha: '%s'", vault.Entries[0].Title)
	}
}

func TestLockVault(t *testing.T) {
	tempDir := t.TempDir()
	vaultPath := filepath.Join(tempDir, "test.procpass")
	masterPassword := "senha-mestra"

	svc := NewVaultService()
	svc.SetKDFParams(testKDFParams())

	err := svc.CreateVault(vaultPath, masterPassword)
	if err != nil {
		t.Fatalf("CreateVault falhou: %v", err)
	}

	// Adicionar entry
	entry := models.NewEntry("Test", "user", "pass", "", "")
	err = svc.AddEntry(*entry)
	if err != nil {
		t.Fatalf("AddEntry falhou: %v", err)
	}

	// Lock vault
	svc.LockVault()

	// Tentar adicionar entry deve falhar
	err = svc.AddEntry(*entry)
	if err == nil {
		t.Fatal("AddEntry em vault bloqueado deveria ter falhado")
	}

	// GetEntries deve retornar nil ou vazio
	entries := svc.GetEntries()
	if entries != nil && len(entries) > 0 {
		t.Fatal("GetEntries em vault bloqueado deveria retornar nil ou vazio")
	}
}

func TestVaultService_OperationsOnLockedVault(t *testing.T) {
	svc := NewVaultService()

	// Todas as operações devem falhar em vault bloqueado
	entry := models.NewEntry("Test", "user", "pass", "", "")
	err := svc.AddEntry(*entry)
	if err == nil {
		t.Fatal("AddEntry em vault bloqueado deveria ter falhado")
	}

	err = svc.UpdateEntry("id", "title", "user", "pass", "", "")
	if err == nil {
		t.Fatal("UpdateEntry em vault bloqueado deveria ter falhado")
	}

	err = svc.DeleteEntry("id")
	if err == nil {
		t.Fatal("DeleteEntry em vault bloqueado deveria ter falhado")
	}

	err = svc.ChangeMasterPassword("newpass")
	if err == nil {
		t.Fatal("ChangeMasterPassword em vault bloqueado deveria ter falhado")
	}
}