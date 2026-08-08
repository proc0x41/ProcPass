package services

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"src/internal/crypto"
	"src/internal/models"
	"src/internal/storage"
	"sync"

	"github.com/google/uuid"
)

type VaultService struct {
	mu         sync.RWMutex
	vault      *models.Vault
	vek        []byte
	vaultPath  string
	isUnlocked bool
	kdfParams  crypto.Argon2Params
}

func NewVaultService() *VaultService {
	return &VaultService{
		kdfParams: crypto.DefaultArgon2Params(),
	}
}

// SetKDFParams permite configurar os parâmetros do Argon2id.
// Deve ser chamado antes de CreateVault. OpenVault usa os parâmetros
// armazenados no próprio arquivo do vault.
func (s *VaultService) SetKDFParams(params crypto.Argon2Params) {
	s.kdfParams = params
}

func (s *VaultService) CreateVault(path, masterPassword string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	salt, err := crypto.GenerateSalt(s.kdfParams.SaltLength)
	if err != nil {
		return fmt.Errorf("error generating salt: %w", err)
	}

	kek, err := crypto.DeriveKey(masterPassword, salt, &s.kdfParams)
	if err != nil {
		return fmt.Errorf("error deriving KEK: %w", err)
	}
	defer crypto.Zeroize(kek)

	vek, err := crypto.GenerateVEK()
	if err != nil {
		return fmt.Errorf("error generating VEK: %w", err)
	}
	defer crypto.Zeroize(vek)

	wrappedVEK, err := crypto.WrapVEK(vek, kek)
	if err != nil {
		return fmt.Errorf("error wrapping VEK: %w", err)
	}

	vault := models.NewVault()

	vaultJSON, err := json.Marshal(vault)
	if err != nil {
		return fmt.Errorf("error marshalling vault: %w", err)
	}

	encryptedVault, err := crypto.Encrypt(vaultJSON, vek)
	if err != nil {
		return fmt.Errorf("error encrypting vault: %w", err)
	}

	vaultFile := storage.VaultFile{
		Version: storage.FileVersion,
		KDF: storage.KDFParams{
			Algorithm:   "argon2id",
			Salt:        salt,
			Memory:      s.kdfParams.Memory,
			Iterations:  s.kdfParams.Iterations,
			Parallelism: s.kdfParams.Parallelism,
		},
		WrappedVEK: *wrappedVEK,
		Vault:      *encryptedVault,
	}

	fileData, err := json.MarshalIndent(vaultFile, "", "  ")
	if err != nil {
		return fmt.Errorf("error marshalling vault file: %w", err)
	}

	if err := s.atomicWrite(path, fileData); err != nil {
		return err
	}

	s.vault = vault
	s.vek = make([]byte, len(vek))
	copy(s.vek, vek)
	s.vaultPath = path
	s.isUnlocked = true

	return nil
}

func (s *VaultService) OpenVault(path, masterPassword string) (*models.Vault, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	fileData, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("error reading vault file: %w", err)
	}

	var vaultFile storage.VaultFile
	if err := json.Unmarshal(fileData, &vaultFile); err != nil {
		return nil, fmt.Errorf("error unmarshalling vault file: %w", err)
	}

	if vaultFile.Version != storage.FileVersion {
		return nil, fmt.Errorf("unsupported vault version: %s", vaultFile.Version)
	}

	params := crypto.Argon2Params{
		Memory:      vaultFile.KDF.Memory,
		Iterations:  vaultFile.KDF.Iterations,
		Parallelism: vaultFile.KDF.Parallelism,
		SaltLength:  uint32(len(vaultFile.KDF.Salt)),
		KeyLength:   32,
	}

	kek, err := crypto.DeriveKey(masterPassword, vaultFile.KDF.Salt, &params)
	if err != nil {
		return nil, fmt.Errorf("error deriving KEK: %w", err)
	}
	defer crypto.Zeroize(kek)

	vek, err := crypto.UnwrapVEK(&vaultFile.WrappedVEK, kek)
	if err != nil {
		return nil, fmt.Errorf("error unwrapping VEK: %w", err)
	}

	vaultJSON, err := crypto.Decrypt(&vaultFile.Vault, vek)
	if err != nil {
		crypto.Zeroize(vek)
		return nil, fmt.Errorf("error decrypting vault: %w", err)
	}

	var vault models.Vault
	if err := json.Unmarshal(vaultJSON, &vault); err != nil {
		crypto.Zeroize(vek)
		return nil, fmt.Errorf("error unmarshalling vault: %w", err)
	}

	s.vault = &vault
	s.vek = vek
	s.vaultPath = path
	s.isUnlocked = true

	return &vault, nil
}

func (s *VaultService) LockVault() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.vek != nil {
		crypto.Zeroize(s.vek)
		s.vek = nil
	}
	s.vault = nil
	s.isUnlocked = false
}

func (s *VaultService) AddEntry(entry models.Entry) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.isUnlocked {
		return fmt.Errorf("vault is locked")
	}

	entry.ID = uuid.New().String()
	s.vault.Entries = append(s.vault.Entries, entry)

	return s.persistLocked()
}

func (s *VaultService) UpdateEntry(id, title, username, password, url, notes string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.isUnlocked {
		return fmt.Errorf("vault is locked")
	}

	for i := range s.vault.Entries {
		if s.vault.Entries[i].ID == id {
			s.vault.Entries[i].Update(title, username, password, url, notes)
			return s.persistLocked()
		}
	}

	return fmt.Errorf("entry not found: %s", id)
}

func (s *VaultService) DeleteEntry(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.isUnlocked {
		return fmt.Errorf("vault is locked")
	}

	for i := range s.vault.Entries {
		if s.vault.Entries[i].ID == id {
			s.vault.Entries = append(s.vault.Entries[:i], s.vault.Entries[i+1:]...)
			return s.persistLocked()
		}
	}

	return fmt.Errorf("entry not found: %s", id)
}

func (s *VaultService) GetEntries() []models.Entry {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if !s.isUnlocked {
		return nil
	}

	return s.vault.Entries
}

func (s *VaultService) ChangeMasterPassword(newMasterPassword string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.isUnlocked {
		return fmt.Errorf("vault is locked")
	}

	newSalt, err := crypto.GenerateSalt(s.kdfParams.SaltLength)
	if err != nil {
		return fmt.Errorf("error generating new salt: %w", err)
	}

	newKEK, err := crypto.DeriveKey(newMasterPassword, newSalt, &s.kdfParams)
	if err != nil {
		return fmt.Errorf("error deriving new KEK: %w", err)
	}
	defer crypto.Zeroize(newKEK)

	newWrappedVEK, err := crypto.WrapVEK(s.vek, newKEK)
	if err != nil {
		return fmt.Errorf("error wrapping VEK with new KEK: %w", err)
	}

	fileData, err := os.ReadFile(s.vaultPath)
	if err != nil {
		return fmt.Errorf("error reading vault file: %w", err)
	}

	var vaultFile storage.VaultFile
	if err := json.Unmarshal(fileData, &vaultFile); err != nil {
		return fmt.Errorf("error unmarshalling vault file: %w", err)
	}

	vaultFile.KDF.Salt = newSalt
	vaultFile.WrappedVEK = *newWrappedVEK

	updatedData, err := json.MarshalIndent(vaultFile, "", "  ")
	if err != nil {
		return fmt.Errorf("error marshalling updated vault file: %w", err)
	}

	return s.atomicWrite(s.vaultPath, updatedData)
}

func (s *VaultService) persistLocked() error {
	vaultJSON, err := json.Marshal(s.vault)
	if err != nil {
		return fmt.Errorf("error marshalling vault: %w", err)
	}

	encryptedVault, err := crypto.Encrypt(vaultJSON, s.vek)
	if err != nil {
		return fmt.Errorf("error encrypting vault: %w", err)
	}

	fileData, err := os.ReadFile(s.vaultPath)
	if err != nil {
		return fmt.Errorf("error reading vault file: %w", err)
	}

	var vaultFile storage.VaultFile
	if err := json.Unmarshal(fileData, &vaultFile); err != nil {
		return fmt.Errorf("error unmarshalling vault file: %w", err)
	}

	vaultFile.Vault = *encryptedVault

	updatedData, err := json.MarshalIndent(vaultFile, "", "  ")
	if err != nil {
		return fmt.Errorf("error marshalling updated vault file: %w", err)
	}

	return s.atomicWrite(s.vaultPath, updatedData)
}

func (s *VaultService) atomicWrite(path string, data []byte) error {
	dir := filepath.Dir(path)
	tempFile, err := os.CreateTemp(dir, "procpass-*.tmp")
	if err != nil {
		return fmt.Errorf("error creating temp file: %w", err)
	}
	tempPath := tempFile.Name()

	defer func() {
		tempFile.Close()
		os.Remove(tempPath)
	}()

	if _, err := tempFile.Write(data); err != nil {
		return fmt.Errorf("error writing temp file: %w", err)
	}

	if err := tempFile.Sync(); err != nil {
		return fmt.Errorf("error syncing temp file: %w", err)
	}

	if err := tempFile.Close(); err != nil {
		return fmt.Errorf("error closing temp file: %w", err)
	}

	if err := os.Rename(tempPath, path); err != nil {
		return fmt.Errorf("error renaming temp file: %w", err)
	}

	return nil
}