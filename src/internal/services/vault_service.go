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
}

func NewVaultService() *VaultService {
	return &VaultService{}
}

func (s *VaultService) CreateVault(path, masterPassword string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	params := crypto.DefaultArgon2Params()

	salt, err := crypto.GenerateSalt(params.SaltLength)
	if err != nil {
		return fmt.Errorf("failure when generating salt: %w", err)
	}

	kek, err := crypto.DeriveKey(masterPassword, salt, &params)
	if err != nil {
		return fmt.Errorf("failure when deriving KEK: %w", err)
	}
	defer crypto.Zeroize(kek)

	vek, err := crypto.GenerateVEK()
	if err != nil {
		return fmt.Errorf("failure when generating VEK: %w", err)
	}
	defer crypto.Zeroize(vek)

	wrappedVEK, err := crypto.WrapVEK(vek, kek)
	if err != nil {
		return fmt.Errorf("failure when wrapping VEK: %w", err)
	}

	vault := models.NewVault()

	vaultJSON, err := json.Marshal(vault)
	if err != nil {
		return fmt.Errorf("failure when marshaling vault: %w", err)
	}

	encryptedVault, err := crypto.Encrypt(vaultJSON, vek)
	if err != nil {
		return fmt.Errorf("failure when encrypting vault: %w", err)
	}

	vaultFile := storage.VaultFile{
		Version: storage.FileVersion,
		KDF: storage.KDFParams{
			Algorithm:   "argon2id",
			Salt:        salt,
			Memory:      64 * 1024 * 1024, //64mb
			Iterations:  3,
			Parallelism: 4,
		},
		WrappedVEK: *wrappedVEK,
		Vault:      *encryptedVault,
	}

	fileData, err := json.MarshalIndent(vaultFile, "", "  ")
	if err != nil {
		return fmt.Errorf("failure when marshaling vault file: %w", err)
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
		return nil, err
	}

	var vaultFile storage.VaultFile
	if err := json.Unmarshal(fileData, &vaultFile); err != nil {
		return nil, fmt.Errorf("failure when desserializing the file: %w", err)
	}

	if vaultFile.Version != storage.FileVersion {
		return nil, fmt.Errorf("file version not supported: %s", vaultFile.Version)
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
		return nil, fmt.Errorf("failure when deriving key: %w", err)
	}
	defer crypto.Zeroize(kek)

	vek, err := crypto.UnwrapVEK(&vaultFile.WrappedVEK, kek)
	if err != nil {
		return nil, fmt.Errorf("failure when unwrapping vek: %w", err)
	}
	defer crypto.Zeroize(vek)

	vaultJSON, err := crypto.Decrypt(&vaultFile.Vault, vek)
	if err != nil {
		crypto.Zeroize(vek)
		return nil, fmt.Errorf("failure when decrypting vault: %w", err)
	}

	var vault models.Vault
	if err := json.Unmarshal(vaultJSON, &vault); err != nil {
		crypto.Zeroize(vek)
		return nil, fmt.Errorf("failure when desserializing vault: %w", err)
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

func (s *VaultService) saveVault(path string, vault *models.Vault, key []byte) error {
	plaintext, err := json.Marshal(vault)
	if err != nil {
		return err
	}

	encrypted, err := crypto.Encrypt(plaintext, key)
	if err != nil {
		return err
	}

	params := crypto.DefaultArgon2Params()

	fileData, err := json.Marshal(storage.VaultFile{
		Version: vault.Version,
		KDF: storage.KDFParams{
			Algorithm:   "argon2id",
			Salt:        vault.Salt,
			Memory:      params.Memory,
			Iterations:  params.Iterations,
			Parallelism: params.Parallelism,
		},
		Vault: *encrypted,
	})
	if err != nil {
		return err
	}

	dir := filepath.Dir(path)
	tmpPath := filepath.Join(dir, ".tmp"+uuid.New().String()+".0x41")
	if err := os.WriteFile(tmpPath, fileData, 0600); err != nil {
		return err
	}

	return os.Rename(tmpPath, path)
}

func (s *VaultService) AddEntry(entry models.Entry) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.isUnlocked {
		return fmt.Errorf("vault is blocked")
	}

	s.vault.Entries = append(s.vault.Entries, entry)
	return s.persistLocked()
}

func (s *VaultService) UpdateEntry(id, title, username, password, url, notes string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.isUnlocked {
		return fmt.Errorf("vault está bloqueado")
	}

	for i := range s.vault.Entries {
		if s.vault.Entries[i].ID == id {
			s.vault.Entries[i].Update(title, username, password, url, notes)
			return s.persistLocked()
		}
	}

	return fmt.Errorf("entry não encontrada: %s", id)
}

func (s *VaultService) DeleteEntry(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.isUnlocked {
		return fmt.Errorf("Vault is locked")
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

func (s *VaultService) persistLocked() error {
	vaultJSON, err := json.Marshal(s.vault)
	if err != nil {
		return err
	}

	encryptedVault, err := crypto.Encrypt(vaultJSON, s.vek)
	if err != nil {
		return err
	}

	fileData, err := os.ReadFile(s.vaultPath)
	if err != nil {
		return fmt.Errorf("failure when reading vault file: %w", err)
	}

	var vaultFile storage.VaultFile
	if err := json.Unmarshal(fileData, &vaultFile); err != nil {
		return fmt.Errorf("failure when unmarshalling vault file: %w", err)
	}

	vaultFile.Vault = *encryptedVault
	updatedData, err := json.MarshalIndent(vaultFile, "", "  ")
	if err != nil {
		return fmt.Errorf("failure when marshalling vault file: %w", err)
	}

	return s.atomicWrite(s.vaultPath, updatedData)
}

func (s *VaultService) atomicWrite(path string, data []byte) error {
	dir := filepath.Dir(path)
	tempFile, err := os.CreateTemp(dir, "procpass-*.tmp")
	if err != nil {
		return fmt.Errorf("erro ao criar arquivo temporário: %w", err)
	}
	tempPath := tempFile.Name()

	defer func() {
		tempFile.Close()
		os.Remove(tempPath)
	}()

	if _, err := tempFile.Write(data); err != nil {
		return fmt.Errorf("erro ao escrever arquivo temporário: %w", err)
	}

	if err := tempFile.Sync(); err != nil {
		return fmt.Errorf("erro ao sincronizar arquivo temporário: %w", err)
	}

	if err := tempFile.Close(); err != nil {
		return fmt.Errorf("erro ao fechar arquivo temporário: %w", err)
	}

	if err := os.Rename(tempPath, path); err != nil {
		return fmt.Errorf("erro ao renomear arquivo temporário: %w", err)
	}

	return nil
}
