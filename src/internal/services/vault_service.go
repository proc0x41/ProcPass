package services

import (
	"encoding/json"
	"os"
	"path/filepath"
	"src/internal/crypto"
	"src/internal/models"
	"time"

	"github.com/google/uuid"
)

type VaultService struct {
	key   []byte
	vault *models.Vault
	path  string
}

func NewVaultService() *VaultService {
	return &VaultService{}
}

func (s *VaultService) CreateVault(path, masterPassword string) error {
	params := crypto.DefaultArgon2Params()
	salt, err := crypto.GenerateSalt(params.SaltLength)
	if err != nil {
		return err
	}

	key, err := crypto.DeriveKey(masterPassword, salt, &params)
	if err != nil {
		return err
	}

	vault := &models.Vault{
		Version:   "1.0",
		Salt:      salt,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
		Entries:   []models.Entry{},
	}
	return s.saveVault(path, vault, key)
}

func (s *VaultService) OpenVault(path, masterPassword string) (*models.Vault, error) {
	fileData, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	header := struct {
		Version string                  `json:"version"`
		Salt    []byte                  `json:"salt"`
		Data    crypto.EncryptedPayload `json:"data"`
	}{}
	if err := json.Unmarshal(fileData, &header); err != nil {
		return nil, err
	}

	params := crypto.DefaultArgon2Params()
	key, err := crypto.DeriveKey(masterPassword, header.Salt, &params)
	if err != nil {
		return nil, err
	}

	plaintext, err := crypto.Decrypt(&header.Data, key)
	if err != nil {
		return nil, err
	}

	var vault models.Vault
	if err := json.Unmarshal(plaintext, &vault); err != nil {
		return nil, err
	}

	s.key = key
	s.vault = &vault
	s.path = path

	return &vault, nil
}

func (s *VaultService) LockVault() {
	if s.key != nil {
		for i := range s.key {
			s.key[i] = 0
		}
	}

	s.key = nil
	s.vault = nil
	s.path = ""
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

	fileData, err := json.Marshal(struct {
		Version string
		Salt    []byte
		Data    crypto.EncryptedPayload
	}{
		Version: vault.Version,
		Salt:    vault.Salt,
		Data:    *encrypted,
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
	if s.vault == nil {
		return os.ErrNotExist
	}

	s.vault.Entries = append(s.vault.Entries, entry)
	s.vault.UpdatedAt = time.Now()

	return s.saveVault(s.path, s.vault, s.key)
}

func (s *VaultService) UpdateEntry(id, title, username, password, url, notes string) error {
	if s.vault == nil {
		return os.ErrNotExist
	}

	for i := range s.vault.Entries {
		if s.vault.Entries[i].ID == id {
			s.vault.Entries[i].Title = title
			s.vault.Entries[i].Username = username
			s.vault.Entries[i].Password = password
			s.vault.Entries[i].URL = url
			s.vault.Entries[i].Notes = notes
			s.vault.Entries[i].UpdatedAt = time.Now()
			s.vault.UpdatedAt = time.Now()
			return s.saveVault(s.path, s.vault, s.key)
		}
	}
	return os.ErrNotExist
}

func (s *VaultService) DeleteEntry(id string) error {
	if s.vault == nil {
		return os.ErrNotExist
	}

	for i := range s.vault.Entries {
		if s.vault.Entries[i].ID == id {
			s.vault.Entries = append(s.vault.Entries[:i], s.vault.Entries[i+1:]...)
			s.vault.UpdatedAt = time.Now()
			return s.saveVault(s.path, s.vault, s.key)
		}
	}
	return os.ErrNotExist
}

func (s *VaultService) GetEntries() []models.Entry {
	if s.vault == nil {
		return nil
	}
	return s.vault.Entries
}
