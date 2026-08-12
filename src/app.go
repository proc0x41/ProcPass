package main

import (
	"context"
	"fmt"
	"src/internal/models"
	"src/internal/services"

	"github.com/wailsapp/wails/v2/pkg/runtime"
)

// App struct
type App struct {
	ctx      context.Context
	vaultSvc *services.VaultService
}

// NewApp creates a new App application struct
func NewApp() *App {
	return &App{
		vaultSvc: services.NewVaultService(),
	}
}

// startup is called when the app starts. The context is saved
// so we can call the runtime methods
func (a *App) startup(ctx context.Context) {
	a.ctx = ctx
}

func (a *App) CreateVault(path, masterPassword string) error {
	return a.vaultSvc.CreateVault(path, masterPassword)
}

func (a *App) UnlockVault(path, masterPassword string) (*models.Vault, error) {
	return a.vaultSvc.OpenVault(path, masterPassword)
}

func (a *App) LockVault() {
	a.vaultSvc.LockVault()
}

func (a *App) AddEntry(title, username, password, url, notes string) error {
	entry := models.NewEntry(title, username, password, url, notes)
	return a.vaultSvc.AddEntry(*entry)
}

func (a *App) UpdateEntry(id, title, username, password, url, notes string) error {
	return a.vaultSvc.UpdateEntry(id, title, username, password, url, notes)
}

func (a *App) DeleteEntry(id string) error {
	return a.vaultSvc.DeleteEntry(id)
}

func (a *App) GetEntries() []models.Entry {
	return a.vaultSvc.GetEntries()
}

// SelectNewVaultPath opens a native save dialog so the user can pick where
// the new vault file will be created. Returns an empty string if cancelled.
func (a *App) SelectNewVaultPath() (string, error) {
	return runtime.SaveFileDialog(a.ctx, runtime.SaveDialogOptions{
		Title:           "Choose where to save your vault",
		DefaultFilename: "vault.procpass",
		Filters: []runtime.FileFilter{
			{DisplayName: "ProcPass Vault (*.procpass;*.json)", Pattern: "*.procpass;*.json"},
			{DisplayName: "All Files (*.*)", Pattern: "*.*"},
		},
	})
}

// SelectVaultPath opens a native open dialog so the user can pick an
// existing vault file. Returns an empty string if cancelled.
func (a *App) SelectVaultPath() (string, error) {
	return runtime.OpenFileDialog(a.ctx, runtime.OpenDialogOptions{
		Title: "Select your vault file",
		Filters: []runtime.FileFilter{
			{DisplayName: "ProcPass Vault (*.procpass;*.json)", Pattern: "*.procpass;*.json"},
			{DisplayName: "All Files (*.*)", Pattern: "*.*"},
		},
	})
}

func (a *App) Greet(name string) string {
	return fmt.Sprintf("Hello %s, It's show time!", name)
}
