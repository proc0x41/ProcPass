package main

import (
	"context"
	"fmt"
	"src/internal/models"
	"src/internal/services"
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

func (a *App) Greet(name string) string {
	return fmt.Sprintf("Hello %s, It's show time!", name)
}
