//go:build windows

package wintray

import (
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
)

const (
	_ = iota
	openUIMenuID
	settingsUIMenuID
	updateSeparatorMenuID
	updateAvailableMenuID
	updateMenuID
	separatorMenuID
	diagLogsMenuID
	diagSeparatorMenuID
	quitMenuID
)

func (t *winTray) initMenus() error {
	if err := t.addOrUpdateMenuItem(openUIMenuID, 0, openUIMenuTitle, false); err != nil {
		return fmt.Errorf("unable to create menu entries %w", err)
	}
	if err := t.addOrUpdateMenuItem(settingsUIMenuID, 0, settingsUIMenuTitle, false); err != nil {
		return fmt.Errorf("unable to create menu entries %w", err)
	}
	if err := t.addOrUpdateMenuItem(diagLogsMenuID, 0, diagLogsMenuTitle, false); err != nil {
		return fmt.Errorf("unable to create menu entries %w\n", err)
	}
	if err := t.addSeparatorMenuItem(diagSeparatorMenuID, 0); err != nil {
		return fmt.Errorf("unable to create menu entries %w", err)
	}

	if err := t.addOrUpdateMenuItem(quitMenuID, 0, quitMenuTitle, false); err != nil {
		return fmt.Errorf("unable to create menu entries %w", err)
	}
	return nil
}

func (t *winTray) UpdateAvailable(ver string) error {
	// Update checks and notifications disabled for Luna AI.
	return nil
}

func (t *winTray) showLogs() error {
	localAppData := os.Getenv("LOCALAPPDATA")
	AppDataDir := filepath.Join(localAppData, "Luna AI")
	cmd_path := "c:\\Windows\\system32\\cmd.exe"
	slog.Debug(fmt.Sprintf("viewing logs with start %s", AppDataDir))
	cmd := exec.Command(cmd_path, "/c", "start", AppDataDir)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: false, CreationFlags: 0x08000000}
	err := cmd.Start()
	if err != nil {
		slog.Error(fmt.Sprintf("Failed to open log dir: %s", err))
	}
	return nil
}
