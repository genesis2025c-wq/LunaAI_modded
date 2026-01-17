package updater

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"

	"github.com/ollama/ollama/app/version"
)

type Updater struct {
	Owner string
	Repo  string
}

var (
	Owner = "genesis2025c-wq"
	Repo  = "LunaAI_modded"

	DefaultUpdater = NewUpdater(Owner, Repo)
)

func NewUpdater(owner, repo string) *Updater {
	return &Updater{
		Owner: owner,
		Repo:  repo,
	}
}

func (u *Updater) Check(ctx context.Context) (*UpdateStatus, error) {
	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/releases/latest", u.Owner, u.Repo)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("github api returned status %d", resp.StatusCode)
	}

	var release Release
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return nil, err
	}

	current := version.Version
	latest := strings.TrimPrefix(release.TagName, "v")

	if isNewer(current, latest) {
		// Find matching asset for platform
		assetURL := ""
		for _, a := range release.Assets {
			if strings.Contains(strings.ToLower(a.Name), runtime.GOOS) && strings.Contains(strings.ToLower(a.Name), runtime.GOARCH) {
				assetURL = a.BrowserDownloadURL
				break
			}
		}

		return &UpdateStatus{
			NewVersion: true,
			Version:    release.TagName,
			Changelog:  release.Body,
			AssetURL:   assetURL,
			Release:    release,
		}, nil
	}

	return &UpdateStatus{NewVersion: false}, nil
}

func (u *Updater) Download(ctx context.Context, url string, targetPath string) error {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download failed with status %d", resp.StatusCode)
	}

	out, err := os.Create(targetPath)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, resp.Body)
	return err
}

func (u *Updater) Apply(newBinaryPath string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}

	oldExe := exe + ".old"

	// Remove previous .old if exists
	os.Remove(oldExe)

	// Step 1: Rename current to .old
	if err := os.Rename(exe, oldExe); err != nil {
		return fmt.Errorf("failed to rename current binary: %w", err)
	}

	// Step 2: Move new binary to current location
	if err := os.Rename(newBinaryPath, exe); err != nil {
		// Rollback if failed
		os.Rename(oldExe, exe)
		return fmt.Errorf("failed to move new binary: %w", err)
	}

	// Step 3: Restart
	cmd := exec.Command(exe, os.Args[1:]...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		// Rollback
		os.Rename(oldExe, exe)
		return fmt.Errorf("failed to restart: %w", err)
	}

	os.Exit(0)
	return nil
}

// Package-level functions for compatibility
func DoUpgrade(interactive bool) error {
	// In the new system, we expect the asset to be already known or chosen
	// For background compatibility, we might need a stored asset URL
	// For now, this is a placeholder or we can trigger a check+download+apply
	return errors.New("DoUpgrade called without specific asset. Use API flow.")
}

func IsUpdatePending() bool {
	return false // Simplified for new system
}

func DoUpgradeAtStartup() error {
	return nil
}

func DoPostUpgradeCleanup() error {
	exe, err := os.Executable()
	if err == nil {
		os.Remove(exe + ".old")
	}
	return nil
}

// Simple semver comparison
func isNewer(current, latest string) bool {
	if latest == "" {
		return false
	}
	if current == "0.0.0" || current == "" {
		return true
	}

	cParts := strings.Split(strings.TrimPrefix(current, "v"), ".")
	lParts := strings.Split(strings.TrimPrefix(latest, "v"), ".")

	for i := 0; i < len(cParts) && i < len(lParts); i++ {
		var cv, lv int
		fmt.Sscanf(cParts[i], "%d", &cv)
		fmt.Sscanf(lParts[i], "%d", &lv)
		if lv > cv {
			return true
		}
		if cv > lv {
			return false
		}
	}
	return len(lParts) > len(cParts)
}

func VerifyChecksum(filePath, expectedHash string) error {
	f, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return err
	}

	actualHash := hex.EncodeToString(h.Sum(nil))
	if !strings.EqualFold(actualHash, expectedHash) {
		return fmt.Errorf("checksum mismatch: expected %s, got %s", expectedHash, actualHash)
	}
	return nil
}
