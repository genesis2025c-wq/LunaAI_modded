package updater

import (
	"log/slog"
	"os"
	"path/filepath"
)

var (
	VerifyDownload     func() error
	Installer          string
	UpdateStageDir     string
	UpgradeLogFile     string
	UpgradeMarkerFile  string
	UserAgentOS        string
	UpdateCheckURLBase string
)

func cleanupOldDownloads(dir string) {
	slog.Debug("cleaning up old downloads", "dir", dir)
	os.RemoveAll(dir)
}

func init() {
	// Initialize defaults for the rest of the package
	localAppData := os.Getenv("LOCALAPPDATA")
	appDataDir := filepath.Join(localAppData, "OllamaModded")
	UpdateStageDir = filepath.Join(appDataDir, "updates")
	UpgradeLogFile = filepath.Join(appDataDir, "upgrade.log")
	UpgradeMarkerFile = filepath.Join(appDataDir, "upgraded")
	UserAgentOS = "LunaAI"
}
