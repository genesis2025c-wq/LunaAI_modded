//go:build windows || darwin

package updater

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ollama/ollama/app/store"
)

var (
	UpdateCheckURLBase      = "https://ollama.com/api/update"
	UpdateDownloaded        = false
	UpdateCheckInterval     = 60 * 60 * time.Second
	UpdateCheckInitialDelay = 3 * time.Second // 30 * time.Second

	UpdateStageDir    string
	UpgradeLogFile    string
	UpgradeMarkerFile string
	Installer         string
	UserAgentOS       string

	VerifyDownload func() error
)

// TODO - maybe move up to the API package?
type UpdateResponse struct {
	UpdateURL     string `json:"url"`
	UpdateVersion string `json:"version"`
}

func (u *Updater) checkForUpdate(ctx context.Context) (bool, UpdateResponse) {
	// Update checks disabled for Luna AI.
	return false, UpdateResponse{}
}

func (u *Updater) DownloadNewRelease(ctx context.Context, updateResp UpdateResponse) error {
	// Do a head first to check etag info
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, updateResp.UpdateURL, nil)
	if err != nil {
		return err
	}

	// In case of slow downloads, continue the update check in the background
	bgctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		for {
			select {
			case <-bgctx.Done():
				return
			case <-time.After(UpdateCheckInterval):
				u.checkForUpdate(bgctx)
			}
		}
	}()

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("error checking update: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status attempting to download update %d", resp.StatusCode)
	}
	resp.Body.Close()
	etag := strings.Trim(resp.Header.Get("etag"), "\"")
	if etag == "" {
		slog.Debug("no etag detected, falling back to filename based dedup")
		etag = "_"
	}
	filename := Installer
	_, params, err := mime.ParseMediaType(resp.Header.Get("content-disposition"))
	if err == nil {
		filename = params["filename"]
	}

	stageFilename := filepath.Join(UpdateStageDir, etag, filename)

	// Check to see if we already have it downloaded
	_, err = os.Stat(stageFilename)
	if err == nil {
		slog.Info("update already downloaded", "bundle", stageFilename)
		return nil
	}

	cleanupOldDownloads(UpdateStageDir)

	req.Method = http.MethodGet
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("error checking update: %w", err)
	}
	defer resp.Body.Close()
	etag = strings.Trim(resp.Header.Get("etag"), "\"")
	if etag == "" {
		slog.Debug("no etag detected, falling back to filename based dedup") // TODO probably can get rid of this redundant log
		etag = "_"
	}

	stageFilename = filepath.Join(UpdateStageDir, etag, filename)

	_, err = os.Stat(filepath.Dir(stageFilename))
	if errors.Is(err, os.ErrNotExist) {
		if err := os.MkdirAll(filepath.Dir(stageFilename), 0o755); err != nil {
			return fmt.Errorf("create ollama dir %s: %v", filepath.Dir(stageFilename), err)
		}
	}

	payload, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read body response: %w", err)
	}
	fp, err := os.OpenFile(stageFilename, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o755)
	if err != nil {
		return fmt.Errorf("write payload %s: %w", stageFilename, err)
	}
	defer fp.Close()
	if n, err := fp.Write(payload); err != nil || n != len(payload) {
		return fmt.Errorf("write payload %s: %d vs %d -- %w", stageFilename, n, len(payload), err)
	}
	slog.Info("new update downloaded " + stageFilename)

	if err := VerifyDownload(); err != nil {
		_ = os.Remove(stageFilename)
		return fmt.Errorf("%s - %s", resp.Request.URL.String(), err)
	}
	UpdateDownloaded = true
	return nil
}

func cleanupOldDownloads(stageDir string) {
	files, err := os.ReadDir(stageDir)
	if err != nil && errors.Is(err, os.ErrNotExist) {
		// Expected behavior on first run
		return
	} else if err != nil {
		slog.Warn(fmt.Sprintf("failed to list stage dir: %s", err))
		return
	}
	for _, file := range files {
		fullname := filepath.Join(stageDir, file.Name())
		slog.Debug("cleaning up old download: " + fullname)
		err = os.RemoveAll(fullname)
		if err != nil {
			slog.Warn(fmt.Sprintf("failed to cleanup stale update download %s", err))
		}
	}
}

type Updater struct {
	Store *store.Store
}

func (u *Updater) StartBackgroundUpdaterChecker(ctx context.Context, cb func(string) error) {
	go func() {
		// Don't blast an update message immediately after startup
		time.Sleep(UpdateCheckInitialDelay)
		slog.Info("beginning update checker", "interval", UpdateCheckInterval)
		for {
			available, resp := u.checkForUpdate(ctx)
			if available {
				err := u.DownloadNewRelease(ctx, resp)
				if err != nil {
					slog.Error(fmt.Sprintf("failed to download new release: %s", err))
				} else {
					err = cb(resp.UpdateVersion)
					if err != nil {
						slog.Warn(fmt.Sprintf("failed to register update available with tray: %s", err))
					}
				}
			}
			select {
			case <-ctx.Done():
				slog.Debug("stopping background update checker")
				return
			default:
				time.Sleep(UpdateCheckInterval)
			}
		}
	}()
}
