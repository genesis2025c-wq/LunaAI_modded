//go:build windows || darwin

package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/google/uuid"
	"github.com/ollama/ollama/app/logrotate"
	"github.com/ollama/ollama/app/server"
	"github.com/ollama/ollama/app/store"
	"github.com/ollama/ollama/app/tools"
	"github.com/ollama/ollama/app/ui"
	"github.com/ollama/ollama/app/updater"
	"github.com/ollama/ollama/app/version"
)

var (
	wv           = &Webview{}
	uiServerPort int
)

var debug = strings.EqualFold(os.Getenv("OLLAMA_DEBUG"), "true") || os.Getenv("OLLAMA_DEBUG") == "1"

var (
	fastStartup = false
	devMode     = false
)

type appMove int

const (
	CannotMove appMove = iota
	UserDeclinedMove
	MoveCompleted
	AlreadyMoved
	LoginSession
	PermissionDenied
	MoveError
)

func main() {
	startHidden := false
	var urlSchemeRequest string
	if len(os.Args) > 1 {
		for _, arg := range os.Args {
			if strings.HasPrefix(arg, "luna://") {
				urlSchemeRequest = arg
				continue
			}
			switch arg {
			case "--fast-startup":
				fastStartup = true
			case "-dev", "--dev":
				devMode = true
			case "hidden", "-j", "--hide":
				startHidden = true
			}
		}
	}

	level := slog.LevelInfo
	if debug {
		level = slog.LevelDebug
	}

	logrotate.Rotate(appLogPath)
	if _, err := os.Stat(filepath.Dir(appLogPath)); errors.Is(err, os.ErrNotExist) {
		os.MkdirAll(filepath.Dir(appLogPath), 0o755)
	}

	logFile, err := os.OpenFile(appLogPath, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o755)
	if err == nil {
		slog.SetDefault(slog.New(slog.NewTextHandler(logFile, &slog.HandlerOptions{Level: level})))
	}

	logStartup()

	// Enable the new auto-updater
	updater.UpdateCheckURLBase = "" // Disable legacy
	if _, err := os.Stat(updater.UpgradeMarkerFile); err == nil {
		updater.DoPostUpgradeCleanup()
		startHidden = true
	}

	handleExistingInstance(startHidden)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return
	}
	port := ln.Addr().(*net.TCPAddr).Port
	token := uuid.NewString()
	wv.port = port
	wv.token = token
	uiServerPort = port

	st := &store.Store{}
	toolRegistry := tools.NewRegistry()
	ctx, cancel := context.WithCancel(context.Background())
	octx, ocancel := context.WithCancel(ctx)

	wv.Store = st
	done := make(chan error, 1)
	osrv := server.New(st, devMode)
	go func() {
		done <- osrv.Run(octx)
	}()

	uiServer := ui.Server{
		Token: token,
		Restart: func() {
			ocancel()
			<-done
			octx, ocancel = context.WithCancel(ctx)
			go func() { done <- osrv.Run(octx) }()
		},
		Store:        st,
		ToolRegistry: toolRegistry,
		Dev:          devMode,
		Logger:       slog.Default(),
		Updater:      updater.DefaultUpdater,
	}

	srv := &http.Server{Handler: uiServer.Handler()}
	go srv.Serve(ln)

	if urlSchemeRequest != "" {
		go handleURLSchemeInCurrentInstance(urlSchemeRequest)
	}

	osRun(cancel, true, startHidden)
	srv.Close()
	cancel()
	<-done
}

func startHiddenTasks() {
	if updater.IsUpdatePending() {
		if !fastStartup {
			if err := updater.DoUpgradeAtStartup(); err == nil {
				os.Exit(0)
			}
		}
	}
}

func parseURLScheme(urlSchemeRequest string) (isConnect bool, err error) {
	parsedURL, err := url.Parse(urlSchemeRequest)
	if err != nil {
		return false, fmt.Errorf("invalid URL: %w", err)
	}
	if parsedURL.Host == "connect" || strings.TrimPrefix(parsedURL.Path, "/") == "connect" {
		return true, nil
	}
	return false, nil
}

func handleURLSchemeInCurrentInstance(urlSchemeRequest string) {
	isConnect, err := parseURLScheme(urlSchemeRequest)
	if err != nil {
		return
	}
	if isConnect {
		handleConnectURLScheme()
	} else {
		if wv.IsRunning() {
			// Show window logic is platform specific and handled in wv.Run usually
		}
	}
}

func handleConnectURLScheme() {
	openInBrowser("https://luna-ai.com/connect")
}

func openInBrowser(url string) {
	var cmd string
	var args []string
	switch runtime.GOOS {
	case "windows":
		cmd = "rundll32"
		args = []string{"url.dll,FileProtocolHandler", url}
	case "darwin":
		cmd = "open"
		args = []string{url}
	}
	exec.Command(cmd, args...).Start()
}

func logStartup() {
	slog.Info("starting Luna AI", "version", version.Version)
}
