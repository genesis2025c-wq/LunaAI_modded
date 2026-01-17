//go:build windows || darwin

package main

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/uuid"
	"github.com/ollama/ollama/app/logrotate"
	"github.com/ollama/ollama/app/server"
	"github.com/ollama/ollama/app/store"
	"github.com/ollama/ollama/app/tools"
	"github.com/ollama/ollama/app/ui"
	"github.com/ollama/ollama/app/updater"
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

	osRun(cancel, true, startHidden)
	srv.Close()
	cancel()
	<-done
}
