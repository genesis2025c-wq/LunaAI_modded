//go:build windows || darwin

package main

import (
	"fmt"
	"sync"
	"unsafe"

	"github.com/ollama/ollama/app/store"
	"github.com/ollama/ollama/app/webview"
)

type Webview struct {
	port    int
	token   string
	webview webview.WebView
	mutex   sync.Mutex

	Store *store.Store
}

func (w *Webview) Run(path string) unsafe.Pointer {
	url := fmt.Sprintf("http://127.0.0.1:%d%s", w.port, path)
	w.mutex.Lock()
	defer w.mutex.Unlock()

	if w.webview == nil {
		wv := webview.New(debug)
		w.webview = wv
		w.webview.Navigate(url)
	}
	return w.webview.Window()
}

func (w *Webview) Terminate() {
	w.mutex.Lock()
	defer w.mutex.Unlock()
	if w.webview != nil {
		w.webview.Terminate()
		w.webview = nil
	}
}

func (w *Webview) IsRunning() bool {
	w.mutex.Lock()
	defer w.mutex.Unlock()
	return w.webview != nil
}
