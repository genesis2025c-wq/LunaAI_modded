package updater

import "time"

type Release struct {
	TagName     string    `json:"tag_name"`
	Name        string    `json:"name"`
	Body        string    `json:"body"`
	PublishedAt time.Time `json:"published_at"`
	Assets      []Asset   `json:"assets"`
}

type Asset struct {
	ID                 int    `json:"id"`
	Name               string `json:"name"`
	Size               int64  `json:"size"`
	BrowserDownloadURL string `json:"browser_download_url"`
}

type UpdateStatus struct {
	NewVersion bool    `json:"new_version"`
	Version    string  `json:"version"`
	Changelog  string  `json:"changelog"`
	AssetURL   string  `json:"asset_url"`
	Release    Release `json:"-"`
}
