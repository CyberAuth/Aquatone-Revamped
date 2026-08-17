package version

import (
	"runtime"

	"github.com/CyberAuth/Aquatone-Revamped/v2/internal/browser"
	"github.com/CyberAuth/Aquatone-Revamped/v2/internal/model"
)

var (
	Version = "2.0.0-dev"
	Commit  = "unknown"
)

func Info() model.ToolInfo {
	return model.ToolInfo{
		Name: "Aquatone Revamped", Version: Version, Commit: Commit,
		GoVersion: runtime.Version(), OS: runtime.GOOS, Arch: runtime.GOARCH,
		BrowserRevision: browser.Revision,
	}
}
