package browser

import (
	"context"
	"image"
	"image/color"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/CyberAuth/Aquatone-Revamped/v2/internal/model"
	"github.com/CyberAuth/Aquatone-Revamped/v2/internal/output"
)

func TestBlankImageDetection(t *testing.T) {
	blank := image.NewRGBA(image.Rect(0, 0, 100, 100))
	if !isBlank(blank) {
		t.Fatal("uniform image should be blank")
	}
	blank.Set(50, 50, color.White)
	if isBlank(blank) {
		t.Fatal("high-contrast image should not be blank")
	}
}

func TestSystemBrowserCapture(t *testing.T) {
	if os.Getenv("AQUATONE_BROWSER_TEST") == "" {
		t.Skip("set AQUATONE_BROWSER_TEST=1 to exercise an installed browser")
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><head><title>Darwin capture</title><style>body{background:linear-gradient(135deg,#07203c,#16d5b5);color:white;font:48px sans-serif}</style></head><body>Aquatone Revamped</body></html>`))
	}))
	defer server.Close()
	writer, err := output.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	manager, err := New(context.Background(), Options{UseSystem: true, Viewport: "900,600", Timeout: 20 * time.Second, Quiet: 100 * time.Millisecond, Settle: 100 * time.Millisecond}, writer)
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	result := &model.Result{URL: server.URL, FinalURL: server.URL, Hostname: "127.0.0.1"}
	capture, err := manager.Capture(context.Background(), result)
	if err != nil {
		t.Fatal(err)
	}
	if capture.Blank || capture.Hash == "" || result.Artifacts.Screenshot == "" {
		t.Fatalf("unexpected capture: %#v, result: %#v", capture, result)
	}
}

func TestParseViewport(t *testing.T) {
	if width, height, err := parseViewport("1440x900"); err != nil || width != 1440 || height != 900 {
		t.Fatalf("got %d x %d, %v", width, height, err)
	}
	if _, _, err := parseViewport("10,10"); err == nil {
		t.Fatal("undersized viewport accepted")
	}
}
