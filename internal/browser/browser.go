package browser

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"image"
	"image/color"
	_ "image/png"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/CyberAuth/Aquatone-Revamped/v2/internal/model"
	"github.com/CyberAuth/Aquatone-Revamped/v2/internal/output"
	"github.com/corona10/goimagehash"
	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/launcher"
	"github.com/go-rod/rod/lib/proto"
)

const Revision = launcher.RevisionDefault

type Options struct {
	BrowserPath string
	UseSystem   bool
	Proxy       string
	Headers     []string
	Viewport    string
	FullPage    bool
	Timeout     time.Duration
	Quiet       time.Duration
	Settle      time.Duration
	Logger      io.Writer
}

type Manager struct {
	options Options
	writer  *output.Writer
	engine  *rod.Browser
	launch  *launcher.Launcher
	tempDir string
	binPath string
	mu      sync.Mutex
}

type Capture struct {
	Hash     string
	Blank    bool
	FinalURL string
}

func CacheRoot() string {
	root, err := os.UserCacheDir()
	if err != nil || root == "" {
		root = os.TempDir()
	}
	return filepath.Join(root, "aquatone-revamped", "browser")
}

func ManagedPath() string {
	b := launcher.NewBrowser()
	b.Revision = Revision
	b.RootDir = CacheRoot()
	return b.BinPath()
}

func Install(ctx context.Context, logger io.Writer) (string, error) {
	b := launcher.NewBrowser()
	b.Context = ctx
	b.Revision = Revision
	b.RootDir = CacheRoot()
	if logger == nil {
		logger = io.Discard
	}
	b.Logger = newLineLogger(logger)
	path, err := b.Get()
	if err != nil {
		return "", err
	}
	if err := recordOrVerifyChecksum(path); err != nil {
		return "", err
	}
	return path, nil
}

func Status() (string, bool, error) {
	path := ManagedPath()
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return path, false, nil
		}
		return path, false, err
	}
	if err := recordOrVerifyChecksum(path); err != nil {
		return path, false, err
	}
	return path, true, nil
}

func Clean() error {
	root := filepath.Clean(CacheRoot())
	base := filepath.Base(root)
	if base != "browser" || !strings.Contains(root, "aquatone-revamped") {
		return fmt.Errorf("refusing to remove unexpected cache path %q", root)
	}
	return os.RemoveAll(root)
}

func New(ctx context.Context, options Options, writer *output.Writer) (*Manager, error) {
	if options.Timeout <= 0 {
		options.Timeout = 30 * time.Second
	}
	if options.Quiet <= 0 {
		options.Quiet = 750 * time.Millisecond
	}
	if options.Settle <= 0 {
		options.Settle = time.Second
	}
	bin := options.BrowserPath
	if bin == "" && options.UseSystem {
		var found bool
		bin, found = launcher.LookPath()
		if !found {
			return nil, fmt.Errorf("no installed Chrome, Chromium, or Edge browser found")
		}
	}
	if bin == "" {
		var err error
		bin, err = Install(ctx, options.Logger)
		if err != nil {
			return nil, fmt.Errorf("install managed browser: %w", err)
		}
	}
	if _, err := os.Stat(bin); err != nil {
		return nil, fmt.Errorf("browser path %s: %w", bin, err)
	}
	tempDir, err := os.MkdirTemp("", "aquatone-browser-*")
	if err != nil {
		return nil, err
	}
	width, height, err := parseViewport(options.Viewport)
	if err != nil {
		_ = os.RemoveAll(tempDir)
		return nil, err
	}
	l := launcher.New().
		Context(ctx).
		Bin(bin).
		Leakless(true).
		Headless(true).
		UserDataDir(tempDir).
		Set("window-size", fmt.Sprintf("%d,%d", width, height)).
		Set("ignore-certificate-errors").
		Set("hide-scrollbars").
		Set("mute-audio").
		Set("disable-notifications").
		Set("disable-background-networking")
	if options.Proxy != "" {
		l.Proxy(options.Proxy)
	}
	controlURL, err := l.Launch()
	if err != nil {
		_ = os.RemoveAll(tempDir)
		return nil, fmt.Errorf("launch browser: %w", err)
	}
	engine := rod.New().ControlURL(controlURL).Context(ctx)
	if err := engine.Connect(); err != nil {
		l.Kill()
		_ = os.RemoveAll(tempDir)
		return nil, fmt.Errorf("connect browser: %w", err)
	}
	return &Manager{options: options, writer: writer, engine: engine, launch: l, tempDir: tempDir, binPath: bin}, nil
}

func (m *Manager) Close() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.engine != nil {
		_ = m.engine.Close()
		m.engine = nil
	}
	if m.launch != nil {
		m.launch.Kill()
		m.launch = nil
	}
	if m.tempDir != "" {
		_ = os.RemoveAll(m.tempDir)
	}
}

func (m *Manager) Capture(ctx context.Context, result *model.Result) (Capture, error) {
	first, data, err := m.captureOnce(ctx, result.FinalURL, m.options.Settle)
	if err == nil && !first.Blank {
		return first, m.write(result, data)
	}
	secondSettle := 3 * time.Second
	second, data, retryErr := m.captureOnce(ctx, result.FinalURL, secondSettle)
	if retryErr != nil {
		if err != nil {
			return Capture{}, fmt.Errorf("initial capture: %v; retry: %w", err, retryErr)
		}
		return Capture{}, retryErr
	}
	return second, m.write(result, data)
}

func (m *Manager) captureOnce(ctx context.Context, rawURL string, settle time.Duration) (Capture, []byte, error) {
	deadlineCtx, cancel := context.WithTimeout(ctx, m.options.Timeout)
	defer cancel()
	incognito, err := m.engine.Incognito()
	if err != nil {
		return Capture{}, nil, err
	}
	defer incognito.Close()
	page, err := incognito.Page(proto.TargetCreateTarget{URL: "about:blank"})
	if err != nil {
		return Capture{}, nil, err
	}
	page = page.Context(deadlineCtx)
	defer page.Close()
	go page.EachEvent(func(*proto.PageJavascriptDialogOpening) {
		_ = proto.PageHandleJavaScriptDialog{Accept: true}.Call(page)
	})()
	if len(m.options.Headers) > 0 {
		cleanup, headerErr := page.SetExtraHeaders(m.options.Headers)
		if headerErr != nil {
			return Capture{}, nil, headerErr
		}
		defer cleanup()
	}
	if err := page.Navigate(rawURL); err != nil {
		return Capture{}, nil, err
	}
	if err := page.WaitLoad(); err != nil {
		return Capture{}, nil, err
	}
	_ = page.WaitIdle(m.options.Quiet)
	select {
	case <-time.After(settle):
	case <-deadlineCtx.Done():
		return Capture{}, nil, deadlineCtx.Err()
	}
	data, err := page.Screenshot(m.options.FullPage, &proto.PageCaptureScreenshot{Format: proto.PageCaptureScreenshotFormatPng})
	if err != nil {
		return Capture{}, nil, err
	}
	decoded, _, err := image.Decode(bytes.NewReader(data))
	if err != nil {
		return Capture{}, nil, fmt.Errorf("decode screenshot: %w", err)
	}
	hash, err := goimagehash.PerceptionHash(decoded)
	if err != nil {
		return Capture{}, nil, err
	}
	info, _ := page.Info()
	finalURL := rawURL
	if info != nil && info.URL != "" {
		finalURL = info.URL
	}
	return Capture{Hash: fmt.Sprintf("%016x", hash.GetHash()), Blank: isBlank(decoded), FinalURL: finalURL}, data, nil
}

func (m *Manager) write(result *model.Result, data []byte) error {
	base := m.writer.BaseName(result.URL, result.Hostname)
	rel, err := m.writer.WriteScreenshot(base, data)
	if err != nil {
		return err
	}
	result.Artifacts.Screenshot = rel
	return nil
}

func isBlank(img image.Image) bool {
	bounds := img.Bounds()
	if bounds.Dx() < 16 || bounds.Dy() < 16 {
		return true
	}
	stepX := max(1, bounds.Dx()/64)
	stepY := max(1, bounds.Dy()/64)
	var count int
	var sum, sumSq float64
	for y := bounds.Min.Y; y < bounds.Max.Y; y += stepY {
		for x := bounds.Min.X; x < bounds.Max.X; x += stepX {
			gray := color.GrayModel.Convert(img.At(x, y)).(color.Gray).Y
			value := float64(gray)
			sum += value
			sumSq += value * value
			count++
		}
	}
	mean := sum / float64(count)
	variance := sumSq/float64(count) - mean*mean
	return variance < 2.0
}

func parseViewport(value string) (int, int, error) {
	if value == "" {
		value = "1440,900"
	}
	parts := strings.FieldsFunc(value, func(r rune) bool { return r == ',' || r == 'x' || r == 'X' })
	if len(parts) != 2 {
		return 0, 0, fmt.Errorf("viewport must be WIDTH,HEIGHT")
	}
	width, err := strconv.Atoi(parts[0])
	if err != nil || width < 320 || width > 10000 {
		return 0, 0, fmt.Errorf("viewport width must be 320-10000")
	}
	height, err := strconv.Atoi(parts[1])
	if err != nil || height < 200 || height > 30000 {
		return 0, 0, fmt.Errorf("viewport height must be 200-30000")
	}
	return width, height, nil
}

type lineLogger struct{ writer io.Writer }

func newLineLogger(writer io.Writer) *lineLogger { return &lineLogger{writer: writer} }
func (l *lineLogger) Printf(format string, values ...interface{}) {
	fmt.Fprintf(l.writer, format, values...)
}
func (l *lineLogger) Println(values ...interface{}) {
	fmt.Fprintln(l.writer, values...)
}

func recordOrVerifyChecksum(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		_ = file.Close()
		return err
	}
	_ = file.Close()
	digest := hex.EncodeToString(hash.Sum(nil))
	checksumPath := path + ".sha256"
	if existing, err := os.ReadFile(checksumPath); err == nil {
		if strings.TrimSpace(string(existing)) != digest {
			return fmt.Errorf("managed browser checksum mismatch; run 'aquatone browser clean' and retry")
		}
		return nil
	}
	return os.WriteFile(checksumPath, []byte(digest+"\n"), 0o600)
}
