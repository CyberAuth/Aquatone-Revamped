package output

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"github.com/CyberAuth/Aquatone-Revamped/v2/internal/model"
)

type Writer struct {
	Dir   string
	mu    sync.Mutex
	jsonl *os.File
	urls  *os.File
}

var unsafeName = regexp.MustCompile(`[^a-zA-Z0-9._-]+`)

func New(dir string) (*Writer, error) {
	dir, err := filepath.Abs(filepath.Clean(dir))
	if err != nil {
		return nil, err
	}
	for _, path := range []string{dir, filepath.Join(dir, "headers"), filepath.Join(dir, "html"), filepath.Join(dir, "screenshots")} {
		if err := os.MkdirAll(path, 0o700); err != nil {
			return nil, fmt.Errorf("create output directory %s: %w", path, err)
		}
		_ = os.Chmod(path, 0o700)
	}
	jsonl, err := os.OpenFile(filepath.Join(dir, "aquatone_results.jsonl"), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return nil, err
	}
	if err := jsonl.Chmod(0o600); err != nil {
		_ = jsonl.Close()
		return nil, err
	}
	urls, err := os.OpenFile(filepath.Join(dir, "aquatone_urls.txt"), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		_ = jsonl.Close()
		return nil, err
	}
	if err := urls.Chmod(0o600); err != nil {
		_ = jsonl.Close()
		_ = urls.Close()
		return nil, err
	}
	return &Writer{Dir: dir, jsonl: jsonl, urls: urls}, nil
}

func (w *Writer) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	var first error
	for _, file := range []*os.File{w.jsonl, w.urls} {
		if file != nil {
			if err := file.Close(); err != nil && first == nil {
				first = err
			}
		}
	}
	return first
}

func (w *Writer) BaseName(rawURL, hostname string) string {
	hash := sha256.Sum256([]byte(rawURL))
	host := strings.Trim(unsafeName.ReplaceAllString(strings.ToLower(hostname), "_"), "_.")
	if host == "" {
		host = "target"
	}
	return fmt.Sprintf("%s_%s", host, hex.EncodeToString(hash[:8]))
}

func (w *Writer) WriteHeaders(base, status string, headers []model.Header) (string, error) {
	rel := filepath.Join("headers", base+".txt")
	var body strings.Builder
	body.WriteString(status)
	body.WriteByte('\n')
	for _, header := range headers {
		fmt.Fprintf(&body, "%s: %s\n", header.Name, header.Value)
	}
	return rel, writePrivate(filepath.Join(w.Dir, rel), []byte(body.String()))
}

func (w *Writer) WriteBody(base string, body []byte) (string, error) {
	rel := filepath.Join("html", base+".html")
	return rel, writePrivate(filepath.Join(w.Dir, rel), body)
}

func (w *Writer) WriteScreenshot(base string, data []byte) (string, error) {
	rel := filepath.Join("screenshots", base+".png")
	return rel, writePrivate(filepath.Join(w.Dir, rel), data)
}

func writePrivate(path string, data []byte) error {
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return err
	}
	return os.Chmod(path, 0o600)
}

func (w *Writer) Record(result *model.Result) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	encoded, err := json.Marshal(result)
	if err != nil {
		return err
	}
	if _, err := w.jsonl.Write(append(encoded, '\n')); err != nil {
		return err
	}
	if result.StatusCode > 0 {
		if _, err := fmt.Fprintln(w.urls, result.FinalURL); err != nil {
			return err
		}
	}
	return nil
}

func (w *Writer) SaveSession(session *model.Session) error {
	data, err := json.MarshalIndent(session, "", "  ")
	if err != nil {
		return err
	}
	return atomicWrite(filepath.Join(w.Dir, "aquatone_session.json"), append(data, '\n'), 0o600)
}

func atomicWrite(path string, data []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".aquatone-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return err
	}
	buffered := bufio.NewWriter(tmp)
	if _, err := buffered.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := buffered.Flush(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpPath, path)
}
