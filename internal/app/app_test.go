package app

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/CyberAuth/Aquatone-Revamped/v2/internal/model"
)

func TestRunEndToEndWithoutScreenshots(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("<title>Local fixture</title>"))
	}))
	defer server.Close()
	outDir := t.TempDir()
	var stdout, stderr bytes.Buffer
	code := Run([]string{"scan", "--out", outDir, "--screenshots=false", server.URL}, bytes.NewReader(nil), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit %d; stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	data, err := os.ReadFile(filepath.Join(outDir, "aquatone_session.json"))
	if err != nil {
		t.Fatal(err)
	}
	var session model.Session
	if err := json.Unmarshal(data, &session); err != nil {
		t.Fatal(err)
	}
	if len(session.Results) != 1 || session.Results[0].Title != "Local fixture" || session.Results[0].ScreenshotState != "skipped" {
		t.Fatalf("unexpected session: %#v", session.Results)
	}
	for _, name := range []string{"aquatone_report.html", "aquatone_results.jsonl", "aquatone_urls.txt"} {
		if _, err := os.Stat(filepath.Join(outDir, name)); err != nil {
			t.Errorf("missing %s: %v", name, err)
		}
	}
}

func TestRunReportCopiesArtifactsToAlternateOutput(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "source")
	destination := filepath.Join(root, "destination")
	if err := os.MkdirAll(filepath.Join(source, "screenshots"), 0o700); err != nil {
		t.Fatal(err)
	}
	artifact := filepath.Join("screenshots", "fixture.png")
	want := []byte("synthetic screenshot")
	if err := os.WriteFile(filepath.Join(source, artifact), want, 0o600); err != nil {
		t.Fatal(err)
	}
	session := model.Session{SchemaVersion: model.SchemaVersion, Results: []*model.Result{{URL: "https://example.test/", Artifacts: model.Artifacts{Screenshot: artifact}}}}
	data, err := json.Marshal(session)
	if err != nil {
		t.Fatal(err)
	}
	sessionPath := filepath.Join(source, "aquatone_session.json")
	if err := os.WriteFile(sessionPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := Run([]string{"report", "--session", sessionPath, "--out", destination}, bytes.NewReader(nil), &stdout, &stderr); code != 0 {
		t.Fatalf("exit %d; stderr=%s", code, stderr.String())
	}
	got, err := os.ReadFile(filepath.Join(destination, artifact))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("copied artifact = %q", got)
	}
	if _, err := os.Stat(filepath.Join(destination, "aquatone_report.html")); err != nil {
		t.Fatal(err)
	}
}

func TestRunRejectsExcessiveRateLimit(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"scan", "--rate-limit", "1000000001", "example.test"}, bytes.NewReader(nil), &stdout, &stderr)
	if code != 2 || !bytes.Contains(stderr.Bytes(), []byte("--rate-limit")) {
		t.Fatalf("exit %d; stderr=%s", code, stderr.String())
	}
}
