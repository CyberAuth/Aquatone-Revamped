package report

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/CyberAuth/Aquatone-Revamped/v2/internal/model"
)

func TestWriteCreatesSelfContainedSafeReport(t *testing.T) {
	destination := filepath.Join(t.TempDir(), "report.html")
	session := &model.Session{SchemaVersion: 2, Results: []*model.Result{{URL: "https://example.test/</script><script>alert(1)</script>", Title: "example"}}}
	if err := Write(session, destination); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(destination)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	if strings.Contains(text, "</script><script>alert(1)</script>") {
		t.Fatal("session data escaped its JSON script element")
	}
	if !strings.Contains(text, "Content-Security-Policy") || strings.Contains(text, "https://cdn.") {
		t.Fatal("report is missing its offline security policy")
	}
}

func TestLoadMigratesV1Session(t *testing.T) {
	path := filepath.Join(t.TempDir(), "v1.json")
	legacy := `{"version":"1.7.0","stats":{"requestSuccessful":1,"screenshotSuccessful":1},"pages":{"https://example.test/":{"uuid":"page-1","url":"https://example.test/","hostname":"example.test","status":"200 OK","pageTitle":"Legacy","hasScreenshot":true,"screenshotPath":"screenshots/legacy.png","tags":[{"text":"nginx","type":"info"}]}},"pageSimilarityClusters":{"abc":["page-1"]}}`
	if err := os.WriteFile(path, []byte(legacy), 0o600); err != nil {
		t.Fatal(err)
	}
	session, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(session.Results) != 1 || session.Results[0].StatusCode != 200 || len(session.Results[0].Technologies) != 1 {
		t.Fatalf("unexpected migrated result: %#v", session.Results)
	}
	if len(session.Clusters) != 1 || len(session.Clusters[0].Members) != 1 || session.Clusters[0].Members[0] != "https://example.test/" {
		t.Fatalf("unexpected migrated clusters: %#v", session.Clusters)
	}
}

func TestCopyArtifactsRejectsTraversal(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "source")
	destination := filepath.Join(root, "destination")
	if err := os.MkdirAll(source, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(destination, 0o700); err != nil {
		t.Fatal(err)
	}
	session := &model.Session{Results: []*model.Result{{Artifacts: model.Artifacts{Screenshot: "../secret"}}}}
	if err := CopyArtifacts(session, source, destination); err == nil {
		t.Fatal("path traversal was accepted")
	}
}
