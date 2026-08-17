package report

import (
	"crypto/sha256"
	"embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/CyberAuth/Aquatone-Revamped/v2/internal/model"
)

//go:embed assets/*
var assets embed.FS

type pageData struct {
	CSP  string
	CSS  template.CSS
	JS   template.JS
	Data template.JS
}

func Write(session *model.Session, destination string) error {
	htmlBytes, err := assets.ReadFile("assets/report.html")
	if err != nil {
		return err
	}
	css, err := assets.ReadFile("assets/report.css")
	if err != nil {
		return err
	}
	js, err := assets.ReadFile("assets/report.js")
	if err != nil {
		return err
	}
	data, err := json.Marshal(session)
	if err != nil {
		return err
	}
	csp := fmt.Sprintf("default-src 'none'; img-src 'self' data:; style-src 'sha256-%s'; script-src 'sha256-%s'; base-uri 'none'; form-action 'none'; object-src 'none'", digest(css), digest(js))
	tmpl, err := template.New("report").Parse(string(htmlBytes))
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(destination), ".aquatone-report-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	_ = tmp.Chmod(0o600)
	if err := tmpl.Execute(tmp, pageData{CSP: csp, CSS: template.CSS(css), JS: template.JS(js), Data: template.JS(data)}); err != nil {
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
	return os.Rename(tmpPath, destination)
}

func Load(path string) (*model.Session, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var probe struct {
		SchemaVersion int `json:"schemaVersion"`
	}
	if err := json.Unmarshal(data, &probe); err != nil {
		return nil, err
	}
	if probe.SchemaVersion >= 2 {
		var session model.Session
		if err := json.Unmarshal(data, &session); err != nil {
			return nil, err
		}
		return &session, nil
	}
	return loadV1(data)
}

// CopyArtifacts copies files referenced by a session when a report is rendered
// outside its original directory. Artifact paths are required to remain inside
// the source directory, including after resolving symbolic links.
func CopyArtifacts(session *model.Session, sourceDir, destinationDir string) error {
	sourceRoot, err := filepath.EvalSymlinks(sourceDir)
	if err != nil {
		return err
	}
	sourceRoot, err = filepath.Abs(sourceRoot)
	if err != nil {
		return err
	}
	destinationRoot, err := filepath.EvalSymlinks(destinationDir)
	if err != nil {
		return err
	}
	destinationRoot, err = filepath.Abs(destinationRoot)
	if err != nil {
		return err
	}
	if sourceRoot == destinationRoot {
		return nil
	}
	seen := map[string]bool{}
	for _, result := range session.Results {
		for _, artifact := range []string{result.Artifacts.Headers, result.Artifacts.Body, result.Artifacts.Screenshot} {
			if artifact == "" || seen[artifact] {
				continue
			}
			seen[artifact] = true
			if err := copyArtifact(sourceRoot, destinationRoot, artifact); err != nil {
				return err
			}
		}
	}
	return nil
}

func copyArtifact(sourceRoot, destinationRoot, artifact string) error {
	portable := strings.ReplaceAll(artifact, "\\", "/")
	if filepath.IsAbs(portable) {
		return fmt.Errorf("artifact path %q is absolute", artifact)
	}
	rel := filepath.Clean(filepath.FromSlash(portable))
	if rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return fmt.Errorf("artifact path %q escapes the session directory", artifact)
	}
	sourcePath, err := filepath.EvalSymlinks(filepath.Join(sourceRoot, rel))
	if err != nil {
		return fmt.Errorf("resolve artifact %q: %w", artifact, err)
	}
	inside, err := filepath.Rel(sourceRoot, sourcePath)
	if err != nil || inside == ".." || strings.HasPrefix(inside, ".."+string(filepath.Separator)) {
		return fmt.Errorf("artifact path %q resolves outside the session directory", artifact)
	}
	info, err := os.Stat(sourcePath)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("artifact path %q is not a regular file", artifact)
	}
	destinationPath := filepath.Join(destinationRoot, rel)
	if err := os.MkdirAll(filepath.Dir(destinationPath), 0o700); err != nil {
		return err
	}
	destinationParent, err := filepath.EvalSymlinks(filepath.Dir(destinationPath))
	if err != nil {
		return err
	}
	insideDestination, err := filepath.Rel(destinationRoot, destinationParent)
	if err != nil || insideDestination == ".." || strings.HasPrefix(insideDestination, ".."+string(filepath.Separator)) {
		return fmt.Errorf("artifact path %q resolves outside the destination directory", artifact)
	}
	input, err := os.Open(sourcePath)
	if err != nil {
		return err
	}
	defer input.Close()
	tmp, err := os.CreateTemp(filepath.Dir(destinationPath), ".aquatone-artifact-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := io.Copy(tmp, input); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpPath, destinationPath)
}

func digest(value []byte) string {
	hash := sha256.Sum256(value)
	return base64.StdEncoding.EncodeToString(hash[:])
}

type v1Session struct {
	Version string `json:"version"`
	Stats   struct {
		StartedAt            time.Time `json:"startedAt"`
		FinishedAt           time.Time `json:"finishedAt"`
		RequestSuccessful    int       `json:"requestSuccessful"`
		RequestFailed        int       `json:"requestFailed"`
		ScreenshotSuccessful int       `json:"screenshotSuccessful"`
		ScreenshotFailed     int       `json:"screenshotFailed"`
	} `json:"stats"`
	Pages map[string]struct {
		UUID           string         `json:"uuid"`
		URL            string         `json:"url"`
		Hostname       string         `json:"hostname"`
		Addrs          []string       `json:"addrs"`
		Status         string         `json:"status"`
		PageTitle      string         `json:"pageTitle"`
		HeadersPath    string         `json:"headersPath"`
		BodyPath       string         `json:"bodyPath"`
		ScreenshotPath string         `json:"screenshotPath"`
		HasScreenshot  bool           `json:"hasScreenshot"`
		Headers        []model.Header `json:"headers"`
		Tags           []struct {
			Text string `json:"text"`
			Type string `json:"type"`
		} `json:"tags"`
	} `json:"pages"`
	Clusters map[string][]string `json:"pageSimilarityClusters"`
}

func loadV1(data []byte) (*model.Session, error) {
	var old v1Session
	if err := json.Unmarshal(data, &old); err != nil {
		return nil, err
	}
	session := &model.Session{
		SchemaVersion: model.SchemaVersion,
		Tool:          model.ToolInfo{Name: "aquatone", Version: old.Version},
		StartedAt:     old.Stats.StartedAt, FinishedAt: old.Stats.FinishedAt,
		Stats: model.Stats{Targets: len(old.Pages), RequestsSuccessful: old.Stats.RequestSuccessful, RequestsFailed: old.Stats.RequestFailed, ScreenshotsSuccessful: old.Stats.ScreenshotSuccessful, ScreenshotsFailed: old.Stats.ScreenshotFailed},
	}
	keys := make([]string, 0, len(old.Pages))
	for key := range old.Pages {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	legacyIDs := make(map[string]string, len(old.Pages))
	for _, key := range keys {
		page := old.Pages[key]
		result := &model.Result{Input: page.URL, URL: page.URL, FinalURL: page.URL, Hostname: page.Hostname, Status: page.Status, Title: page.PageTitle, IPs: page.Addrs, Headers: page.Headers}
		if fields := strings.Fields(page.Status); len(fields) > 0 {
			result.StatusCode, _ = strconv.Atoi(fields[0])
		}
		for _, tag := range page.Tags {
			if tag.Type == "info" && tag.Text != "" {
				result.Technologies = append(result.Technologies, tag.Text)
			}
		}
		sort.Strings(result.Technologies)
		result.Artifacts = model.Artifacts{Headers: page.HeadersPath, Body: page.BodyPath, Screenshot: page.ScreenshotPath}
		if page.HasScreenshot {
			result.ScreenshotState = "ok"
		} else {
			result.ScreenshotState = "failed"
		}
		session.Results = append(session.Results, result)
		legacyIDs[key] = page.URL
		if page.UUID != "" {
			legacyIDs[page.UUID] = page.URL
		}
	}
	clusterKeys := make([]string, 0, len(old.Clusters))
	for key := range old.Clusters {
		clusterKeys = append(clusterKeys, key)
	}
	sort.Strings(clusterKeys)
	for i, key := range clusterKeys {
		members := make([]string, 0, len(old.Clusters[key]))
		for _, member := range old.Clusters[key] {
			if migrated, ok := legacyIDs[member]; ok {
				members = append(members, migrated)
			} else {
				members = append(members, member)
			}
		}
		sort.Strings(members)
		session.Clusters = append(session.Clusters, model.Cluster{ID: fmt.Sprintf("legacy-%03d", i+1), Members: members})
	}
	return session, nil
}
