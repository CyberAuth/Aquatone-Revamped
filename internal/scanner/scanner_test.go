package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	inputparser "github.com/CyberAuth/Aquatone-Revamped/v2/internal/input"
	"github.com/CyberAuth/Aquatone-Revamped/v2/internal/output"
)

func TestDirectURLScan(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "aquatone-test")
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<!doctype html><title>  Test   Page </title><h1>Hello</h1>"))
	}))
	defer server.Close()

	writer, err := output.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	s, err := New(Options{Concurrency: 2, ConnectTimeout: time.Second, HTTPTimeout: 2 * time.Second, MaxBodyBytes: 1024, FollowRedirects: true, MaxRedirects: 3, UserAgent: "aquatone-test"}, writer)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	endpoints := s.Discover(context.Background(), []inputparser.Target{{Input: server.URL, URL: server.URL}})
	if len(endpoints) != 1 {
		t.Fatalf("got %d endpoints", len(endpoints))
	}
	results := s.Scan(context.Background(), endpoints, nil)
	if len(results) != 1 || results[0].StatusCode != http.StatusOK {
		t.Fatalf("got %#v", results)
	}
	if results[0].Title != "Test Page" || results[0].Artifacts.Headers == "" {
		t.Fatalf("unexpected result: %#v", results[0])
	}
}

func TestCustomHostHeaderUsesRequestHost(t *testing.T) {
	received := make(chan string, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received <- r.Host
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	writer, err := output.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	s, err := New(Options{Concurrency: 1, ConnectTimeout: time.Second, HTTPTimeout: time.Second, Headers: http.Header{"Host": {"virtual.example"}}, MaxRedirects: 1}, writer)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	results := s.Scan(context.Background(), []Endpoint{{Input: server.URL, URL: server.URL}}, nil)
	if len(results) != 1 || results[0].StatusCode != http.StatusNoContent {
		t.Fatalf("unexpected results: %#v", results)
	}
	if got := <-received; got != "virtual.example" {
		t.Fatalf("Host = %q", got)
	}
}

func TestNewRejectsRateLimitWithZeroTickerInterval(t *testing.T) {
	_, err := New(Options{RateLimit: int(time.Second) + 1}, nil)
	if err == nil || !strings.Contains(err.Error(), "rate limit") {
		t.Fatalf("unexpected error: %v", err)
	}
}
