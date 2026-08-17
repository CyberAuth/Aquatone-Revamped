package cluster

import (
	"testing"

	"github.com/CyberAuth/Aquatone-Revamped/v2/internal/model"
)

func TestBuildClustersSimilarCapturesDeterministically(t *testing.T) {
	results := []*model.Result{
		{URL: "https://b.test/", ScreenshotState: "ok", ScreenshotHash: "0000000000000001"},
		{URL: "https://a.test/", ScreenshotState: "ok", ScreenshotHash: "0000000000000000"},
		{URL: "https://c.test/", ScreenshotState: "ok", ScreenshotHash: "ffffffffffffffff"},
	}
	clusters := Build(results, 0.95)
	if len(clusters) != 2 {
		t.Fatalf("got %#v", clusters)
	}
	if len(clusters[0].Members) != 2 || clusters[0].Members[0] != "https://a.test/" {
		t.Fatalf("unexpected cluster order: %#v", clusters)
	}
}
