package ports

import "testing"

func TestParseSchemesRangesAndDeduplication(t *testing.T) {
	got, err := Parse("https:443,http:8000-8001,https:443")
	if err != nil {
		t.Fatal(err)
	}
	want := []Spec{{Port: 443, Scheme: "https"}, {Port: 8000, Scheme: "http"}, {Port: 8001, Scheme: "http"}}
	if len(got) != len(want) {
		t.Fatalf("got %#v, want %#v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %#v, want %#v", got, want)
		}
	}
}

func TestParseRejectsUnsafeRanges(t *testing.T) {
	for _, value := range []string{"0", "65536", "1-5000", "ftp:21", "nope"} {
		if _, err := Parse(value); err == nil {
			t.Errorf("Parse(%q) unexpectedly succeeded", value)
		}
	}
}
