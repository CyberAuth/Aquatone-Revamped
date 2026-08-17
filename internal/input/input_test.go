package input

import (
	"strings"
	"testing"
)

func TestParseTextExtractsAndNormalizes(t *testing.T) {
	targets, err := Parse(strings.NewReader("Example.COM\nhttps://Example.com/path#fragment\n192.0.2.5\nserver01\ninvalid_word\n"), "text")
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 4 {
		t.Fatalf("got %#v", targets)
	}
	var foundURL bool
	for _, target := range targets {
		if target.URL == "https://example.com/path" {
			foundURL = true
		}
	}
	if !foundURL {
		t.Fatalf("normalized URL missing from %#v", targets)
	}
}

func TestParseNmapOnlyUsesOpenHTTPServices(t *testing.T) {
	xml := `<?xml version="1.0"?><nmaprun><host><status state="up"/><address addr="192.0.2.10" addrtype="ipv4"/><ports><port portid="443"><state state="open"/><service name="https" tunnel="ssl"/></port><port portid="22"><state state="open"/><service name="ssh"/></port><port portid="8080"><state state="closed"/><service name="http"/></port></ports></host></nmaprun>`
	targets, err := Parse(strings.NewReader(xml), "nmap")
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 1 || targets[0].URL != "https://192.0.2.10/" {
		t.Fatalf("got %#v", targets)
	}
}

func TestParseNmapPreservesIPv6BracketsAndUnknownWebPorts(t *testing.T) {
	xml := `<?xml version="1.0"?><nmaprun><host><status state="up"/><address addr="2001:db8::1" addrtype="ipv6"/><ports><port portid="443"><state state="open"/><service name="https"/></port><port portid="8080"><state state="open"/></port><port portid="22"><state state="open"/></port></ports></host></nmaprun>`
	targets, err := Parse(strings.NewReader(xml), "nmap")
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 2 {
		t.Fatalf("got %#v", targets)
	}
	var foundHTTPS, foundUnknown bool
	for _, target := range targets {
		if target.URL == "https://[2001:db8::1]/" {
			foundHTTPS = true
		}
		if target.Host == "2001:db8::1" && target.Port == 8080 && target.URL == "" {
			foundUnknown = true
		}
	}
	if !foundHTTPS || !foundUnknown {
		t.Fatalf("missing expected targets: %#v", targets)
	}
}

func TestParseRejectsCredentialBearingURL(t *testing.T) {
	targets, err := Parse(strings.NewReader("https://user:secret@example.test/"), "text")
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range targets {
		if target.URL != "" {
			t.Fatalf("credential-bearing URL accepted: %#v", target)
		}
	}
}
