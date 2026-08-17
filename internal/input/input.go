package input

import (
	"bufio"
	"encoding/xml"
	"fmt"
	"io"
	"net"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"mvdan.cc/xurls/v2"
)

type Target struct {
	Input  string
	URL    string
	Host   string
	Port   int
	Scheme string
}

const maxInputBytes = 64 << 20

var hostnamePattern = regexp.MustCompile(`(?i)^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
var singleLabelPattern = regexp.MustCompile(`(?i)^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
var likelyWebPorts = map[int]struct{}{
	80: {}, 81: {}, 300: {}, 443: {}, 591: {}, 593: {}, 832: {}, 981: {}, 1010: {}, 1311: {},
	2082: {}, 2087: {}, 2095: {}, 2096: {}, 2480: {}, 3000: {}, 3128: {}, 3333: {}, 4243: {},
	4567: {}, 4711: {}, 4712: {}, 4993: {}, 5000: {}, 5104: {}, 5108: {}, 5800: {}, 6543: {},
	7000: {}, 7396: {}, 7474: {}, 8000: {}, 8001: {}, 8008: {}, 8014: {}, 8042: {}, 8069: {},
	8080: {}, 8081: {}, 8083: {}, 8088: {}, 8090: {}, 8091: {}, 8118: {}, 8123: {}, 8172: {},
	8222: {}, 8243: {}, 8280: {}, 8281: {}, 8333: {}, 8443: {}, 8500: {}, 8834: {}, 8880: {},
	8888: {}, 8983: {}, 9000: {}, 9043: {}, 9060: {}, 9080: {}, 9090: {}, 9091: {}, 9200: {},
	9443: {}, 9800: {}, 9981: {}, 12443: {}, 16080: {}, 18091: {}, 18092: {}, 20720: {}, 28017: {},
}

func Parse(r io.Reader, format string) ([]Target, error) {
	data, err := io.ReadAll(io.LimitReader(r, maxInputBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxInputBytes {
		return nil, fmt.Errorf("input exceeds %d MiB limit", maxInputBytes>>20)
	}
	trimmed := strings.TrimSpace(string(data))
	if trimmed == "" {
		return nil, nil
	}
	if format == "nmap" || (format == "auto" && (strings.Contains(trimmed, "<nmaprun") || strings.Contains(trimmed, "<masscan"))) {
		return parseNmap(data)
	}
	return parseText(strings.NewReader(trimmed)), nil
}

func FromArgs(args []string) []Target {
	return parseText(strings.NewReader(strings.Join(args, "\n")))
}

func Merge(groups ...[]Target) []Target {
	seen := map[string]Target{}
	for _, group := range groups {
		for _, target := range group {
			key := target.URL
			if key == "" {
				key = fmt.Sprintf("%s|%d|%s", strings.ToLower(target.Host), target.Port, target.Scheme)
			}
			if _, ok := seen[key]; !ok {
				seen[key] = target
			}
		}
	}
	keys := make([]string, 0, len(seen))
	for key := range seen {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	result := make([]Target, 0, len(keys))
	for _, key := range keys {
		result = append(result, seen[key])
	}
	return result
}

func parseText(r io.Reader) []Target {
	seen := map[string]Target{}
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)
	urlMatcher := xurls.Relaxed()
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		for _, raw := range urlMatcher.FindAllString(line, -1) {
			if normalized, ok := normalizeURL(raw); ok {
				seen[normalized] = Target{Input: raw, URL: normalized}
			}
		}
		fields := strings.Fields(line)
		for _, field := range fields {
			field = strings.Trim(field, " \t\r\n,;()[]{}<>\"'")
			if field == "" || strings.Contains(field, "://") || strings.Contains(field, "@") {
				continue
			}
			host := field
			if parsed, err := url.Parse("//" + field); err == nil && parsed.Hostname() != "" {
				host = parsed.Hostname()
			}
			host = strings.TrimSuffix(strings.ToLower(host), ".")
			if net.ParseIP(host) == nil && !hostnamePattern.MatchString(host) && !(len(fields) == 1 && singleLabelPattern.MatchString(host)) {
				continue
			}
			seen[host] = Target{Input: field, Host: host}
		}
	}
	keys := make([]string, 0, len(seen))
	for key := range seen {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	result := make([]Target, 0, len(keys))
	for _, key := range keys {
		result = append(result, seen[key])
	}
	return result
}

func normalizeURL(raw string) (string, bool) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || u.User != nil {
		return "", false
	}
	u.Fragment = ""
	if u.Path == "" {
		u.Path = "/"
	}
	u.Scheme = strings.ToLower(u.Scheme)
	u.Host = strings.ToLower(u.Host)
	return u.String(), true
}

type nmapRun struct {
	Hosts []struct {
		Status struct {
			State string `xml:"state,attr"`
		} `xml:"status"`
		Addresses []struct {
			Addr string `xml:"addr,attr"`
			Type string `xml:"addrtype,attr"`
		} `xml:"address"`
		Hostnames []struct {
			Name string `xml:"name,attr"`
		} `xml:"hostnames>hostname"`
		Ports []struct {
			Port  int `xml:"portid,attr"`
			State struct {
				State string `xml:"state,attr"`
			} `xml:"state"`
			Service struct {
				Name   string `xml:"name,attr"`
				Tunnel string `xml:"tunnel,attr"`
			} `xml:"service"`
		} `xml:"ports>port"`
	} `xml:"host"`
}

func parseNmap(data []byte) ([]Target, error) {
	var run nmapRun
	if err := xml.Unmarshal(data, &run); err != nil {
		return nil, fmt.Errorf("parse Nmap/Masscan XML: %w", err)
	}
	var targets []Target
	for _, host := range run.Hosts {
		if host.Status.State != "" && host.Status.State != "up" {
			continue
		}
		var names []string
		for _, hostname := range host.Hostnames {
			if hostname.Name != "" {
				names = append(names, hostname.Name)
			}
		}
		if len(names) == 0 {
			for _, address := range host.Addresses {
				if address.Type != "mac" && address.Addr != "" {
					names = append(names, address.Addr)
				}
			}
		}
		for _, port := range host.Ports {
			if port.State.State != "open" {
				continue
			}
			scheme := ""
			if port.Service.Tunnel == "ssl" || port.Service.Name == "https" || port.Service.Name == "ssl" {
				scheme = "https"
			} else if strings.Contains(port.Service.Name, "http") {
				scheme = "http"
			} else if !likelyWebPort(port.Port) {
				continue
			}
			for _, name := range names {
				name = strings.TrimSuffix(name, ".")
				if scheme == "" {
					input := net.JoinHostPort(name, fmt.Sprintf("%d", port.Port))
					targets = append(targets, Target{Input: input, Host: name, Port: port.Port})
					continue
				}
				hostPort := net.JoinHostPort(name, fmt.Sprintf("%d", port.Port))
				if (scheme == "http" && port.Port == 80) || (scheme == "https" && port.Port == 443) {
					hostPort = name
					if net.ParseIP(name) != nil && strings.Contains(name, ":") {
						hostPort = "[" + name + "]"
					}
				}
				raw := fmt.Sprintf("%s://%s/", scheme, hostPort)
				targets = append(targets, Target{Input: raw, URL: raw})
			}
		}
	}
	return Merge(targets), nil
}

func likelyWebPort(port int) bool {
	_, ok := likelyWebPorts[port]
	return ok
}
