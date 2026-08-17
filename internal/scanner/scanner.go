package scanner

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/CyberAuth/Aquatone-Revamped/v2/internal/input"
	"github.com/CyberAuth/Aquatone-Revamped/v2/internal/model"
	"github.com/CyberAuth/Aquatone-Revamped/v2/internal/output"
	"github.com/CyberAuth/Aquatone-Revamped/v2/internal/ports"
	wappalyzer "github.com/projectdiscovery/wappalyzergo"
	"golang.org/x/net/html"
)

type Options struct {
	Ports           []ports.Spec
	Concurrency     int
	ConnectTimeout  time.Duration
	HTTPTimeout     time.Duration
	MaxBodyBytes    int64
	SaveBody        bool
	FollowRedirects bool
	MaxRedirects    int
	Proxy           string
	Headers         http.Header
	UserAgent       string
	RateLimit       int
	MatchStatus     map[int]bool
	FilterStatus    map[int]bool
}

type Endpoint struct {
	Input  string
	URL    string
	Host   string
	Port   int
	Scheme string
}

type Scanner struct {
	options    Options
	writer     *output.Writer
	transport  *http.Transport
	wappalyzer *wappalyzer.Wappalyze
	limiter    <-chan time.Time
	stopTicker func()
	openPorts  atomic.Int64
}

func New(options Options, writer *output.Writer) (*Scanner, error) {
	if options.Concurrency < 1 {
		options.Concurrency = 25
	}
	if options.MaxBodyBytes <= 0 {
		options.MaxBodyBytes = 10 << 20
	}
	if options.RateLimit < 0 || int64(options.RateLimit) > int64(time.Second) {
		return nil, fmt.Errorf("rate limit must be between 0 and %d requests per second", int64(time.Second))
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} // Recon must inspect hosts with invalid certificates.
	transport.DialContext = (&net.Dialer{Timeout: options.ConnectTimeout, KeepAlive: 30 * time.Second}).DialContext
	transport.MaxIdleConns = options.Concurrency * 2
	transport.MaxIdleConnsPerHost = 4
	if options.Proxy != "" {
		proxyURL, err := url.Parse(options.Proxy)
		if err != nil || proxyURL.Scheme == "" || proxyURL.Host == "" {
			return nil, fmt.Errorf("invalid proxy URL")
		}
		transport.Proxy = http.ProxyURL(proxyURL)
	}
	fingerprinter, err := wappalyzer.New()
	if err != nil {
		return nil, fmt.Errorf("load technology fingerprints: %w", err)
	}
	s := &Scanner{options: options, writer: writer, transport: transport, wappalyzer: fingerprinter}
	if options.RateLimit > 0 {
		ticker := time.NewTicker(time.Second / time.Duration(options.RateLimit))
		s.limiter = ticker.C
		s.stopTicker = ticker.Stop
	}
	return s, nil
}

func (s *Scanner) Close() {
	if s.stopTicker != nil {
		s.stopTicker()
	}
	s.transport.CloseIdleConnections()
}

func (s *Scanner) OpenPorts() int {
	return int(s.openPorts.Load())
}

func (s *Scanner) Discover(ctx context.Context, targets []input.Target) []Endpoint {
	var direct []Endpoint
	var hosts []input.Target
	for _, target := range targets {
		if target.URL == "" {
			if target.Port > 0 {
				direct = append(direct, Endpoint{Input: target.Input, Host: target.Host, Port: target.Port, Scheme: target.Scheme})
				continue
			}
			hosts = append(hosts, target)
			continue
		}
		u, err := url.Parse(target.URL)
		if err == nil {
			direct = append(direct, Endpoint{Input: target.Input, URL: target.URL, Host: u.Hostname(), Port: portForURL(u), Scheme: u.Scheme})
		}
	}
	type job struct {
		target input.Target
		port   ports.Spec
	}
	jobs := make(chan job)
	results := make(chan Endpoint)
	var workers sync.WaitGroup
	for range s.options.Concurrency {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for item := range jobs {
				address := net.JoinHostPort(item.target.Host, strconv.Itoa(item.port.Port))
				conn, err := (&net.Dialer{Timeout: s.options.ConnectTimeout}).DialContext(ctx, "tcp", address)
				if err != nil {
					continue
				}
				_ = conn.Close()
				s.openPorts.Add(1)
				select {
				case results <- Endpoint{Input: item.target.Input, Host: item.target.Host, Port: item.port.Port, Scheme: item.port.Scheme}:
				case <-ctx.Done():
					return
				}
			}
		}()
	}
	go func() {
		defer close(jobs)
		for _, target := range hosts {
			for _, port := range s.options.Ports {
				select {
				case jobs <- job{target: target, port: port}:
				case <-ctx.Done():
					return
				}
			}
		}
	}()
	go func() {
		workers.Wait()
		close(results)
	}()
	for endpoint := range results {
		direct = append(direct, endpoint)
	}
	sort.Slice(direct, func(i, j int) bool {
		return endpointKey(direct[i]) < endpointKey(direct[j])
	})
	return dedupeEndpoints(direct)
}

func (s *Scanner) Scan(ctx context.Context, endpoints []Endpoint, onResult func(*model.Result)) []*model.Result {
	jobs := make(chan Endpoint)
	results := make(chan *model.Result)
	var workers sync.WaitGroup
	for range s.options.Concurrency {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for endpoint := range jobs {
				result := s.scanEndpoint(ctx, endpoint)
				select {
				case results <- result:
				case <-ctx.Done():
					return
				}
			}
		}()
	}
	go func() {
		defer close(jobs)
		for _, endpoint := range endpoints {
			select {
			case jobs <- endpoint:
			case <-ctx.Done():
				return
			}
		}
	}()
	go func() {
		workers.Wait()
		close(results)
	}()
	all := make([]*model.Result, 0, len(endpoints))
	for result := range results {
		all = append(all, result)
		if onResult != nil {
			onResult(result)
		}
	}
	sort.Slice(all, func(i, j int) bool { return all[i].URL < all[j].URL })
	return all
}

func (s *Scanner) scanEndpoint(ctx context.Context, endpoint Endpoint) *model.Result {
	schemes := []string{endpoint.Scheme}
	if endpoint.Scheme == "" {
		schemes = []string{"https", "http"}
	}
	var last *model.Result
	for _, scheme := range schemes {
		rawURL := endpoint.URL
		if rawURL == "" {
			rawURL = buildURL(scheme, endpoint.Host, endpoint.Port)
		}
		result := s.fetch(ctx, endpoint.Input, rawURL)
		last = result
		if result.StatusCode > 0 {
			return result
		}
	}
	return last
}

func (s *Scanner) fetch(ctx context.Context, original, rawURL string) *model.Result {
	u, _ := url.Parse(rawURL)
	result := &model.Result{
		Input: original, URL: rawURL, FinalURL: rawURL, Hostname: u.Hostname(),
		Port: portForURL(u), Scheme: u.Scheme, ScreenshotState: "pending",
	}
	lookupCtx, cancel := context.WithTimeout(ctx, s.options.ConnectTimeout)
	result.IPs, _ = net.DefaultResolver.LookupHost(lookupCtx, result.Hostname)
	result.CNAME, _ = net.DefaultResolver.LookupCNAME(lookupCtx, result.Hostname)
	cancel()
	result.CNAME = strings.TrimSuffix(result.CNAME, ".")

	if s.limiter != nil {
		select {
		case <-s.limiter:
		case <-ctx.Done():
			result.Errors = append(result.Errors, model.StageError{Stage: "http", Message: ctx.Err().Error()})
			return result
		}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		result.Errors = append(result.Errors, model.StageError{Stage: "http", Message: err.Error()})
		return result
	}
	for name, values := range s.options.Headers {
		if strings.EqualFold(name, "Host") {
			if len(values) > 0 {
				req.Host = values[len(values)-1]
			}
			continue
		}
		for _, value := range values {
			req.Header.Add(name, value)
		}
	}
	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", s.options.UserAgent)
	}
	redirects := []model.Redirect{}
	hostOverride := req.Host
	client := &http.Client{Transport: s.transport, Timeout: s.options.HTTPTimeout}
	client.CheckRedirect = func(next *http.Request, via []*http.Request) error {
		if !s.options.FollowRedirects {
			return http.ErrUseLastResponse
		}
		if len(via) >= s.options.MaxRedirects {
			return fmt.Errorf("stopped after %d redirects", s.options.MaxRedirects)
		}
		if hostOverride != "" {
			next.Host = hostOverride
		}
		redirects = append(redirects, model.Redirect{URL: next.URL.String()})
		return nil
	}
	started := time.Now()
	resp, err := client.Do(req)
	result.ResponseTimeMS = time.Since(started).Milliseconds()
	if err != nil {
		result.Errors = append(result.Errors, model.StageError{Stage: "http", Message: sanitizeError(err)})
		return result
	}
	defer resp.Body.Close()
	result.StatusCode, result.Status = resp.StatusCode, resp.Status
	result.FinalURL = resp.Request.URL.String()
	result.Redirects = redirects
	result.ContentType = resp.Header.Get("Content-Type")
	result.Server = resp.Header.Get("Server")
	for name, values := range resp.Header {
		for _, value := range values {
			result.Headers = append(result.Headers, model.Header{Name: name, Value: value})
		}
	}
	sort.Slice(result.Headers, func(i, j int) bool {
		if result.Headers[i].Name == result.Headers[j].Name {
			return result.Headers[i].Value < result.Headers[j].Value
		}
		return result.Headers[i].Name < result.Headers[j].Name
	})
	body, readErr := io.ReadAll(io.LimitReader(resp.Body, s.options.MaxBodyBytes+1))
	if readErr != nil {
		result.Errors = append(result.Errors, model.StageError{Stage: "body", Message: readErr.Error()})
	}
	if int64(len(body)) > s.options.MaxBodyBytes {
		body = body[:s.options.MaxBodyBytes]
		result.Errors = append(result.Errors, model.StageError{Stage: "body", Message: "response body truncated at configured limit"})
	}
	result.ContentLength = int64(len(body))
	result.Title = titleFromHTML(body)
	tech := s.wappalyzer.Fingerprint(resp.Header, body)
	for name := range tech {
		result.Technologies = append(result.Technologies, name)
	}
	sort.Strings(result.Technologies)
	if resp.TLS != nil {
		result.TLS = tlsInfo(resp.TLS)
	}
	base := s.writer.BaseName(result.URL, result.Hostname)
	if rel, err := s.writer.WriteHeaders(base, result.Status, result.Headers); err == nil {
		result.Artifacts.Headers = rel
	} else {
		result.Errors = append(result.Errors, model.StageError{Stage: "artifact", Message: err.Error()})
	}
	if s.options.SaveBody {
		if rel, err := s.writer.WriteBody(base, body); err == nil {
			result.Artifacts.Body = rel
		} else {
			result.Errors = append(result.Errors, model.StageError{Stage: "artifact", Message: err.Error()})
		}
	}
	return result
}

func (s *Scanner) ShouldScreenshot(result *model.Result) bool {
	if result.StatusCode == 0 {
		return false
	}
	if len(s.options.MatchStatus) > 0 && !s.options.MatchStatus[result.StatusCode] {
		return false
	}
	return !s.options.FilterStatus[result.StatusCode]
}

func titleFromHTML(body []byte) string {
	tokenizer := html.NewTokenizer(strings.NewReader(string(body)))
	for {
		switch tokenizer.Next() {
		case html.ErrorToken:
			return ""
		case html.StartTagToken:
			token := tokenizer.Token()
			if strings.EqualFold(token.Data, "title") && tokenizer.Next() == html.TextToken {
				return strings.Join(strings.Fields(html.UnescapeString(tokenizer.Token().Data)), " ")
			}
		}
	}
}

func tlsInfo(state *tls.ConnectionState) *model.TLSInfo {
	info := &model.TLSInfo{Version: tlsVersion(state.Version)}
	if len(state.PeerCertificates) == 0 {
		return info
	}
	cert := state.PeerCertificates[0]
	info.Subject, info.Issuer = cert.Subject.String(), cert.Issuer.String()
	info.DNSNames = append([]string(nil), cert.DNSNames...)
	info.NotBefore, info.NotAfter = cert.NotBefore, cert.NotAfter
	info.Expired = time.Now().After(cert.NotAfter)
	return info
}

func tlsVersion(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("0x%x", version)
	}
}

func buildURL(scheme, host string, port int) string {
	hostPort := net.JoinHostPort(host, strconv.Itoa(port))
	if (scheme == "http" && port == 80) || (scheme == "https" && port == 443) {
		hostPort = host
		if strings.Contains(host, ":") {
			hostPort = "[" + host + "]"
		}
	}
	return fmt.Sprintf("%s://%s/", scheme, hostPort)
}

func portForURL(u *url.URL) int {
	if value := u.Port(); value != "" {
		port, _ := strconv.Atoi(value)
		return port
	}
	if u.Scheme == "https" {
		return 443
	}
	return 80
}

func endpointKey(endpoint Endpoint) string {
	if endpoint.URL != "" {
		return endpoint.URL
	}
	return fmt.Sprintf("%s|%d|%s", endpoint.Host, endpoint.Port, endpoint.Scheme)
}

func dedupeEndpoints(items []Endpoint) []Endpoint {
	seen := map[string]bool{}
	result := make([]Endpoint, 0, len(items))
	for _, item := range items {
		key := endpointKey(item)
		if !seen[key] {
			seen[key] = true
			result = append(result, item)
		}
	}
	return result
}

func sanitizeError(err error) string {
	message := err.Error()
	if parsed, parseErr := url.Parse(message); parseErr == nil && parsed.User != nil {
		parsed.User = url.User("[redacted]")
		return parsed.String()
	}
	return message
}
