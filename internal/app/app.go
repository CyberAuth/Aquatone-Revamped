package app

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/CyberAuth/Aquatone-Revamped/v2/internal/browser"
	"github.com/CyberAuth/Aquatone-Revamped/v2/internal/cluster"
	inputparser "github.com/CyberAuth/Aquatone-Revamped/v2/internal/input"
	"github.com/CyberAuth/Aquatone-Revamped/v2/internal/model"
	"github.com/CyberAuth/Aquatone-Revamped/v2/internal/output"
	"github.com/CyberAuth/Aquatone-Revamped/v2/internal/ports"
	"github.com/CyberAuth/Aquatone-Revamped/v2/internal/report"
	"github.com/CyberAuth/Aquatone-Revamped/v2/internal/scanner"
	"github.com/CyberAuth/Aquatone-Revamped/v2/internal/version"
)

type streams struct {
	in  io.Reader
	out io.Writer
	err io.Writer
}

func Run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	s := streams{in: stdin, out: stdout, err: stderr}
	if len(args) == 0 {
		return runScan(args, s)
	}
	switch args[0] {
	case "scan":
		return runScan(args[1:], s)
	case "report":
		return runReport(args[1:], s)
	case "browser":
		return runBrowser(args[1:], s)
	case "version":
		return runVersion(args[1:], s)
	case "help", "-h", "--help":
		printHelp(stdout)
		return 0
	}
	if hasFlag(args, "session") {
		return runReport(args, s)
	}
	if hasFlag(args, "version") {
		return runVersion(nil, s)
	}
	return runScan(args, s)
}

type scanFlags struct {
	inputFile             string
	inputFormat           string
	nmap                  bool
	outDir                string
	portList              string
	concurrency           int
	screenshotConcurrency int
	rateLimit             int
	connectTimeout        string
	httpTimeout           string
	screenshotTimeout     string
	screenshotWait        string
	maxBodyBytes          int64
	saveBody              bool
	followRedirects       bool
	noRedirect            bool
	proxy                 string
	headers               stringList
	userAgent             string
	matchStatus           string
	filterStatus          string
	viewport              string
	fullPage              bool
	screenshots           bool
	systemBrowser         bool
	browserPath           string
	similarity            float64
	silent                bool
	debug                 bool
	templatePath          string
}

func runScan(args []string, streams streams) int {
	flags := scanFlags{}
	set := flag.NewFlagSet("aquatone scan", flag.ContinueOnError)
	set.SetOutput(streams.err)
	set.StringVar(&flags.inputFile, "input", "", "input file (default: stdin)")
	set.StringVar(&flags.inputFile, "input-file", "", "legacy alias for --input")
	set.StringVar(&flags.inputFormat, "input-format", "auto", "input format: auto, text, or nmap")
	set.BoolVar(&flags.nmap, "nmap", false, "parse input as Nmap/Masscan XML")
	defaultOut := os.Getenv("AQUATONE_OUT_PATH")
	if defaultOut == "" {
		defaultOut = "."
	}
	set.StringVar(&flags.outDir, "out", defaultOut, "output directory")
	set.StringVar(&flags.portList, "ports", "medium", "ports, ranges, schemes, or alias")
	set.IntVar(&flags.concurrency, "concurrency", 25, "network worker count")
	set.IntVar(&flags.concurrency, "threads", 25, "legacy alias for --concurrency")
	set.IntVar(&flags.screenshotConcurrency, "screenshot-concurrency", min(4, runtime.NumCPU()), "screenshot worker count")
	set.IntVar(&flags.rateLimit, "rate-limit", 0, "maximum HTTP requests per second (0 is unlimited)")
	set.StringVar(&flags.connectTimeout, "connect-timeout", "3s", "TCP/DNS timeout")
	set.StringVar(&flags.connectTimeout, "scan-timeout", "3s", "legacy TCP timeout (duration or milliseconds)")
	set.StringVar(&flags.httpTimeout, "http-timeout", "10s", "HTTP timeout (duration or milliseconds)")
	set.StringVar(&flags.screenshotTimeout, "screenshot-timeout", "30s", "screenshot timeout (duration or milliseconds)")
	set.StringVar(&flags.screenshotWait, "screenshot-wait", "1s", "render settle time")
	set.Int64Var(&flags.maxBodyBytes, "max-body-bytes", 10<<20, "maximum response bytes to analyze/save")
	set.BoolVar(&flags.saveBody, "save-body", false, "save response bodies")
	set.BoolVar(&flags.followRedirects, "follow-redirects", true, "follow HTTP redirects")
	set.BoolVar(&flags.noRedirect, "no-redirect", false, "legacy flag to disable redirects")
	set.StringVar(&flags.proxy, "proxy", "", "HTTP or SOCKS proxy URL")
	set.Var(&flags.headers, "header", "request header, repeatable (Name: value)")
	set.StringVar(&flags.userAgent, "user-agent", "Mozilla/5.0 (compatible; Aquatone-Revamped/2.0; +https://github.com/CyberAuth/Aquatone-Revamped)", "HTTP user agent")
	set.StringVar(&flags.matchStatus, "match-status", "", "only screenshot these status codes/ranges")
	set.StringVar(&flags.filterStatus, "filter-status", "", "do not screenshot these status codes/ranges")
	set.StringVar(&flags.viewport, "viewport", "1440,900", "screenshot viewport WIDTH,HEIGHT")
	set.StringVar(&flags.viewport, "resolution", "1440,900", "legacy alias for --viewport")
	set.BoolVar(&flags.fullPage, "full-page", false, "capture full-page screenshots")
	set.BoolVar(&flags.screenshots, "screenshots", true, "capture screenshots")
	set.BoolVar(&flags.systemBrowser, "system-browser", false, "use an installed Chrome/Chromium/Edge")
	set.StringVar(&flags.browserPath, "browser-path", "", "explicit browser executable path")
	set.StringVar(&flags.browserPath, "chrome-path", "", "legacy alias for --browser-path")
	set.Float64Var(&flags.similarity, "similarity", 0.80, "visual clustering similarity from 0 to 1")
	set.BoolVar(&flags.silent, "silent", false, "suppress progress output")
	set.BoolVar(&flags.debug, "debug", false, "print diagnostic errors")
	set.StringVar(&flags.templatePath, "template-path", "", "legacy custom template path (not supported by v2)")
	if err := set.Parse(args); err != nil {
		return 2
	}
	if flags.templatePath != "" {
		fmt.Fprintln(streams.err, "error: custom templates are not supported by the v2 report schema")
		return 2
	}
	if flags.nmap {
		flags.inputFormat = "nmap"
	}
	if flags.inputFormat != "auto" && flags.inputFormat != "text" && flags.inputFormat != "nmap" {
		fmt.Fprintln(streams.err, "error: --input-format must be auto, text, or nmap")
		return 2
	}
	if flags.concurrency < 1 || flags.screenshotConcurrency < 1 {
		fmt.Fprintln(streams.err, "error: concurrency values must be positive")
		return 2
	}
	if flags.rateLimit < 0 || int64(flags.rateLimit) > int64(time.Second) {
		fmt.Fprintf(streams.err, "error: --rate-limit must be between 0 and %d requests per second\n", int64(time.Second))
		return 2
	}
	if flags.similarity < 0 || flags.similarity > 1 {
		fmt.Fprintln(streams.err, "error: --similarity must be between 0 and 1")
		return 2
	}
	connectTimeout, err := parseDuration(flags.connectTimeout)
	if err != nil {
		return printError(streams.err, "--connect-timeout", err)
	}
	httpTimeout, err := parseDuration(flags.httpTimeout)
	if err != nil {
		return printError(streams.err, "--http-timeout", err)
	}
	screenshotTimeout, err := parseDuration(flags.screenshotTimeout)
	if err != nil {
		return printError(streams.err, "--screenshot-timeout", err)
	}
	screenshotWait, err := parseDuration(flags.screenshotWait)
	if err != nil {
		return printError(streams.err, "--screenshot-wait", err)
	}
	portSpecs, err := ports.Parse(flags.portList)
	if err != nil {
		return printError(streams.err, "--ports", err)
	}
	matchStatus, err := parseStatusSet(flags.matchStatus)
	if err != nil {
		return printError(streams.err, "--match-status", err)
	}
	filterStatus, err := parseStatusSet(flags.filterStatus)
	if err != nil {
		return printError(streams.err, "--filter-status", err)
	}
	headers, headerNames, err := parseHeaders(flags.headers)
	if err != nil {
		return printError(streams.err, "--header", err)
	}
	targets, err := collectTargets(flags.inputFile, flags.inputFormat, set.Args(), streams.in)
	if err != nil {
		return printError(streams.err, "input", err)
	}
	if len(targets) == 0 {
		fmt.Fprintln(streams.err, "error: no valid targets found")
		return 2
	}
	writer, err := output.New(flags.outDir)
	if err != nil {
		return printError(streams.err, "output", err)
	}
	defer writer.Close()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	started := time.Now()
	session := &model.Session{
		SchemaVersion: model.SchemaVersion, Tool: version.Info(), StartedAt: started,
		Config: model.ScanConfig{Ports: flags.portList, Concurrency: flags.concurrency, ScreenshotConcurrency: flags.screenshotConcurrency, RateLimit: flags.rateLimit, SaveBody: flags.saveBody, FullPage: flags.fullPage, Viewport: flags.viewport, ProxyConfigured: flags.proxy != "", HeaderNames: headerNames},
	}
	if !flags.silent {
		fmt.Fprintf(streams.out, "Aquatone Revamped %s · %d targets · output %s\n", version.Version, len(targets), writer.Dir)
	}
	scan, err := scanner.New(scanner.Options{
		Ports: portSpecs, Concurrency: flags.concurrency, ConnectTimeout: connectTimeout, HTTPTimeout: httpTimeout,
		MaxBodyBytes: flags.maxBodyBytes, SaveBody: flags.saveBody, FollowRedirects: flags.followRedirects && !flags.noRedirect,
		MaxRedirects: 10, Proxy: flags.proxy, Headers: headers, UserAgent: flags.userAgent, RateLimit: flags.rateLimit,
		MatchStatus: matchStatus, FilterStatus: filterStatus,
	}, writer)
	if err != nil {
		return printError(streams.err, "scanner", err)
	}
	defer scan.Close()
	endpoints := scan.Discover(ctx, targets)
	results := scan.Scan(ctx, endpoints, func(result *model.Result) {
		if flags.silent {
			return
		}
		if result.StatusCode > 0 {
			fmt.Fprintf(streams.out, "%3d  %s\n", result.StatusCode, result.FinalURL)
		} else if flags.debug {
			fmt.Fprintf(streams.err, "failed  %s: %v\n", result.URL, result.Errors)
		}
	})
	if flags.screenshots {
		runScreenshots(ctx, results, scan, flags, headers, screenshotTimeout, screenshotWait, writer, streams)
	} else {
		for _, result := range results {
			result.ScreenshotState = "skipped"
		}
	}
	for _, result := range results {
		if err := writer.Record(result); err != nil && flags.debug {
			fmt.Fprintln(streams.err, "record result:", err)
		}
	}
	session.Results = results
	session.Clusters = cluster.Build(results, flags.similarity)
	session.FinishedAt = time.Now()
	session.Interrupted = ctx.Err() != nil
	session.Stats = calculateStats(len(targets), scan.OpenPorts(), results)
	if err := writer.SaveSession(session); err != nil {
		return printError(streams.err, "session", err)
	}
	reportPath := filepath.Join(writer.Dir, "aquatone_report.html")
	if err := report.Write(session, reportPath); err != nil {
		return printError(streams.err, "report", err)
	}
	if !flags.silent {
		fmt.Fprintf(streams.out, "Completed in %s · %d responsive · %d screenshots\nReport: %s\n", time.Since(started).Round(time.Millisecond), session.Stats.RequestsSuccessful, session.Stats.ScreenshotsSuccessful, reportPath)
	}
	if session.Interrupted {
		return 130
	}
	return 0
}

func runScreenshots(ctx context.Context, results []*model.Result, scan *scanner.Scanner, flags scanFlags, headers http.Header, timeout, settle time.Duration, writer *output.Writer, streams streams) {
	eligible := make([]*model.Result, 0, len(results))
	for _, result := range results {
		if scan.ShouldScreenshot(result) {
			eligible = append(eligible, result)
		} else {
			result.ScreenshotState = "skipped"
		}
	}
	if len(eligible) == 0 {
		return
	}
	flatHeaders := make([]string, 0)
	for name, values := range headers {
		for _, value := range values {
			flatHeaders = append(flatHeaders, name, value)
		}
	}
	manager, err := browser.New(ctx, browser.Options{
		BrowserPath: flags.browserPath, UseSystem: flags.systemBrowser, Proxy: flags.proxy, Headers: flatHeaders,
		Viewport: flags.viewport, FullPage: flags.fullPage, Timeout: timeout, Quiet: 750 * time.Millisecond,
		Settle: settle, Logger: streams.out,
	}, writer)
	if err != nil {
		for _, result := range eligible {
			result.ScreenshotState = "failed"
			result.Errors = append(result.Errors, model.StageError{Stage: "screenshot", Message: err.Error()})
		}
		fmt.Fprintln(streams.err, "warning: screenshots unavailable:", err)
		return
	}
	defer manager.Close()
	jobs := make(chan *model.Result)
	var wait sync.WaitGroup
	for range flags.screenshotConcurrency {
		wait.Add(1)
		go func() {
			defer wait.Done()
			for result := range jobs {
				capture, err := manager.Capture(ctx, result)
				if err != nil {
					result.ScreenshotState = "failed"
					result.Errors = append(result.Errors, model.StageError{Stage: "screenshot", Message: err.Error()})
					continue
				}
				result.ScreenshotHash, result.BrowserFinalURL = capture.Hash, capture.FinalURL
				if capture.Blank {
					result.ScreenshotState = "blank"
					result.Errors = append(result.Errors, model.StageError{Stage: "screenshot", Message: "capture remained visually blank after retry"})
				} else {
					result.ScreenshotState = "ok"
				}
			}
		}()
	}
	for _, result := range eligible {
		select {
		case jobs <- result:
		case <-ctx.Done():
			close(jobs)
			wait.Wait()
			return
		}
	}
	close(jobs)
	wait.Wait()
}

func runReport(args []string, streams streams) int {
	set := flag.NewFlagSet("aquatone report", flag.ContinueOnError)
	set.SetOutput(streams.err)
	var sessionPath, outDir string
	set.StringVar(&sessionPath, "session", "", "v1 or v2 session JSON")
	set.StringVar(&outDir, "out", "", "output directory (default: session directory)")
	if err := set.Parse(args); err != nil {
		return 2
	}
	if sessionPath == "" && len(set.Args()) > 0 {
		sessionPath = set.Args()[0]
	}
	if sessionPath == "" {
		fmt.Fprintln(streams.err, "error: --session is required")
		return 2
	}
	session, err := report.Load(sessionPath)
	if err != nil {
		return printError(streams.err, "load session", err)
	}
	if outDir == "" {
		outDir = filepath.Dir(sessionPath)
	}
	if err := os.MkdirAll(outDir, 0o700); err != nil {
		return printError(streams.err, "output", err)
	}
	if err := report.CopyArtifacts(session, filepath.Dir(sessionPath), outDir); err != nil {
		return printError(streams.err, "copy report artifacts", err)
	}
	destination := filepath.Join(outDir, "aquatone_report.html")
	if err := report.Write(session, destination); err != nil {
		return printError(streams.err, "report", err)
	}
	fmt.Fprintln(streams.out, destination)
	return 0
}

func runBrowser(args []string, streams streams) int {
	if len(args) == 0 {
		fmt.Fprintln(streams.err, "usage: aquatone browser install|status|clean")
		return 2
	}
	switch args[0] {
	case "install":
		path, err := browser.Install(context.Background(), streams.out)
		if err != nil {
			return printError(streams.err, "browser install", err)
		}
		fmt.Fprintln(streams.out, path)
	case "status":
		path, installed, err := browser.Status()
		if err != nil {
			return printError(streams.err, "browser status", err)
		}
		fmt.Fprintf(streams.out, "revision=%d installed=%t path=%s\n", browser.Revision, installed, path)
	case "clean":
		if err := browser.Clean(); err != nil {
			return printError(streams.err, "browser clean", err)
		}
		fmt.Fprintln(streams.out, "managed browser cache removed")
	default:
		fmt.Fprintln(streams.err, "usage: aquatone browser install|status|clean")
		return 2
	}
	return 0
}

func runVersion(args []string, streams streams) int {
	info := version.Info()
	jsonOutput := len(args) > 0 && args[0] == "--json"
	if jsonOutput {
		data, _ := json.Marshal(info)
		fmt.Fprintln(streams.out, string(data))
	} else {
		fmt.Fprintf(streams.out, "Aquatone Revamped %s (%s/%s, %s, commit %s, browser revision %d)\n", info.Version, info.OS, info.Arch, info.GoVersion, info.Commit, info.BrowserRevision)
	}
	return 0
}

func collectTargets(inputFile, format string, args []string, stdin io.Reader) ([]inputparser.Target, error) {
	var groups [][]inputparser.Target
	if len(args) > 0 {
		groups = append(groups, inputparser.FromArgs(args))
	}
	if inputFile != "" {
		file, err := os.Open(inputFile)
		if err != nil {
			return nil, err
		}
		parsed, parseErr := inputparser.Parse(file, format)
		_ = file.Close()
		if parseErr != nil {
			return nil, parseErr
		}
		groups = append(groups, parsed)
	}
	if len(groups) == 0 {
		parsed, err := inputparser.Parse(stdin, format)
		if err != nil {
			return nil, err
		}
		groups = append(groups, parsed)
	}
	return inputparser.Merge(groups...), nil
}

func calculateStats(targets, openPorts int, results []*model.Result) model.Stats {
	stats := model.Stats{Targets: targets, PortsOpen: openPorts}
	for _, result := range results {
		if result.StatusCode > 0 {
			stats.RequestsSuccessful++
		} else {
			stats.RequestsFailed++
		}
		switch result.ScreenshotState {
		case "ok":
			stats.ScreenshotsSuccessful++
		case "blank":
			stats.ScreenshotsBlank++
		case "failed":
			stats.ScreenshotsFailed++
		}
	}
	return stats
}

func parseHeaders(values []string) (http.Header, []string, error) {
	headers := http.Header{}
	for _, raw := range values {
		name, value, ok := strings.Cut(raw, ":")
		if !ok || strings.TrimSpace(name) == "" {
			return nil, nil, fmt.Errorf("header must use 'Name: value' format")
		}
		if strings.ContainsAny(name, "\r\n") || strings.ContainsAny(value, "\r\n") {
			return nil, nil, fmt.Errorf("header contains a newline")
		}
		headers.Add(strings.TrimSpace(name), strings.TrimSpace(value))
	}
	names := make([]string, 0, len(headers))
	for name := range headers {
		names = append(names, name)
	}
	sort.Strings(names)
	return headers, names, nil
}

func parseStatusSet(value string) (map[int]bool, error) {
	set := map[int]bool{}
	if strings.TrimSpace(value) == "" {
		return set, nil
	}
	for _, token := range strings.Split(value, ",") {
		token = strings.TrimSpace(token)
		start, end := 0, 0
		if a, b, ok := strings.Cut(token, "-"); ok {
			var err error
			start, err = strconv.Atoi(a)
			if err != nil {
				return nil, fmt.Errorf("invalid status %q", token)
			}
			end, err = strconv.Atoi(b)
			if err != nil || end < start {
				return nil, fmt.Errorf("invalid status range %q", token)
			}
		} else {
			status, err := strconv.Atoi(token)
			if err != nil {
				return nil, fmt.Errorf("invalid status %q", token)
			}
			start, end = status, status
		}
		if start < 100 || end > 599 {
			return nil, fmt.Errorf("status outside 100-599")
		}
		for status := start; status <= end; status++ {
			set[status] = true
		}
	}
	return set, nil
}

func parseDuration(value string) (time.Duration, error) {
	if milliseconds, err := strconv.Atoi(value); err == nil {
		if milliseconds < 0 {
			return 0, errors.New("duration cannot be negative")
		}
		return time.Duration(milliseconds) * time.Millisecond, nil
	}
	duration, err := time.ParseDuration(value)
	if err != nil || duration < 0 {
		return 0, fmt.Errorf("invalid duration %q", value)
	}
	return duration, nil
}

type stringList []string

func (s *stringList) String() string         { return strings.Join(*s, ",") }
func (s *stringList) Set(value string) error { *s = append(*s, value); return nil }

func hasFlag(args []string, name string) bool {
	for _, arg := range args {
		if arg == "-"+name || arg == "--"+name || strings.HasPrefix(arg, "-"+name+"=") || strings.HasPrefix(arg, "--"+name+"=") {
			return true
		}
	}
	return false
}

func printError(writer io.Writer, label string, err error) int {
	fmt.Fprintf(writer, "error: %s: %v\n", label, err)
	return 1
}

func printHelp(writer io.Writer) {
	fmt.Fprintln(writer, "Aquatone Revamped - visual HTTP attack-surface inspection")
	fmt.Fprintln(writer, "")
	fmt.Fprintln(writer, "Usage:")
	fmt.Fprintln(writer, "  aquatone [scan] [flags] [targets...]")
	fmt.Fprintln(writer, "  aquatone report --session FILE")
	fmt.Fprintln(writer, "  aquatone browser install|status|clean")
	fmt.Fprintln(writer, "  aquatone version [--json]")
}
