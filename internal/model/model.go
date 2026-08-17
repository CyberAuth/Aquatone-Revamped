package model

import "time"

const SchemaVersion = 2

type ToolInfo struct {
	Name            string `json:"name"`
	Version         string `json:"version"`
	Commit          string `json:"commit,omitempty"`
	GoVersion       string `json:"goVersion,omitempty"`
	OS              string `json:"os,omitempty"`
	Arch            string `json:"arch,omitempty"`
	BrowserRevision int    `json:"browserRevision,omitempty"`
}

type ScanConfig struct {
	Ports                 string   `json:"ports"`
	Concurrency           int      `json:"concurrency"`
	ScreenshotConcurrency int      `json:"screenshotConcurrency"`
	RateLimit             int      `json:"rateLimit,omitempty"`
	SaveBody              bool     `json:"saveBody"`
	FullPage              bool     `json:"fullPage"`
	Viewport              string   `json:"viewport"`
	ProxyConfigured       bool     `json:"proxyConfigured"`
	HeaderNames           []string `json:"headerNames,omitempty"`
}

type Stats struct {
	Targets               int `json:"targets"`
	PortsOpen             int `json:"portsOpen"`
	RequestsSuccessful    int `json:"requestsSuccessful"`
	RequestsFailed        int `json:"requestsFailed"`
	ScreenshotsSuccessful int `json:"screenshotsSuccessful"`
	ScreenshotsBlank      int `json:"screenshotsBlank"`
	ScreenshotsFailed     int `json:"screenshotsFailed"`
}

type Session struct {
	SchemaVersion int        `json:"schemaVersion"`
	Tool          ToolInfo   `json:"tool"`
	StartedAt     time.Time  `json:"startedAt"`
	FinishedAt    time.Time  `json:"finishedAt"`
	Interrupted   bool       `json:"interrupted,omitempty"`
	Config        ScanConfig `json:"config"`
	Stats         Stats      `json:"stats"`
	Results       []*Result  `json:"results"`
	Clusters      []Cluster  `json:"clusters,omitempty"`
}

type Header struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type Redirect struct {
	URL        string `json:"url"`
	StatusCode int    `json:"statusCode,omitempty"`
}

type TLSInfo struct {
	Version   string    `json:"version,omitempty"`
	Subject   string    `json:"subject,omitempty"`
	Issuer    string    `json:"issuer,omitempty"`
	DNSNames  []string  `json:"dnsNames,omitempty"`
	NotBefore time.Time `json:"notBefore,omitempty"`
	NotAfter  time.Time `json:"notAfter,omitempty"`
	Expired   bool      `json:"expired,omitempty"`
}

type Artifacts struct {
	Headers    string `json:"headers,omitempty"`
	Body       string `json:"body,omitempty"`
	Screenshot string `json:"screenshot,omitempty"`
}

type StageError struct {
	Stage   string `json:"stage"`
	Message string `json:"message"`
}

type Result struct {
	Input           string       `json:"input"`
	URL             string       `json:"url"`
	FinalURL        string       `json:"finalUrl,omitempty"`
	Hostname        string       `json:"hostname"`
	Port            int          `json:"port"`
	Scheme          string       `json:"scheme"`
	StatusCode      int          `json:"statusCode,omitempty"`
	Status          string       `json:"status,omitempty"`
	ContentType     string       `json:"contentType,omitempty"`
	ContentLength   int64        `json:"contentLength,omitempty"`
	Title           string       `json:"title,omitempty"`
	Server          string       `json:"server,omitempty"`
	Technologies    []string     `json:"technologies,omitempty"`
	IPs             []string     `json:"ips,omitempty"`
	CNAME           string       `json:"cname,omitempty"`
	TLS             *TLSInfo     `json:"tls,omitempty"`
	Headers         []Header     `json:"headers,omitempty"`
	Redirects       []Redirect   `json:"redirects,omitempty"`
	ResponseTimeMS  int64        `json:"responseTimeMs,omitempty"`
	ScreenshotHash  string       `json:"screenshotHash,omitempty"`
	ScreenshotState string       `json:"screenshotState,omitempty"`
	BrowserFinalURL string       `json:"browserFinalUrl,omitempty"`
	Artifacts       Artifacts    `json:"artifacts"`
	Errors          []StageError `json:"errors,omitempty"`
}

type Cluster struct {
	ID      string   `json:"id"`
	Hash    string   `json:"hash"`
	Members []string `json:"members"`
}
