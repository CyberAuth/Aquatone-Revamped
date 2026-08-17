# Aquatone Revamped

Aquatone Revamped is a modern continuation of [Aquatone](https://github.com/michenriksen/aquatone) for visually inspecting HTTP attack surface at scale. It accepts URLs, hostnames, IP addresses, and Nmap/Masscan XML; probes web services; captures screenshots; fingerprints technologies; and produces a searchable, fully offline report.

This project is under active redevelopment. The v2 session format is stable enough for testing, but command-line compatibility may still change before the first stable release.

## Highlights

- Native builds for macOS (Apple Silicon and Intel), Linux (arm64 and amd64), and Windows (amd64)
- Bounded TCP, HTTP, and screenshot worker pools with rate limiting and graceful interruption
- Managed Chromium download by default, with system-browser and explicit-path overrides
- TLS, DNS, redirect, response-header, title, and Wappalyzer technology metadata
- Perceptual screenshot clustering with retry detection for blank captures
- Self-contained report with search, filters, sorting, and no CDN or runtime network requests
- Versioned JSON session, streaming-friendly JSONL results, and legacy v1 report migration

## Install from source

Go 1.26.6 or newer is required. Go 1.26 supports macOS 12 Monterey and newer.

```sh
go install github.com/CyberAuth/Aquatone-Revamped/v2/cmd/aquatone@latest
```

Or build a local checkout:

```sh
go build -o aquatone ./cmd/aquatone
```

Release archives will be published for supported platforms once v2 is released.

## Quick start

Only scan systems you own or are explicitly authorized to assess.

```sh
cat targets.txt | aquatone scan --out ./results
aquatone scan --ports large --rate-limit 20 example.test 192.0.2.10
aquatone scan --nmap --input scan.xml --out ./results
```

Explicit URLs are requested directly. Bare hosts are checked on the selected port set. On a port without an explicit scheme, HTTPS is attempted before HTTP.

The first screenshot run downloads a managed Chromium build into the user cache. To use an installed browser instead:

```sh
aquatone scan --system-browser example.test
aquatone scan --browser-path "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" example.test
```

Managed-browser lifecycle commands:

```sh
aquatone browser status
aquatone browser install
aquatone browser clean
```

Run `aquatone help` for the command overview and `aquatone scan --help` for all scan flags.

## Inputs

Aquatone extracts HTTP(S) URLs, DNS hostnames, and IPv4/IPv6 addresses from arguments, stdin, or `--input`. Use `--input-format nmap` (or `--nmap`) for Nmap/Masscan XML.

Port values support aliases (`small`, `medium`, `large`, `xlarge`), lists, bounded ranges, and scheme hints:

```sh
aquatone scan --ports '80,https:443,http:8000-8010' targets.txt
```

## Output

Output directories and generated artifacts use owner-only permissions where the operating system supports them.

| Path | Purpose |
| --- | --- |
| `aquatone_report.html` | Interactive offline report |
| `aquatone_session.json` | Complete versioned session |
| `aquatone_results.jsonl` | One machine-readable result per line |
| `aquatone_urls.txt` | Responsive final URLs |
| `screenshots/` | PNG captures |
| `headers/` | Response status and headers |
| `html/` | Response bodies when `--save-body` is enabled |

Reports contain target metadata and may contain sensitive assessment evidence. Store and share them accordingly. Request-header values and proxy credentials are not written to the session; only configured header names and a proxy-present boolean are recorded.

Regenerate a report from either a v2 session or a legacy Aquatone v1 session:

```sh
aquatone report --session ./results/aquatone_session.json
```

## Compatibility notes

Common v1 flags such as `--threads`, `--scan-timeout`, `--resolution`, `--chrome-path`, `--no-redirect`, and `--session` remain accepted. Custom v1 HTML templates are not compatible with the v2 schema. Subdomain-takeover detection was intentionally removed: stale fingerprint lists create misleading security claims and are better handled by a maintained, purpose-built validator.

## Security and privacy

- The report embeds its code and data, uses a restrictive Content Security Policy, and performs no automatic remote requests.
- Browser profiles are created in temporary directories and removed after a run.
- Managed-browser binaries receive a local SHA-256 integrity marker after download; `browser status` detects later cache modification. Use `--system-browser` or `--browser-path` if your environment requires independently managed browser provenance.
- Output filenames are derived from sanitized hostnames plus hashes, not raw target paths.
- Never add real client targets, scan output, credentials, cookies, or private vulnerability details to issues, tests, fixtures, or commits.

See [SECURITY.md](SECURITY.md) for private vulnerability reporting and [CONTRIBUTING.md](CONTRIBUTING.md) before contributing.

## Project lineage

Aquatone Revamped is based on Michael Henriksen's original MIT-licensed Aquatone. The original copyright and license are retained in [LICENSE.txt](LICENSE.txt), with additional attribution in [NOTICE.md](NOTICE.md). This continuation is maintained independently and is not endorsed by the original author.

## Responsible use and disclaimer

Use this software only on systems you own or have explicit written
authorization to assess. You are responsible for the scope, rate, handling of
collected data, and compliance with applicable laws and third-party terms.

The software is provided "as is", without warranty, and the authors and
copyright holders disclaim liability to the fullest extent permitted by law.
See the [MIT License](LICENSE.txt) for the complete terms. This usage notice
does not modify or restrict the license.
