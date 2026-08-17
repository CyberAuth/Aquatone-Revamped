# Contributing

Thanks for helping improve Aquatone Revamped.

1. Discuss large behavioral changes in an issue before implementation.
2. Keep changes focused and add tests for new behavior or regressions.
3. Run `go test -race ./...`, `go vet ./...`, and `gofmt` before submitting a pull request.
4. Describe user-visible changes in `CHANGELOG.md`.

Use only synthetic domains (`example.com`, `.test`) and documentation address ranges in tests and examples. Never commit scan output, browser profiles, API keys, proxy credentials, cookies, internal hostnames, personal filesystem paths, terminal history, or client information. Review staged changes with `git diff --cached` before every commit.

For security-sensitive defects, follow `SECURITY.md` instead of opening a public issue.

By contributing, you agree that your contribution is provided under the repository's MIT License.
