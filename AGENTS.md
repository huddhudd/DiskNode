# Repository Guidelines

## Project Structure & Module Organization
The Go module `saveserver` is rooted here. Runtime entrypoint `cmd/nvserver` wires HTTP services around `CloudStart.ini`, `Data/NvFiles.db`, and the cache directories configured through INI. Package `nvservice` contains service layers: `server` exposes HTTP handlers, `usersave` orchestrates temp-file merging, history, and task queues, `storage` enumerates cache volumes, `listdata` covers list serialization. SQLite access and reference counting live in `nvfiles`. Legacy C++ reference implementations remain in the root and `demo/`¡ªtreat them as behavioral docs. Static assets such as list manifests live under `Data/`.

## Build, Test, and Development Commands
Run `go run ./cmd/nvserver` for local development; it binds to `:8080` and reads `CloudStart.ini` from the working directory. Build a distributable binary with `go build -o bin/nvserver.exe ./cmd/nvserver`. Execute all unit and integration tests with `go test ./...`; add `-run` filters while iterating on a package. Use `go vet ./...` before shipping to catch API misuse. The utility workflow runner lives at `cmd/userdiskapitester`; invoke it with `go run ./cmd/userdiskapitester --help` to validate end-to-end flows against a running server.

## Coding Style & Naming Conventions
All Go code must stay `gofmt`-clean; run `gofmt -w` or `go fmt ./...` prior to review. Packages follow lower_snake directory names (e.g., `usersave`) and exported identifiers mirror the C++ API naming to preserve compatibility. Favor table-driven tests and short helper functions over long statements. If you touch the C++ reference files, keep the existing 4-space indentation and brace-on-new-line layout, and run `clang-format` with the repository defaults.

## Testing Guidelines
Tests live beside implementation files (for example `nvservice/usersave/service_test.go`). Cover both happy paths and failure modes, especially around cleanup of temporary archives, HTTP handler status codes, and SQLite reference counting. When adding task logic, extend the existing httptest suites in `nvservice/server` and add package-level unit tests in `nvservice/usersave`. Prefer real temporary directories created via `t.TempDir()` and seed fixtures through the `listdata` helpers; avoid mutating files in `Data/`.

## Commit & Pull Request Guidelines
The repository currently lacks Git history; align new work with Conventional Commits (`feat:`, `fix:`, `refactor:`) so downstream automation can hook in later. Commit in small, reviewable slices with tests green. Pull request descriptions should include: (1) summary of behavior change, (2) configuration or data prerequisites (e.g., sample `CloudStart.ini` edits), and (3) screenshots or curl transcripts when HTTP responses change. Flag any Go version bumps or dependency updates explicitly.
