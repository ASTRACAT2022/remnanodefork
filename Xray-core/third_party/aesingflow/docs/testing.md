# Testing

`go test ./...` covers codec, state machines, token authentication, scheduler and a local QUIC/TLS integration test. `go test -race ./...`, `go vet ./...`, and `staticcheck ./...` are recommended before release. The decoder fuzz target is invoked with `go test -fuzz=Fuzz -fuzztime=30s ./core/codec/...`.

Linux `tc netem` scripts in `tests/netem` require root and an interface supplied as the first argument (default `eth0`). They are intentionally not run in unit tests because they alter host networking.
