module github.com/ASTRACAT2022/aesingflow

go 1.26.0

require github.com/quic-go/quic-go v0.60.0

// Keep the congestion-control fix auditable and reproducible. The upstream
// v0.60.0 sender is hard-coded to Reno; AesingFlow's local copy uses CUBIC.
replace github.com/quic-go/quic-go => ./third_party/quic-go

require (
	golang.org/x/crypto v0.51.0 // indirect
	golang.org/x/net v0.55.0 // indirect
	golang.org/x/sys v0.45.0 // indirect
)
